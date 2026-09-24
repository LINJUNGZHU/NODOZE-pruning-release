"""Audit frozen selections, then evaluate against local partial-positive labels."""
from __future__ import annotations
import argparse,csv,gzip,json,statistics
from collections import Counter
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,episodes
from pathlib import Path
from scripts.evaluate_frequency_diffusion import metrics
from tc_pruning.sparse_edge_evaluation import sha256_file


def validate_decision(row,universe,pois):
    if row['status']=='no_incumbent':
        if row.get('selected_ids') or row.get('raw_events') is not None:raise ValueError('fake solver output')
        if row.get('optimizer',{}).get('status')!='no_incumbent':raise ValueError('missing solver diagnostics')
        return None
    if row['status']=='infeasible_mandatory':
        if row['mandatory_events']<=row['raw_cap']:raise ValueError('false infeasible status')
        return None
    ids=row['selected_ids'];chosen=set(ids)
    if len(chosen)!=len(ids):raise ValueError('duplicate selected ID')
    if not chosen<=universe:raise ValueError('unknown selected IDs')
    if not pois<=chosen:raise ValueError('missing declared POI')
    if len(chosen)!=row['raw_events'] or len(chosen)>row['raw_cap']:raise ValueError('raw count or budget mismatch')
    return chosen


def summarize_random(rows):
    out={'runs':len(rows)}
    for key in ('proxy_recall','proxy_f1'):
        v=[x[key] for x in rows if x[key] is not None]
        out[key+'_mean']=statistics.mean(v) if v else None
        out[key+'_std']=statistics.stdev(v) if len(v)>1 else None
    return out


def episode_audit(selected_ids,id_group,group_counts,pois):
    counts=Counter(id_group[e] for e in selected_ids)
    complete={g for g,n in counts.items() if n==group_counts[g]}
    poi_groups={id_group[e] for e in pois}
    return dict(complete_episodes=len(complete),partial_episodes=len(counts)-len(complete),
                complete_poi_episodes=len(complete&poi_groups),poi_episodes=len(poi_groups))


def kernel_seconds(method,scenario,report):
    if method in scenario.get('method_kernel_seconds',{}):return scenario['method_kernel_seconds'][method]
    if method=='pcst_native':return scenario['scoring_seconds']+scenario['pcst_grid_seconds']
    if method=='localdegree_top':return report['localdegree_seconds']
    if method=='coverage_no_frequency':return scenario['nofrequency_seconds']
    if method in ('diffusion_top','episode','coverage_exact','coverage_semantic','coverage_partial'):
        return scenario['scoring_seconds']
    return None # historical scores are cached; random has no scoring kernel


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    refpath=Path('docs/sparse-five-local-critical-reference.json');ref=json.loads(refpath.read_text())
    common_config=None;common_source=None;cases=[]
    for i,reference in enumerate(ref['cases']):
        path=a.input/f'case{i}.json.gz'
        with gzip.open(path,'rt') as f:report=json.load(f)
        if sha256_file(Path(report['ledger']))!=reference['ledger_sha256'] or report['ledger_sha256']!=reference['ledger_sha256']:
            raise ValueError('candidate hash mismatch')
        if report['labels_used_for_selection']:raise ValueError('labels used for selection')
        if common_config is None:common_config=report['config'];common_source=report['source_sha256']
        if report['config']!=common_config or report['source_sha256']!=common_source:raise ValueError('source/config differs across cases')
        for source,h in report['source_sha256'].items():
            if sha256_file(Path(source))!=h:raise ValueError('source changed: '+source)
        data=load_ledger(Path(report['ledger']));universe=set(data['ids'])
        if len(universe)!=len(data['ids']):raise ValueError('duplicate candidate ID')
        original_pois={data['ids'][i] for i in np.flatnonzero(data['poi'])}
        group=episodes(data['src'],data['dst'],data['relation'],data['timestamp'],common_config['episode_window_ns'])
        id_group=dict(zip(data['ids'],map(int,group)));group_counts=np.bincount(group)
        del data
        if not set(reference['critical_event_ids'])<=universe:raise ValueError('reference outside candidates')
        scenarios={s['scenario']:s for s in report['scenarios']};rows=[]
        if set(scenarios['all']['poi_ids'])!=original_pois:raise ValueError('changed full-scenario POIs')
        for name,s in scenarios.items():
            expected=original_pois-({s['removed_poi']} if s['removed_poi'] else set())
            if set(s['poi_ids'])!=expected:raise ValueError('POI removal mismatch')
        for row in report['results']:
            s=scenarios[row['scenario']];chosen=validate_decision(row,universe,set(s['poi_ids']))
            x={k:v for k,v in row.items() if k!='selected_ids'}
            if chosen is not None:
                x.update(metrics(row['selected_ids'],reference,len(universe)))
                x.update(episode_audit(row['selected_ids'],id_group,group_counts,set(s['poi_ids'])))
                times=x.pop('selection_seconds');x['timing_samples']=len(times)
                x['selection_seconds_median']=statistics.median(times)
                x['selection_seconds_min']=min(times);x['selection_seconds_max']=max(times)
                x['shared_kernel_seconds']=kernel_seconds(row['method'],s,report)
                x['kernel_plus_selection_seconds']=x['shared_kernel_seconds']+x['selection_seconds_median'] if x['shared_kernel_seconds'] is not None else None
            rows.append(x)
        random=[]
        for track in ('poi_only','shared_context'):
            for cap in common_config['raw_budgets']:
                selected=[x for x in rows if x['scenario']=='all' and x['track']==track and x['raw_cap']==cap and x['method'].startswith('random_') and x['status']=='ok']
                if selected:random.append(dict(track=track,raw_cap=cap,**summarize_random(selected)))
        cases.append(dict(name=reference['name'],report_path=str(path),report_sha256=sha256_file(path),candidate_events=len(universe),
            candidate_episodes=report['candidate_episodes'],load_seconds=report['load_seconds'],group_seconds=report['group_seconds'],
            elapsed_seconds=report['elapsed_seconds'],peak_rss_mib=report['peak_rss_mib'],versions=report['versions'],
            scenarios=report['scenarios'],audit=dict(candidate_ids_unique=True,selected_ids_and_caps_and_pois_valid=True,reference_in_candidate=True),
            random_summary=random,results=rows))
        print(reference['name'],'audited',len(rows),'decisions',flush=True)
    result=dict(protocol='cross-domain-local-proxy-evaluation-v1',reference_sha256=sha256_file(refpath),config=common_config,
        source_sha256=common_source,scope='development cases; closed-world proxy; public kernels with task adapters, not whole-paper replication',cases=cases)
    a.output.write_text(json.dumps(result,indent=2))
    flat=[dict(case=c['name'],**{k:v for k,v in r.items() if k!='official_equivalent'}) for c in cases for r in c['results']]
    fields=list(dict.fromkeys(k for r in flat for k in r))
    with a.output.with_suffix('.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");w.writeheader();w.writerows(flat)


if __name__=='__main__':main()
