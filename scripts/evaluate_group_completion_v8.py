"""Independent certificate/trace replay and partial-positive evaluation after freeze."""
import argparse,csv,gzip,json,math,statistics
from collections import Counter
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.alternative_witnesses import Witness,validate_witness
from tc_pruning.sparse_edge_evaluation import sha256_file


def read(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def literal_utility(pool,events,edge=False,eta=1.):
    linear=sum(pool['event_scores'][e] for e in events)
    if edge:return linear
    counts=Counter(pool['group_of'][e] for e in events)
    return eta*linear+sum(pool['group_weights'][str(g)]*math.sqrt(c) for g,c in counts.items())


def resolve_pool(decision,pools):
    pool=pools.get(decision['pool_sha256'])
    if decision['candidate_scope']=='bounded' and pool is None:raise ValueError('missing frozen candidate pool')
    if decision['pool_sha256'] is not None and pool is None:raise ValueError('unknown frozen candidate pool hash')
    return pool


def verify(decision,pool,data):
    ids=data['ids'];index={e:i for i,e in enumerate(ids)}
    chosen=set(decision['selected_ids']);mandatory=set(decision['mandatory_ids'])
    true_poi={ids[int(i)] for i in np.flatnonzero(data['poi'])}
    if len(chosen)!=len(decision['selected_ids']) or mandatory!=true_poi or not mandatory<=chosen or not chosen<=set(ids) or len(chosen)>decision['budget']:raise ValueError('identity/budget/POI mismatch')
    closed=set(mandatory);registry={w['digest']:w for w in pool['certificates']} if pool else None
    for c in decision['certificates']:
        if registry is not None and registry.get(c['digest'])!=c:raise ValueError('certificate outside frozen pool')
        w=Witness(index[c['anchor']],tuple(sorted(index[e] for e in c['events'])),tuple(index[e] for e in c['forward']),tuple(index[e] for e in c['backward']),c['rule'],c['digest'])
        if not validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']):raise ValueError('illegal temporal certificate')
        closed.update(c['events'])
    if closed!=chosen:raise ValueError('certificate union differs from selected events')
    if pool:
        materialized=set(pool['materialized_ids'])
        if not chosen<=materialized or len(materialized)>32768:raise ValueError('materialization cap violated')
        if 'trace' in decision:
            current=set(mandatory);edge=decision['method'].endswith('_edge')
            for step in decision['trace']:
                action=pool['actions'][step['bundle']];extra=set(action['events'])-current
                if extra!={ids[i] for i in step['added_events']} or step['used_before']!=len(current):raise ValueError('trace event cost mismatch')
                before=literal_utility(pool,current,edge);current.update(extra)
                if step['used_after']!=len(current) or len(current)>decision['budget']:raise ValueError('trace budget mismatch')
                if not math.isclose(literal_utility(pool,current,edge)-before,step['marginal_gain'],rel_tol=1e-8,abs_tol=1e-9):raise ValueError('trace gain mismatch')
            if current!=chosen or not math.isclose(literal_utility(pool,chosen,edge),decision['objective_value'],rel_tol=1e-8,abs_tol=1e-9):raise ValueError('objective/trace mismatch')
    return len(decision['certificates'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profiles',type=Path);p.add_argument('--config',type=Path,default=Path('configs/group_completion_v8.json'));a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    cfg=json.loads(a.config.read_text())
    refpath=Path('docs/sparse-five-local-critical-reference.json');reference=json.loads(refpath.read_text());rows=[];cases=[]
    for i,ref in enumerate(reference['cases']):
        manifest=read(a.input/f'case{i}'/'manifest.json.gz')
        if manifest['labels_used'] or manifest['ledger_sha256']!=ref['ledger_sha256'] or manifest['config_sha256']!=sha256_file(a.config):raise ValueError('freeze/reference mismatch')
        for source,digest in manifest['source_sha256'].items():
            if sha256_file(Path(source))!=digest:raise ValueError('source changed: '+source)
        ledger=Path(manifest['ledger_path'])
        if sha256_file(ledger)!=manifest['ledger_sha256']:raise ValueError('ledger changed')
        raw=load_ledger(ledger);data,_=canonical_event_order(raw,np.zeros(len(raw['ids'])))
        positive=set(ref['critical_event_ids']);universe=set(data['ids'])
        if not positive<=universe:raise ValueError('reference outside ledger')
        pools={}
        for record in manifest['pool_records']:
            path=Path(record['path'])
            if sha256_file(path)!=record['sha256']:raise ValueError('pool changed')
            pools[record['sha256']]=read(path)
        for entry in manifest['decisions']:
            path=Path(entry['path'])
            if sha256_file(path)!=entry['sha256']:raise ValueError('decision changed')
            d=read(path);pool=resolve_pool(d,pools)
            certs=verify(d,pool,data)
            selected=set(d['selected_ids']);mandatory=set(d['mandatory_ids']);new_positive=positive-mandatory
            groups=[set(ex['parallel_event_ids']) for ex in ref['exemplars']]
            rows.append(dict(case_index=i,name=manifest['name'],method=d['method'],budget=d['budget'],selected_events=len(selected),
                candidate_events=len(universe),materialized_events=len(pool['materialized_ids']) if pool else len(universe),
                tp_known=len(selected&positive),positive_events=len(positive),recall_known=len(selected&positive)/len(positive),
                recall_incremental=len((selected-mandatory)&new_positive)/len(new_positive) if new_positive else None,
                group_any=sum(bool(g&selected) for g in groups)/len(groups),group_full=sum(g<=selected for g in groups)/len(groups),
                pool_positive_recall=len(set(pool['materialized_ids'])&positive)/len(positive) if pool else 1.,
                lineage_selected=sum(e.startswith('LINEAGE') for e in selected),verified_certificates=certs,
                selection_seconds=d['selection_seconds'],candidate_scope=d['candidate_scope'],official_equivalent={k:None for k in ['fp','fn','precision','recall','f1']}))
        cases.append(dict(case_index=i,name=manifest['name'],elapsed_seconds=manifest['elapsed_seconds'],whole_matrix_peak_rss_mib=manifest['peak_rss_mib'],execution_git_commit=manifest['execution_git_commit']))
    summary=[]
    for method in cfg['methods']:
        for budget in cfg['budgets']:
            r=[x for x in rows if x['method']==method and x['budget']==budget]
            if len(r)!=5:raise ValueError('incomplete quality matrix')
            summary.append(dict(method=method,budget=budget,macro_recall_known=statistics.mean(x['recall_known'] for x in r),total_tp_known=sum(x['tp_known'] for x in r),macro_recall_incremental=statistics.mean(x['recall_incremental'] for x in r if x['recall_incremental'] is not None)))
    profiles=[]
    if a.profiles:
        for i in range(5):
            values=[read(a.profiles/f'repeat{j}'/f'case{i}'/'manifest.json.gz') for j in range(cfg['profiling_repeats'])]
            for m in values:
                if m['source_sha256']!=read(a.input/f'case{i}'/'manifest.json.gz')['source_sha256']:raise ValueError('profile source mismatch')
            profiles.append(dict(case_index=i,repeats=len(values),whole_matrix_elapsed_median=statistics.median(v['elapsed_seconds'] for v in values),whole_matrix_peak_rss_median=statistics.median(v['peak_rss_mib'] for v in values),selection=[dict(method=method,budget=b,median_seconds=statistics.median(next(d['selection_seconds'] for d in v['decisions'] if d['method']==method and d['budget']==b) for v in values)) for method in cfg['methods'] for b in cfg['budgets']]))
    report=dict(protocol=cfg['protocol'],label_sha256=sha256_file(refpath),scope='five previously inspected development cases; partial positives, no official-equivalent accuracy claim',rows=rows,summary=summary,cases=cases,profiles=profiles)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    flat=[{k:v for k,v in row.items() if k!='official_equivalent'} for row in rows]
    with a.output.with_suffix('.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
