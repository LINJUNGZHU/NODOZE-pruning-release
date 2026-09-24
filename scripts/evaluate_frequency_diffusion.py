"""Separate, post-selection evaluator for frozen local partial-positive labels."""
from __future__ import annotations
import argparse,csv,json
from pathlib import Path
from tc_pruning.sparse_edge_evaluation import sha256_file


def metrics(ids,reference,candidates):
    selected=set(ids)
    if len(selected)!=len(ids):raise ValueError('duplicate selected IDs')
    positive=set(reference['critical_event_ids'])
    uncertain=set(reference.get('uncertain_event_ids',[]))
    if positive&uncertain:raise ValueError('overlapping labels')
    tp=len(selected&positive);fp=len(selected-positive-uncertain);fn=len(positive-selected)
    tn=candidates-len(positive)-len(uncertain)-fp
    if tn<0:raise ValueError('invalid candidate universe')
    stages={};hits=[]
    for ex in reference['exemplars']:
        hit=bool(selected.intersection(ex['parallel_event_ids']));hits.append(hit)
        stages[ex['stage']]=stages.get(ex['stage'],False) or hit
    return dict(proxy_tp=tp,proxy_fp=fp,proxy_fn=fn,proxy_tn=tn,
        proxy_precision=tp/(tp+fp) if tp+fp else None,
        proxy_recall=tp/len(positive) if positive else None,
        proxy_f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
        proxy_fpr=fp/(fp+tn) if fp+tn else None,proxy_fnr=fn/(tp+fn) if tp+fn else None,
        groups_hit=sum(hits),groups_total=len(hits),stages_hit=sum(stages.values()),stages_total=len(stages),
        selected_uncertain=len(selected&uncertain),
        official_equivalent={k:None for k in ['fp','fn','precision','recall','f1']})


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    refpath=Path('docs/sparse-five-local-critical-reference.json');ref=json.loads(refpath.read_text())
    cases=[];common=None
    for i,reference in enumerate(ref['cases']):
        path=a.input/f'case{i}.json';report=json.loads(path.read_text())
        if reference['ledger_sha256']!=report['ledger_sha256'] or sha256_file(Path(report['ledger']))!=report['ledger_sha256']:
            raise ValueError('frozen ledger mismatch')
        if common is None:common=report['config']
        if common!=report['config']:raise ValueError('different case configurations')
        if report['labels_used_for_selection']:raise ValueError('selection used labels')
        rows=[]
        for r in report['results']:
            if len(r['selected_ids'])!=r['raw_events']:raise ValueError('raw event count mismatch')
            rows.append({k:v for k,v in r.items() if k!='selected_ids'}|metrics(r['selected_ids'],reference,report['candidate_events']))
        cases.append(dict(name=reference['name'],decision_file=str(path),decision_sha256=sha256_file(path),
            candidate_events=report['candidate_events'],candidate_episodes=report['candidate_episodes'],
            source_sha256=report['source_sha256'],elapsed_seconds=report['elapsed_seconds'],
            load_seconds=report['load_seconds'],preprocessing_seconds=report['preprocessing_seconds'],
            scoring_seconds=report['scoring_seconds'],peak_rss_mib=report['peak_rss_mib'],
            all_walks_converged=all(w['converged'] for diag in report['diagnostics'].values() for w in diag['walks']),results=rows))
    out=dict(protocol='frozen-local-proxy-frequency-diffusion-v1',reference_sha256=sha256_file(refpath),
        scope='five previously inspected development cases; partial positive local reference; closed-world proxy only',config=common,cases=cases)
    a.output.write_text(json.dumps(out,indent=2,ensure_ascii=False))
    rows=[dict(case=c['name'],**{k:v for k,v in r.items() if k!='official_equivalent'}) for c in cases for r in c['results']]
    with a.output.with_suffix('.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    for c in cases:
        for r in c['results']:
            if r['method'] in ['full','classic','no_episode_expansion']:
                print(c['name'],r['method'],r['raw_cap'],'E',r['raw_events'],'TP',r['proxy_tp'],'groups',r['groups_hit'],'stages',r['stages_hit'])


if __name__=='__main__':main()
