"""Matched-cap ranking ablation, preserving RASP's causal-fork selector."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import time
import numpy as np
from scripts.run_rasp import load_candidates, write_json
from tc_pruning.rasp import propagate, temporal_routes, temporal_fork_routes, select_fork_bundles
from tc_pruning.rank_fusion import reciprocal_rank_fusion


def run(ledger, reference, output):
    output.mkdir(parents=True,exist_ok=False)
    config=json.loads(Path('configs/rasp_rank_fusion.json').read_text())
    scoring=json.loads(Path(config['scoring_config']).read_text())
    hashes={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in
            ('tc_pruning/rasp.py','tc_pruning/rank_fusion.py','scripts/run_rank_fusion.py')}
    d=load_candidates(ledger); n=len(d['ids'])
    tick=time.perf_counter()
    score,evidence=propagate(d['src'],d['dst'],d['relation'],d['rarity'],d['poi'],d['process_nodes'],scoring)
    back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
    parent,pivot,reachable,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
    plain=evidence['uncontrasted']
    ranks={'rasp':score,'plain_ppr':plain,
           'rrf_dual':reciprocal_rank_fusion([score,plain],reachable,config['rrf_k']),
           'rrf_triple':reciprocal_rank_fusion([score,plain,d['rarity']],reachable,config['rrf_k'])}
    masks={}; results=[]
    budgets=[('4000',min(n,config['absolute_budget']))]+[(f'{r:g}',int(n*r)) for r in config['budgets']]
    for budget_name,budget in budgets:
        for method,rank in ranks.items():
            key=method+'@'+budget_name
            kept,_=select_fork_bundles(rank,d['poi'],back,parent,pivot,budget,d['tie'])
            _,_,after,_=temporal_fork_routes(d['src'][kept],d['dst'][kept],d['timestamp'][kept],d['poi'][kept])
            assert kept.sum()<=budget and np.all(kept[d['poi']])
            assert int((kept & reachable).sum())==int(after.sum())
            masks[key]=kept
            results.append(dict(method=method,budget_name=budget_name,edge_budget=budget,
                                retained_events=int(kept.sum()),candidate_events=n,lost_fork_connections=0))
    # Freeze all masks before opening truth.
    truth=json.loads(reference.read_text()); attack=set(truth['attack_event_ids'])
    lookup={v:i for i,v in enumerate(d['ids'])}
    attack_idx=np.array([lookup[e] for e in attack if e in lookup],dtype=int)
    for r in results:
        kept=masks[r['method']+'@'+r['budget_name']]
        r.update(attack_total=len(attack),retained_attack_events=int(kept[attack_idx].sum()),
                 attack_event_recall=float(kept[attack_idx].sum())/len(attack),
                 retained_paths=sum(all(e in lookup and kept[lookup[e]] for e in p) for p in truth['attack_paths']),
                 reference_paths=len(truth['attack_paths']))
    report=dict(config=config,scoring_config=scoring,implementation_sha256=hashes,
                selection_input_sha256=d['input_sha256'],ground_truth_used_for_selection=False,
                elapsed_before_export_seconds=time.perf_counter()-tick,results=results,
                scope='full frozen candidates, development-only ranking ablation')
    write_json(output/'comparison.json',report)
    with gzip.open(output/'edge-ranks.jsonl.gz','wt') as stream:
        for i,e in enumerate(d['ids']):
            stream.write(json.dumps(dict(event_id=e,rasp_score=float(score[i]),plain_score=float(plain[i]),
                rarity=float(d['rarity'][i]),rrf_dual=float(ranks['rrf_dual'][i]),rrf_triple=float(ranks['rrf_triple'][i]),
                decisions={k:bool(v[i]) for k,v in masks.items()}))+'\n')
    print(json.dumps(report),flush=True)
    print('COMPLETE',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ledger','reference','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.ledger,a.reference,a.output)
