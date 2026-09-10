"""Paired retrieval/selection experiment; labels read only after masks freeze."""
import argparse
import json
from pathlib import Path
import time
import numpy as np
from scripts.run_rasp import load_candidates, write_json
from tc_pruning.history_archive import HistoryArchive
from tc_pruning.rasp import propagate, temporal_routes, temporal_fork_routes, select_fork_bundles


def select(d, indices, config, budget):
    indices = np.asarray(sorted(indices), dtype=int)
    poi = d['poi'][indices]
    if not len(indices) or not poi.any(): return set(), 'no_active_poi'
    if poi.sum() > budget: return set(), 'infeasible'
    nodes, inverse = np.unique(np.r_[d['src'][indices], d['dst'][indices]], return_inverse=True)
    src, dst = inverse[:len(indices)], inverse[len(indices):]
    ts = d['timestamp'][indices]
    score, _ = propagate(src,dst,d['relation'][indices],d['rarity'][indices],poi,d['process_nodes'][nodes],config)
    back = temporal_routes(src,dst,ts,poi)[0][0]
    parent,pivot,reachable,_ = temporal_fork_routes(src,dst,ts,poi,back)
    kept,_ = select_fork_bundles(score,poi,back,parent,pivot,min(budget,len(indices)),d['tie'][indices])
    _,_,after,_ = temporal_fork_routes(src[kept],dst[kept],ts[kept],poi[kept])
    assert int((kept & reachable).sum()) == int(after.sum())
    return set(indices[kept].tolist()), 'ready'


def run(ledger, reference, output):
    output.mkdir(parents=True,exist_ok=False)
    d = load_candidates(ledger); n=len(d['ids'])
    config=json.loads(Path('configs/rasp_v1.json').read_text())
    order=np.lexsort((d['tie'],d['timestamp']))
    archive=HistoryArchive(output/'archive')
    # Offline replay preparation uses a frozen candidate ledger, not raw CDM.
    for i in order:
        archive.append(dict(event_id=d['ids'][i],src=int(d['src'][i]),dst=int(d['dst'][i]),
                            relation=int(d['relation'][i]),timestamp_ns=int(d['timestamp'][i]),rarity=float(d['rarity'][i])))
    archive.flush()
    end=int(d['timestamp'].max()); registry=np.flatnonzero(d['poi'])
    endpoints=set(d['src'][registry])|set(d['dst'][registry])
    index={eid:i for i,eid in enumerate(d['ids'])}
    window=set(order[-20000:].tolist()); budget=int(min(n,20000)*.2)
    candidates={'window':window}; diagnostics={}
    for hops in (1,2):
        start=time.perf_counter(); rows,diag=archive.retrieve(endpoints,end,hops)
        candidates[f'history_{hops}hop']=window|{index[r['event_id']] for r in rows}
        diagnostics[f'history_{hops}hop']={**diag,'retrieval_seconds':time.perf_counter()-start}
    candidates['full_history']=set(range(n))
    results=[]; masks={}
    for name,indices in candidates.items():
        start=time.perf_counter(); kept,status=select(d,indices,config,budget)
        masks[name]=kept
        results.append(dict(method=name,candidate_events=len(indices),retained_events=len(kept),
                            edge_budget=budget,status=status,selection_seconds=time.perf_counter()-start,
                            **diagnostics.get(name,{})))
    truth=json.loads(reference.read_text()); attack=set(truth['attack_event_ids'])
    for result in results:
        name=result['method']; available={d['ids'][i] for i in candidates[name]}; kept={d['ids'][i] for i in masks[name]}
        result.update(attack_total=len(attack),attack_in_candidates=len(attack&available),
                      retained_attack_events=len(attack&kept),attack_event_recall=len(attack&kept)/len(attack),
                      candidate_attack_coverage=len(attack&available)/len(attack),
                      retained_paths=sum(set(p)<=kept for p in truth['attack_paths']),reference_paths=len(truth['attack_paths']))
    report={'results':results,'selection_input_sha256':d['input_sha256'], 'ground_truth_used_for_selection':False,
            'evaluation_scope':'end-of-stream development replay; same absolute edge cap and batch RASP scorer; not online attack detection',
            'known_pois':len(registry),'source':str(ledger),'config':config}
    write_json(output/'comparison.json',report)
    write_json(output/'retained-ids.json',{k:[d['ids'][i] for i in sorted(v)] for k,v in masks.items()})
    print(json.dumps(report),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ledger','reference','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.ledger,a.reference,a.output)
