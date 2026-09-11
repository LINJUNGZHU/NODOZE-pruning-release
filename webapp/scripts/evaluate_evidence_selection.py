"""Fixed-budget and matched-size development comparisons; all POIs are reported."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import time
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.optc_investigation import rescore
from tc_pruning.evidence_selection import select_evidence, witness_bundle


def summary(run):
    m,t=run['metrics'],run['truth']
    return dict(mode=run['algorithm']['selection_mode'],budget_ratio=run['algorithm']['budget_ratio'],
                retained=m['retained_edges'],candidate=m['candidate_edges'],nodes=m['retained_nodes'],
                reference_retained=t['retained_events'],reference_total=t['matched_events'],
                reference_density=t['retained_events']/m['retained_edges'],
                non_poi_reference_retained=t['non_poi_retained'],stages=t['stages'],
                certificate=run['decision_certificate'],scores=run['score_diagnostics'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache',type=Path,default=ROOT/'webapp/runtime/optc-demo.json')
    p.add_argument('--output',type=Path,default=ROOT/'docs/evidence-selection-evaluation.json')
    args=p.parse_args();base=json.loads(args.cache.read_text());results=[]
    for preset in base['poi_presets']:
        rows=[]
        for mode in ('context','evidence'):
            for budget in (.01,.02,.05,.1,.2):
                started=time.monotonic();run=rescore(copy.deepcopy(base),preset['event_id'],budget,mode)
                row=summary(run);row['runtime_seconds']=time.monotonic()-started;rows.append(row)
                print(preset['label'],mode,budget,row['retained'],row['reference_retained'],flush=True)
                if mode=='evidence' and budget==.2:compact=run
        count=compact['metrics']['retained_edges'];ratio=float(np.nextafter(count/len(base['edges']),1.))
        matched=rescore(copy.deepcopy(base),preset['event_id'],ratio,'context')
        control=summary(matched);control['comparison']='legacy at new method actual edge count'
        # Simple ranking baseline: known POI plus top legacy propagation scores.
        order=sorted(range(len(compact['edges'])),key=lambda i:(not compact['edges'][i]['poi'],-compact['edges'][i]['propagation_score'],compact['edges'][i]['id']))
        top=order[:count]
        score_only=dict(retained=count,reference_retained=sum(bool(compact['edges'][i]['reference_evidence']) for i in top),
                        constraint='ranking-only control; does not guarantee causal witness closure')
        x=compact['decision_inputs'];top_set=set(top)
        score_only['without_temporal_witness']=sum(x['pivot'][i]<0 for i in top)
        score_only['canonical_witness_not_in_selection']=sum(not set(witness_bundle(i,x['backward'],x['parent'],x['pivot']))<=top_set for i in top if x['pivot'][i]>=0)
        # Repeat exactly tied selection priorities at the small 1% budget.
        x=compact['decision_inputs'];a={k:np.array(v) for k,v in x.items() if isinstance(v,list) and k!='event_ids'}
        refs=np.array([bool(e['reference_evidence']) for e in compact['edges']]);samples=[];sets=[]
        for seed in range(5):
            keys=[(hashlib.sha256(f'{seed}:{id}'.encode()).hexdigest(),) for id in x['event_ids']]
            kept,_=select_evidence(a['evidence'],a['poi'],a['backward'],a['parent'],a['pivot'],a['family'],int(len(refs)*.01),keys,certified=a['certified'])
            sets.append(set(np.flatnonzero(kept)));samples.append(int((kept&refs).sum()))
        stability=dict(budget_ratio=.01,tie_order_seeds=list(range(5)),reference_retained=samples,
                       jaccard_against_first=[len(s&sets[0])/len(s|sets[0]) for s in sets])
        # Candidate order and post-selection reference labels must not drive decisions.
        shuffled=copy.deepcopy(base);shuffled['edges'].reverse()
        shuffled=rescore(shuffled,preset['event_id'],.2,'evidence')
        order_invariant=[e['id'] for e in shuffled['edges'] if e['retained']]==[e['id'] for e in compact['edges'] if e['retained']]
        assert order_invariant
        results.append(dict(poi=preset,grid=rows,matched_size_context=control,matched_size_score_only=score_only,
                            tie_sensitivity=stability,input_order_invariant=order_invariant))
    report=dict(protocol=dict(budgets=[.01,.02,.05,.1,.2],all_configured_pois=True,
                             evaluation='development; single host/window, partial indicator labels',
                             selection_uses_reference_labels=False,false_positive_rate_claim=False,
                             baseline_status='Existing RASP-D and score-only controls, NOT reproduced Kairos/Orthrus/NodLink results'),
                results=results,implementation_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in
                [ROOT/'tc_pruning/rasp.py',ROOT/'tc_pruning/evidence_selection.py',ROOT/'tc_pruning/rasp_diverse.py',ROOT/'tc_pruning/optc_investigation.py']})
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,allow_nan=False)+'\n')

if __name__=='__main__':main()
