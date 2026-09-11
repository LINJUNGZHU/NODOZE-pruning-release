"""Fixed-grid development evaluation, without selecting thresholds on labels."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.optc_investigation import rescore
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack,node_metrics
from webapp.scripts.verify_attack_report import verify


def evaluate(base):
    results=[]
    for preset in base['poi_presets']:
        started=time.monotonic()
        data=rescore(copy.deepcopy(base),preset['event_id'],.2,'context',.9)
        elapsed=time.monotonic()-started
        attack=data['attack'];ev=attack['evaluation'];grid=[]
        for q in (.8,.9,.95,.99):
            run=infer_attack(data['edges'],preset['event_id'],dict(anomaly_quantile=q))
            evaluation=evaluate_attack(run,data['edges'])
            grid.append(dict(quantile=q,predicted=[n['id'] for n in run['nodes'] if n['predicted_attack']],
                             threshold=run['threshold'],evaluation=evaluation,
                             runtime_seconds=run['runtime_seconds']))
        labels=ev['published_benchmark']['labels'];universe=set(labels)
        controls={}
        for name,predicted in [('behavior_only',{n['id'] for n in attack['nodes'] if n['behavioral_match']}),
                               ('anomaly_only',{n['id'] for n in attack['nodes'] if n['anomaly_match']}),
                               ('all_retained_processes_as_attack',{e[k] for e in data['edges'] if e['retained'] for k in ('source','target')} & universe)]:
            controls[name]=node_metrics(universe,predicted,labels)
        variants=[]
        stable=lambda a:{k:v for k,v in a.items() if k!='runtime_seconds'}
        for b,m in [(.01,'context'),(.2,'evidence')]:
            other=rescore(copy.deepcopy(base),preset['event_id'],b,m,.9)
            invariant=stable(other['attack'])==stable(attack)
            if not invariant:raise AssertionError('pruning changed attack detection')
            variants.append(dict(budget=b,mode=m,identical_attack_report=invariant))
        reverse=infer_attack(list(reversed(data['edges'])),preset['event_id'])
        reverse.pop('runtime_seconds');original={k:v for k,v in attack.items() if k not in ('runtime_seconds','evaluation')}
        if reverse!=original:raise AssertionError('input order affected detection')
        times=[infer_attack(data['edges'],preset['event_id'])['runtime_seconds'] for _ in range(3)]
        ids=set(attack['path_event_ids'])|set(attack['evidence_event_ids'])
        audit=verify(dict(attack=attack,events=[e for e in data['edges'] if e['id'] in ids]))
        results.append(dict(poi=preset,summary=attack['summary'],evaluation=ev,threshold=attack['threshold'],
                            predicted_nodes=[n for n in attack['nodes'] if n['predicted_attack']],
                            paths=attack['paths'],sensitivity=grid,ablations=controls,
                            pruning_invariance=variants,input_order_invariant=True,path_audit=audit,
                            runtime=dict(end_to_end_rescore_seconds=elapsed,inference_seconds=times,
                                         inference_median_seconds=statistics.median(times))))
        print(preset['label'],json.dumps(ev['published_benchmark']['node_metrics']),flush=True)
    files=['tc_pruning/attack_inference.py','tc_pruning/attack_evaluation.py','tc_pruning/optc_investigation.py',
           'poi/optc-day1-attack-reference.json','poi/optc-0201-public-labels.json']
    return dict(protocol=dict(candidate_events=len(base['edges']),host='SysClient0201',
                              default_quantile=.9,sensitivity_quantiles=[.8,.9,.95,.99],
                              development_only=True,independent_test_set=False,parameters_selected_on_labels=False,
                              baseline_status='Local ablations and naive pruning-as-detection control, not full SOTA reproductions',
                              runtime_scope='Loaded candidate graph + existing pre-POI index; excludes initial raw-log ingest'),
                source_sha256={f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files},results=results)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,default=ROOT/'webapp/runtime/optc-demo.json')
    p.add_argument('--output',type=Path,default=ROOT/'docs/attack-inference-evaluation.json');args=p.parse_args()
    result=evaluate(json.loads(args.cache.read_text()));args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
