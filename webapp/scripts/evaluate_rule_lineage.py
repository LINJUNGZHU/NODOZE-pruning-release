"""Evaluate v2 and frozen legacy rules on both references and every manual POI."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack
from tc_pruning.optc_investigation import rescore


def metrics(report):
    e=report['evaluation']
    return dict(summary=report['summary'],runtime_seconds=report['runtime_seconds'],
                public=e.get('published_benchmark',{}).get('node_metrics'),
                tapas=e.get('tapas_benchmark',{}).get('node_metrics'),
                path_events=e.get('published_benchmark',{}).get('path_event_metrics'),
                activity_events=e.get('published_benchmark',{}).get('activity_event_metrics'),
                predicted_nodes=[dict(id=n['id'],pids=n['pids'],label=n['label'],decision_kind=n.get('decision_kind'),
                                     public_label=e.get('published_benchmark',{}).get('labels',{}).get(n['id']),
                                     tapas_label=e.get('tapas_benchmark',{}).get('labels',{}).get(n['id'])) for n in report['nodes'] if n['predicted_attack']])


def main():
    catalog=json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text());results=[]
    for entry in catalog:
        data=json.loads(Path(entry['cache_path']).read_text())
        for preset in data['poi_presets']:
            # Recompute POI-dependent evidence once; predictions are compared on
            # exactly the same raw events, history and budget.
            trial=rescore(copy.deepcopy(data),preset['event_id'],.2,'context',.9,detector='rules')
            new=trial['attack'];old=infer_attack(trial['edges'],preset['event_id'],detector='rules_legacy');old['evaluation']=evaluate_attack(old,trial['edges'])
            row=dict(id=entry['id'],poi=preset['event_id'],events=len(trial['edges']),legacy=metrics(old),enhanced=metrics(new))
            results.append(row)
            print(entry['id'],preset['event_id'][:8],'legacy',row['legacy']['public'],'v2',row['enhanced']['public'],'TAPAS',row['enhanced']['tapas'],flush=True)
        # Persist the default/manual POI selected before this experiment.
        rescore(data,data['poi']['event_id'],.2,'context',.9,detector='rules')
        path=Path(entry['cache_path']);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(data,ensure_ascii=False,allow_nan=False));tmp.replace(path)
        output=dict(source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['tc_pruning/attack_inference.py','tc_pruning/rule_lineage.py','tc_pruning/attack_evaluation.py','poi/tapas-optc-slices.json']},protocol='Exploratory development on known same-host overlapping windows; label files are evaluation only. No ID/IP/PID or payload basename lookup in inference.',
                    target=dict(process_recall=.9,public_scope='published malicious process tasks',tapas_scope='static node membership projected to observed process UUIDs'),results=results)
        (ROOT/'docs/rule-lineage-evaluation.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
if __name__=='__main__':main()
