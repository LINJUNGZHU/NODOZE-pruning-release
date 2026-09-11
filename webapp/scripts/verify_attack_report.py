"""Offline verification of emitted event paths (not a malice certificate)."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.attack_inference import check_path
from tc_pruning.optc import parse_event


def verify(document):
    attack=document['attack'];events=document['events'];by_id={e['id']:e for e in events}
    if len(by_id)!=len(events): raise ValueError('duplicate events')
    for e in events:
        raw=parse_event(e['raw'])
        if raw is None or any(raw[k]!=e[k] for k in ('id','source','target','timestamp_ns','relation','timestamp')):
            raise ValueError('event does not match its raw record')
    path_union=set()
    if len({p['id'] for p in attack['paths']})!=len(attack['paths']): raise ValueError('duplicate paths')
    for p in attack['paths']:
        if not check_path(p['event_ids'],by_id): raise ValueError('invalid temporal directed path')
        es=[by_id[i] for i in p['event_ids']]
        if p['node_ids']!=[es[0]['source']]+[e['target'] for e in es]: raise ValueError('path nodes mismatch')
        if (p['start'],p['end'])!=(es[0]['timestamp'],es[-1]['timestamp']): raise ValueError('path time mismatch')
        path_union.update(p['event_ids'])
    if path_union!=set(attack['path_event_ids']): raise ValueError('path event union mismatch')
    evidence={i for n in attack['nodes'] if n['predicted_attack'] for i in n['evidence_event_ids']}
    if evidence!=set(attack['evidence_event_ids']): raise ValueError('evidence union mismatch')
    if set(by_id)!=path_union|evidence: raise ValueError('missing/extra supporting event')
    processes={n['id'] for n in attack['nodes']};predicted={n['id'] for n in attack['nodes'] if n['predicted_attack']}
    path_nodes={n for p in attack['paths'] for n in p['node_ids']}
    if set(attack['connector_node_ids'])!=(path_nodes&processes)-predicted: raise ValueError('connector role mismatch')
    if set(attack['resource_node_ids'])!=path_nodes-processes: raise ValueError('resource role mismatch')
    for p in attack['paths']:
        if set(p['inferred_node_ids'])!=set(p['node_ids'])&predicted: raise ValueError('inferred role mismatch')
    return dict(raw_events_verified=True,strict_temporal_paths_verified=True,roles_verified=True,
                paths=len(attack['paths']),maliciousness_proven=False,
                limitation='Checks internal event/route consistency, not log authenticity, model optimality or ground-truth correctness.')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('report',type=Path);args=parser.parse_args()
    print(json.dumps(verify(json.loads(args.report.read_text())),indent=2))
