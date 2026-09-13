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
    multiview_verified=False;context_union=set()
    context_index=attack.get('model',{}).get('context_index',{})
    for node in attack['nodes']:
        mv=node.get('multiview')
        if not mv or not node['predicted_attack']:continue
        if set(mv.get('views',{}))!={'attribute','structural','causal'}:raise ValueError('invalid view set')
        view_union={eid for view in mv['views'].values() for eid in view['evidence_event_ids']}
        if not view_union<=set(by_id) or view_union!=set(node['evidence_event_ids']) or view_union!=set(mv['evidence_event_ids']):
            raise ValueError('view evidence union mismatch')
        for view in mv['views'].values():
            if not set(view.get('target_event_ids',[]))<=set(view['evidence_event_ids']):raise ValueError('view target evidence missing')
            from tc_pruning.multiview import resolve_context
            resolved=set(resolve_context(view,context_index))
            if not resolved<=set(by_id):raise ValueError('view scoring context missing')
            scope=view.get('context_scope')
            if scope is not None:
                if any(by_id[eid]['timestamp_ns']//60_000_000_000!=scope['minute'] for eid in resolved):
                    raise ValueError('view context minute mismatch')
                if 'before_ns' in scope:
                    targets=view.get('target_event_ids',[])
                    if len(targets)!=1 or by_id[targets[0]]['timestamp_ns']!=scope['before_ns']:
                        raise ValueError('view context cutoff mismatch')
            context_union.update(resolved)
        if len(mv['flags'])!=7 or any(type(flag) is not bool for flag in mv['flags']) or sum(mv['flags'])!=mv['votes']:
            raise ValueError('view voting mismatch')
        if mv['predicted']!=(mv['votes']>=4) or node['predicted_attack']!=mv['predicted']:
            raise ValueError('view prediction mismatch')
        multiview_verified=True
    if context_union!=set(attack.get('context_event_ids',[])):raise ValueError('view context union mismatch')
    for entries in context_index.values():
        for eid,timestamp in entries:
            if eid in context_union and by_id[eid]['timestamp_ns']!=timestamp:raise ValueError('view context timestamp mismatch')
    activity=set(attack.get('activity_event_ids',[]))
    if set(by_id)!=path_union|evidence|activity|context_union: raise ValueError('missing/extra supporting event')
    processes={n['id'] for n in attack['nodes']};predicted={n['id'] for n in attack['nodes'] if n['predicted_attack']}
    path_nodes={n for p in attack['paths'] for n in p['node_ids']}
    if set(attack['connector_node_ids'])!=(path_nodes&processes)-predicted: raise ValueError('connector role mismatch')
    if set(attack['resource_node_ids'])!=path_nodes-processes: raise ValueError('resource role mismatch')
    for p in attack['paths']:
        if set(p['inferred_node_ids'])!=set(p['node_ids'])&predicted: raise ValueError('inferred role mismatch')
    activity_verified=False
    if 'activity_event_ids' in attack:
        births={};ends={}
        for e in sorted(events,key=lambda e:(e['timestamp_ns'],e['id'])):
            if e['relation']=='PROCESS_CREATE' and e['target'] in predicted:births.setdefault(e['target'],e)
        start={n:births[n]['timestamp_ns'] if n in births else min((e['timestamp_ns'] for e in events if e['raw']['actorID']==n),default=0) for n in predicted}
        for e in sorted(events,key=lambda e:(e['timestamp_ns'],e['id'])):
            if e['relation']=='PROCESS_TERMINATE' and e['target'] in start and e['timestamp_ns']>=start[e['target']]:ends.setdefault(e['target'],e['timestamp_ns'])
        expected=set()
        for e in events:
            actor=e['raw']['actorID']
            own=actor in start and start[actor]<=e['timestamp_ns']<=ends.get(actor,float('inf'))
            birth=e['relation']=='PROCESS_CREATE' and e['target'] in births and e['id']==births[e['target']]['id']
            end=e['relation']=='PROCESS_TERMINATE' and e['target'] in ends and e['timestamp_ns']==ends[e['target']]
            if own or birth or end:expected.add(e['id'])
        if activity!=expected:raise ValueError('activity membership mismatch')
        activity_verified=True
    rule_verified=False
    if attack.get('version')=='attack-hypothesis-v2-lineage':
        from tc_pruning.rule_lineage import verify_witness
        for node in attack['nodes']:
            if not node['predicted_attack']:continue
            verify_witness(node,by_id,attack['config'])
            witness=node['rule_witness']
            if witness['root_node_id'] not in predicted:raise ValueError('unreported behavioral root')
            if witness['kind']=='corroborated_behavior':
                start=witness['active_since_ns']
                end=min((e['timestamp_ns'] for e in events if e['relation']=='PROCESS_TERMINATE' and e['target']==node['id'] and e['timestamp_ns']>=start),default=float('inf'))
                support=[by_id[i] for i in witness['root_evidence_event_ids']]
                if not any(e['raw']['actorID']==node['id'] and start<e['timestamp_ns']<end and
                           (e['relation']=='PROCESS_CREATE' or e['raw']['object']=='FLOW' and e['raw']['properties'].get('direction','').lower()=='outbound') for e in support):
                    raise ValueError('behavioral root corroboration is outside lifetime')
        rule_verified=True
    story_verified=False
    if 'story' in attack:
        from tc_pruning.attack_story import verify_story
        story_verified=verify_story(attack,events)
    return dict(multiview_references_verified=multiview_verified,learned_scores_recomputed=False,story_facts_verified=story_verified,activity_membership_verified=activity_verified,rule_witnesses_verified=rule_verified,raw_events_verified=True,strict_temporal_paths_verified=True,roles_verified=True,
                paths=len(attack['paths']),maliciousness_proven=False,
                limitation='Checks internal event/route consistency, not log authenticity, model optimality or ground-truth correctness.')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('report',type=Path);args=parser.parse_args()
    print(json.dumps(verify(json.loads(args.report.read_text())),indent=2))
