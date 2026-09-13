"""Evidence-preserving investigation scope, not another maliciousness classifier.

Adapted from conditional expansion and task segmentation. Resource propagation
is one write -> later read step only; common resources stop it. Bundling is
reversible WITHIN the selected subgraph, not lossless pruning of the full graph.
"""
from collections import defaultdict
from bisect import bisect_left
import hashlib

DEFAULT_CONFIG=dict(boundary_processes=5,resource_seconds=120,bundle_seconds=60)


def build_context(report, edges, config=None):
    from tc_pruning.attack_inference import process_metadata
    cfg=dict(DEFAULT_CONFIG,**(config or {}))
    if set(cfg)!=set(DEFAULT_CONFIG) or any(type(v) is not int or v<1 for v in cfg.values()):raise ValueError('invalid context configuration')
    by_id={e['id']:e for e in edges}
    if len(by_id)!=len(edges):raise ValueError('duplicate context event ID')
    predicted={n['id'] for n in report['nodes'] if n['predicted_attack']}
    required=set(report.get('evidence_event_ids',[]))|set(report.get('path_event_ids',[]))|set(report.get('context_event_ids',[]))
    selected=required|set(report.get('activity_event_ids',[]))
    if not selected<=by_id.keys():raise ValueError('missing context evidence')
    process_ids=set(process_metadata(edges));outsiders=defaultdict(set);writes=defaultdict(list)
    for e in edges:
        r=e['raw']
        if r['object']=='FILE':
            if r['actorID'] not in predicted:outsiders[r['objectID']].add(r['actorID'])
            if e['id'] in selected and r['actorID'] in predicted and r['action'] in ('WRITE','CREATE'):
                writes[r['objectID']].append(e['timestamp_ns'])
    boundaries={n for n,actors in outsiders.items() if len(actors)>=cfg['boundary_processes']}
    for times in writes.values():times.sort()
    added=set()
    for e in edges:
        r=e['raw'];resource=r['objectID']
        if r['object']!='FILE' or r['action']!='READ' or resource in boundaries or resource not in writes:continue
        times=writes[resource];idx=bisect_left(times,e['timestamp_ns'])-1
        if idx>=0 and e['timestamp_ns']-times[idx]<=cfg['resource_seconds']*1_000_000_000:added.add(e['id'])
    selected|=added
    grouped=defaultdict(list)
    for e in sorted((by_id[i] for i in selected),key=lambda e:(e['timestamp_ns'],e['id'])):
        key=(e['source'],e['target'],e['relation'],e['timestamp_ns']//(cfg['bundle_seconds']*1_000_000_000))
        grouped[key].append(e)
    bundles=[]
    for key,items in sorted(grouped.items()):
        ids=[e['id'] for e in items]
        bundles.append(dict(id='bundle-'+hashlib.sha256('\n'.join(ids).encode()).hexdigest()[:16],source=key[0],target=key[1],relation=key[2],
            time_block=key[3],event_count=len(ids),event_ids=ids,start=items[0]['timestamp'],end=items[-1]['timestamp']))
    nodes={n for i in selected for n in (by_id[i]['source'],by_id[i]['target'])}
    return dict(version='context-graph-v1',config=cfg,event_ids=sorted(selected),required_event_ids=sorted(required),
        resource_expansion_event_ids=sorted(added-selected.intersection(required|set(report.get('activity_event_ids',[])))),
        predicted_process_ids=sorted(predicted),context_process_ids=sorted((nodes&process_ids)-predicted),
        boundary_node_ids=sorted(boundaries&nodes),node_ids=sorted(nodes),bundles=bundles,
        summary=dict(candidate_events=len(edges),selected_events=len(selected),bundle_count=len(bundles),selected_nodes=len(nodes),
            preserved_required_events=len(required),required_events=len(required),
            event_reduction=1-len(selected)/len(edges) if edges else 0,
            bundle_reduction=1-len(bundles)/len(selected) if selected else 0),
        contract=dict(truth_used=False,classification_changed=False,full_graph_lossless=False,bundles_reversible=True,
            guarantee='保留输入检测器的全部判定证据和已输出路径；聚合组可展开到每条原始事件。该保证不等于保留所有真实攻击事件。',
            limitation='共享文件关联只生成上下文节点，不把读取者自动判攻击；不证明文件内容传播或攻击阶段完成。'))


def verify_context(context, report, edges):
    expected=build_context(report,edges,context.get('config'))
    if context!=expected:raise ValueError('context membership or bundle evidence mismatch')
    return True


def verify_context_export(context, report, events):
    """Verify exported membership, not boundary selection against omitted logs."""
    by_id={e['id']:e for e in events};ids=set(context['event_ids'])
    required=set(report['evidence_event_ids'])|set(report['path_event_ids'])|set(report.get('context_event_ids',[]))
    if not ids<=by_id.keys() or not required<=ids or set(context['required_event_ids'])!=required:
        raise ValueError('context export evidence missing')
    seen=[]
    for b in context['bundles']:
        es=[by_id[i] for i in b['event_ids']]
        if not es or len(es)!=b['event_count'] or any((e['source'],e['target'],e['relation'])!=(b['source'],b['target'],b['relation']) for e in es):
            raise ValueError('context export bundle mismatch')
        if es!=sorted(es,key=lambda e:(e['timestamp_ns'],e['id'])) or (b['start'],b['end'])!=(es[0]['timestamp'],es[-1]['timestamp']):
            raise ValueError('context export times mismatch')
        if any(e['timestamp_ns']//(context['config']['bundle_seconds']*1_000_000_000)!=b['time_block'] for e in es):raise ValueError('context export block mismatch')
        seen.extend(b['event_ids'])
    if len(seen)!=len(set(seen)) or set(seen)!=ids:raise ValueError('context export partition mismatch')
    return True
