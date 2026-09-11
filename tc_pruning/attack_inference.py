"""POI-conditioned attack hypotheses, separate from pruning and truth labels.

This is an inspectable hybrid heuristic, not a calibrated malware classifier.
Only processes receive an attack hypothesis. Resources and lineage connectors
retain separate roles. No ground-truth identifiers are read by this module.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
import re
import time

import numpy as np

from tc_pruning.optc import signature

VERSION = 'attack-hypothesis-v1'
DEFAULT_CONFIG = dict(anomaly_quantile=.90, min_families=2, top_families=3,
                      max_lineage_hops=12,max_path_anchors=12,lineage_depth=4,lineage_seconds=600,launcher_seconds=120)


def process_metadata(edges):
    """eCAR CREATE pid/image refer to the CHILD, ppid/parent_image to actor."""
    nodes = {}
    def add(nid, pid=None, image=None):
        n = nodes.setdefault(nid, dict(id=nid, pids=set(), images=set()))
        if pid is not None: n['pids'].add(pid)
        if image: n['images'].add(image)
    for e in edges:
        r = e['raw']; p = r.get('properties', {})
        if r['object'] == 'PROCESS' and r['action'] == 'CREATE':
            add(r['actorID'], r.get('ppid'), p.get('parent_image_path'))
            add(r['objectID'], r.get('pid'), p.get('image_path'))
        else:
            add(r['actorID'], r.get('pid'), p.get('image_path'))
            if r['object'] == 'PROCESS': add(r['objectID'], image=p.get('target_image_path'))
    return {k:dict(id=k, pids=sorted(v['pids'], key=str), images=sorted(v['images']))
            for k,v in sorted(nodes.items())}


def command_signals(raw):
    """Static syntax observations only; never execute or infer truncated payloads."""
    if (raw['object'], raw['action']) != ('PROCESS', 'CREATE'): return []
    p = raw.get('properties', {})
    if p.get('image_path', '').lower().replace('/', '\\').split('\\')[-1] not in ('powershell.exe', 'pwsh.exe'):
        return []
    command = p.get('command_line', '')
    signals = []
    if re.search(r'(?i)(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+\S+', command):
        signals.append('encoded_command')
    if re.search(r'(?i)(?:^|\s)-(?:w|windowstyle)\s+(?:hidden|1)(?:\s|$)', command):
        signals.append('hidden_window')
    return signals


def actor_for_evidence(edge):
    r = edge['raw']
    return r['objectID'] if (r['object'], r['action']) == ('PROCESS', 'CREATE') else r['actorID']


def transfer_edge(e):
    # OPEN/TERMINATE records alone do not establish an information transfer.
    r = e['raw']
    return ((r['object'] == 'PROCESS' and r['action'] == 'CREATE') or
            (r['object'] == 'FILE' and r['action'] in ('READ', 'WRITE', 'CREATE')) or
            r['object'] == 'FLOW') and e['source'] != e['target']


def temporal_paths(edges, source, start_ns):
    """Canonical earliest-arrival directed paths, with strict timestamp steps."""
    reached = {source: ()}
    grouped = defaultdict(list)
    for e in edges:
        if e['timestamp_ns'] > start_ns and transfer_edge(e):
            grouped[e['timestamp_ns']].append(e)
    for timestamp in sorted(grouped):
        updates = {}
        for e in sorted(grouped[timestamp], key=lambda e:e['id']):
            if e['source'] in reached and e['target'] not in reached:
                updates.setdefault(e['target'], reached[e['source']] + (e['id'],))
        reached.update(updates)
    return reached


def check_path(event_ids, by_id):
    if not event_ids or len(event_ids) != len(set(event_ids)): return False
    try: es = [by_id[i] for i in event_ids]
    except KeyError: return False
    return all(transfer_edge(e) for e in es) and all(
        a['target'] == b['source'] and a['timestamp_ns'] < b['timestamp_ns']
        for a,b in zip(es, es[1:]))


def infer_attack(edges, poi_id, config=None, detector='rules', neural_scores=None):
    started = time.monotonic()
    cfg = dict(DEFAULT_CONFIG, **(config or {}))
    if detector not in ('rules','rules_legacy','neural'):raise ValueError('unknown attack detector')
    if detector=='neural' and neural_scores is None:
        from tc_pruning.deep_graph import score_nodes
        neural_scores=score_nodes(edges)
    q = cfg['anomaly_quantile']
    if isinstance(q, bool) or not isinstance(q, (float,int)) or not 0 < q < 1:
        raise ValueError('anomaly_quantile must be in (0, 1)')
    for key in ('min_families', 'top_families', 'max_lineage_hops','max_path_anchors','lineage_depth','lineage_seconds','launcher_seconds'):
        if type(cfg[key]) is not int or cfg[key] < 1: raise ValueError(f'invalid {key}')
    edges = sorted(edges, key=lambda e:(e['timestamp_ns'], e['id']))
    by_id = {e['id']:e for e in edges}
    if len(by_id) != len(edges): raise ValueError('duplicate event IDs')
    if poi_id not in by_id: raise ValueError('unknown POI')
    processes = process_metadata(edges)
    births, activities, families, linked = {}, defaultdict(list), defaultdict(dict), set()
    for e in edges:
        r = e['raw']; actor = actor_for_evidence(e)
        activities[r['actorID']].append(e)
        if (r['object'],r['action']) == ('PROCESS','CREATE'):
            births.setdefault(r['objectID'], e)
        if e.get('decision', {}).get('temporal_witness'):
            linked.update((e['source'], e['target']))
        if not e.get('decision', {}).get('certified_background_lift'): continue
        if not e.get('decision', {}).get('temporal_witness'): continue
        value = math.sqrt(max(0.,e['evidence_score']) / (1 + e['historical_count']))
        if not math.isfinite(value): raise ValueError('non-finite attack evidence')
        if value <= 0: continue
        key = signature(e)
        previous = families[actor].get(key)
        if previous is None or value > previous[0]: families[actor][key] = (value,e['id'])
    deaths={}
    for e in edges:
        if e['relation']=='PROCESS_TERMINATE' and e['target'] in births and e['timestamp_ns']>=births[e['target']]['timestamp_ns']:
            deaths.setdefault(e['target'],e['timestamp_ns'])
    rows = []
    for nid, meta in processes.items():
        support = sorted(families[nid].values(), key=lambda x:(-x[0],x[1]))
        # Fixed denominator: one family cannot masquerade as three observations.
        anomaly = sum(v for v,_ in support[:cfg['top_families']]) / cfg['top_families']
        birth = births.get(nid)
        flags = command_signals(birth['raw']) if birth else []
        corroboration = []
        if birth and len(flags) == 2:
            # Follow-up activity must occur AFTER this process launch.
            for e in activities[nid]:
                r=e['raw']; p=r.get('properties', {})
                if e['timestamp_ns'] <= birth['timestamp_ns']: continue
                if detector=='rules' and e['timestamp_ns']>=deaths.get(nid,float('inf')):continue
                if ((r['object'] == 'FLOW' and p.get('direction','').lower() == 'outbound') or
                    (r['object'] == 'PROCESS' and r['action'] == 'CREATE')):
                    corroboration.append(e['id']); break
        behavioral = bool(corroboration and nid in linked)
        evidence_ids = list(dict.fromkeys(([birth['id']] if flags else []) + corroboration + [i for _,i in support[:cfg['top_families']]]))
        rows.append(dict(**meta, label=meta['images'][0] if meta['images'] else nid,
                         anomaly_score=anomaly, family_count=len(support),
                         command_signals=flags, behavioral_match=behavioral,behavioral_candidate=bool(corroboration),corroboration_event_ids=corroboration,
                         evidence_event_ids=evidence_ids, poi_linked=nid in linked,
                         seed_node=nid in (by_id[poi_id]['source'],by_id[poi_id]['target']),
                         first_support_ns=min((by_id[i]['timestamp_ns'] for i in evidence_ids),default=None)))
    population = [r['anomaly_score'] for r in rows if r['family_count'] >= cfg['min_families'] and r['anomaly_score'] > 0]
    threshold = float(np.quantile(population,q)) if population else None
    for row in rows:
        outlier = bool(threshold is not None and row['anomaly_score'] > threshold and row['family_count'] >= cfg['min_families'])
        row.update(anomaly_match=outlier, predicted_attack=row['behavioral_match'] or outlier)
        row['reasons'] = []
        if row['behavioral_match']: row['reasons'].append('编码命令 + 隐藏窗口，且创建后存在出站连接或子进程；有 POI 调查关联')
        if outlier: row['reasons'].append(f"{row['family_count']} 个不同历史异常交互，聚合分严格超过当前窗口 {q:.0%} 分位线")
        if not row['reasons']: row['reasons'].append('未满足攻击假设判定；不等于已确认正常')
        row['status'] = 'inferred_attack' if row['predicted_attack'] else 'manual_seed' if row['seed_node'] else 'unclassified'
    rule_summary=None
    if detector=='rules':
        from tc_pruning.rule_lineage import expand_lineage
        rule_summary=expand_lineage(rows,edges,cfg)
    if detector=='neural':
        for row in rows:
            neural=neural_scores['nodes'].get(row['id'])
            row['rule_prediction']=row['predicted_attack']
            row['predicted_attack']=bool(neural and neural['predicted'])
            row['neural']=neural
            row['behavioral_match']=False;row['anomaly_match']=False
            row['anomaly_score']=neural['score'] if neural else 0.
            row['evidence_event_ids']=neural['evidence_event_ids'] if neural else []
            row['first_support_ns']=min((by_id[i]['timestamp_ns'] for i in row['evidence_event_ids']),default=None)
            row['reasons']=[f"学习到的图表示与历史近邻距离 {row['anomaly_score']:.5g} {'超过' if row['predicted_attack'] else '未超过'} 独立校准线 {neural_scores['threshold']:.5g}；规则不参与本次判定"]
            row['status']='inferred_attack' if row['predicted_attack'] else 'manual_seed' if row['seed_node'] else 'unclassified'
    rows.sort(key=lambda r:(not r['predicted_attack'],not r['behavioral_match'],-r['anomaly_score'],r['id']))
    for rank,row in enumerate(rows,1): row['rank']=rank
    predicted = {r['id']:r for r in rows if r['predicted_attack']}
    # Full observed activity of inferred processes is distinct from the small
    # selected path explanation. Do not silently report path samples as recovery.
    active={nid:births[nid]['timestamp_ns'] if nid in births else min((e['timestamp_ns'] for e in activities[nid]),default=0) for nid in predicted}
    ended={}
    for e in edges:
        if e['relation']=='PROCESS_TERMINATE' and e['target'] in active and e['timestamp_ns']>=active[e['target']]:
            ended.setdefault(e['target'],e['timestamp_ns'])
    activity_ids=[]
    for e in edges:
        actor=e['raw']['actorID']
        own=actor in active and active[actor]<=e['timestamp_ns']<=ended.get(actor,float('inf'))
        birth=e['relation']=='PROCESS_CREATE' and e['target'] in predicted and births[e['target']]['id']==e['id']
        terminal=e['relation']=='PROCESS_TERMINATE' and e['target'] in ended and e['timestamp_ns']==ended[e['target']]
        if own or birth or terminal:activity_ids.append(e['id'])
    paths, seen_paths, disconnected = [], set(), []
    def append_path(event_ids, kind, anchor, truncated=False):
        event_ids = tuple(event_ids)
        if event_ids in seen_paths or not check_path(event_ids,by_id): return
        seen_paths.add(event_ids)
        es = [by_id[i] for i in event_ids]
        node_ids = [es[0]['source']] + [e['target'] for e in es]
        shared_resource = kind=='between_inferred_nodes' and any(e['raw']['object']=='FILE' for e in es)
        paths.append(dict(id='path-'+hashlib.sha256('|'.join(event_ids).encode()).hexdigest()[:16],
                          kind=kind, anchor_node_id=anchor, event_ids=list(event_ids),node_ids=node_ids,
                          start=es[0]['timestamp'],end=es[-1]['timestamp'],
                          inferred_node_ids=list(dict.fromkeys(n for n in node_ids if n in predicted)),
                          lineage_truncated=truncated,temporal_valid=True,
                          support_level='dependency_only' if shared_resource else 'execution_trace',
                          interpretation='共享文件的读写关联可能来自正常缓存；不能据此证明攻击载荷传递或提权机制' if shared_resource else '真实进程启动/通信轨迹；不表示所有祖先进程恶意'))
    path_anchors=dict(list(predicted.items())[:cfg['max_path_anchors']])
    for nid,row in path_anchors.items():
        birth = births.get(nid)
        chain = [birth['id']] if birth else []
        cursor = birth
        while cursor and len(chain) < cfg['max_lineage_hops']:
            parent = births.get(cursor['source'])
            if not parent or parent['timestamp_ns'] >= cursor['timestamp_ns'] or parent['id'] in chain: break
            chain.insert(0,parent['id']);cursor=parent
        truncated = bool(cursor and len(chain)>=cfg['max_lineage_hops'] and births.get(cursor['source']))
        # Explicit lineage plus one real outgoing transfer; no GT-selected endpoint.
        outgoing = next((e for e in activities[nid] if e['source']==nid and transfer_edge(e)
                         and e['raw']['object']=='FLOW' and
                         (not birth or e['timestamp_ns'] > birth['timestamp_ns'])),None)
        if outgoing: chain.append(outgoing['id'])
        if chain: append_path(chain,'execution_lineage',nid,truncated)
        start = row['first_support_ns']
        reached = temporal_paths(edges,nid,start) if start is not None else {}
        for target in sorted(path_anchors):
            if nid==target: continue
            if target in reached: append_path(reached[target],'between_inferred_nodes',nid)
            else: disconnected.append(dict(source=nid,target=target,reason='首个支持证据之后未找到严格时序有向路径；不自动补边'))
    path_event_ids = set(i for p in paths for i in p['event_ids'])
    path_node_ids = set(n for p in paths for n in p['node_ids'])
    evidence_event_ids = set(i for r in rows if r['predicted_attack'] for i in r['evidence_event_ids'])
    resource_ids = path_node_ids - set(processes)
    connectors = (path_node_ids & set(processes)) - set(predicted)
    report = dict(version=VERSION,config=cfg,poi_event_id=poi_id, nodes=rows,paths=paths,
                  disconnected_pairs=disconnected,resource_node_ids=sorted(resource_ids),
                  connector_node_ids=sorted(connectors),path_event_ids=sorted(path_event_ids),
                  evidence_event_ids=sorted(evidence_event_ids),activity_event_ids=activity_ids,
                  activity_contract='Observed actor activity from process birth (or first observation) through termination, plus creation/termination boundaries; candidate event subgraph, not a single attack path or event-maliciousness proof',
                  summary=dict(inferred_attack_nodes=len(predicted),evaluated_process_nodes=len(rows),
                               paths=len(paths),path_edges=len(path_event_ids),activity_edges=len(activity_ids),resource_nodes=len(resource_ids),
                               connector_nodes=len(connectors),
                               path_anchor_nodes=len(path_anchors),untraced_predictions=len(predicted)-len(path_anchors),
                               execution_paths=sum(p['support_level']=='execution_trace' for p in paths),
                               dependency_only_paths=sum(p['support_level']=='dependency_only' for p in paths)),
                  threshold=dict(value=threshold,quantile=q,population_size=len(population),comparison='strict >',
                                 calibration='same-window empirical ranking; not benign validation or FPR control'),
                  contract=dict(truth_used=False,pruning_used=False,score_is_probability=False,
                                scope='POI-conditioned retrospective investigation in the entire candidate window',
                                classification='behavioral evidence OR high-tail anomaly; seeds are not forced predictions',
                                resources='参与路径的文件/网络对象不是自动判定的恶意节点',
                                paths='真实事件的严格时序有向路径；路径存在不证明每个节点或事件恶意'))
    report['detector']=detector
    if detector=='rules':
        report['version']='attack-hypothesis-v2-lineage'
        report['rule_summary']=rule_summary
        report['threshold'].update(value=None,review_value=threshold,calibration='No scalar attack threshold; empirical quantile only queues review')
        report['contract']['classification']=rule_summary['policy']
        report['contract']['scope']='Retrospective bounded execution attribution; no POI gating of behavioral roots'
    if detector=='neural':
        report['model']={k:v for k,v in neural_scores.items() if k!='nodes'}
        report['threshold']=dict(value=neural_scores['threshold'],comparison='strict >',calibration=neural_scores['calibration'])
        report['contract']['classification']='Learned graph embedding neighbor distance only; no rule or POI gating'
        report['contract']['scope']='Retrospective minute-level graphs in the candidate window; model/calibration strictly earlier'
    inputs = [dict(id=e['id'],source=e['source'],target=e['target'],timestamp_ns=e['timestamp_ns'],raw=e['raw'],
                   evidence_score=e.get('evidence_score'),historical_count=e.get('historical_count'),
                   certified=e.get('decision',{}).get('certified_background_lift'),
                   temporal_witness=e.get('decision',{}).get('temporal_witness')) for e in edges]
    report['input_sha256']=hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    report['runtime_seconds']=time.monotonic()-started
    return report
