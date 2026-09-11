"""Manual OpTC POI investigations with strict pre-POI historical frequencies."""
from __future__ import annotations
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import time

import numpy as np
from tc_pruning.optc import signature
from tc_pruning.rasp import propagate, temporal_routes, temporal_fork_routes
from tc_pruning.rasp_diverse import event_families, select_diverse

ROOT = Path(__file__).resolve().parents[1]


def signature_key(edge):
    return json.dumps(signature(edge), ensure_ascii=False, separators=(',', ':'))


def validate_presets(edges, manifest, pdf_text):
    for marker in ('132.197.158.98', 'runme.bat', 'Sysclient0201', '5452', '2952'):
        if marker.lower() not in pdf_text.lower():
            raise ValueError(f'Ground-truth PDF missing {marker}')
    by_id = {e['id']: e for e in edges}
    for preset in manifest['pois']:
        e = by_id.get(preset['event_id'])
        if e is None:
            raise ValueError(f"Configured POI missing from input: {preset['event_id']}")
        raw, props = e['raw'], e['raw']['properties']
        valid = raw['hostname'].lower() == manifest['host'].lower()
        valid &= all(raw.get(k) == preset[k] for k in ('object', 'action', 'pid'))
        valid &= datetime.fromisoformat(raw['timestamp']) == datetime.fromisoformat(preset['timestamp'])
        for key in ('dest_ip', 'dest_port'):
            if key in preset: valid &= str(props.get(key)) == preset[key]
        if 'file_suffix' in preset:
            valid &= props.get('file_path', '').lower().endswith(preset['file_suffix'].lower())
        if not valid:
            raise ValueError(f"Configured POI evidence mismatch: {preset['event_id']}")


def pre_poi_counts(database, cutoff_ns, index_id):
    path = Path(database).resolve()
    if not path.is_file():
        raise FileNotFoundError(f'Frequency index missing: {path}; run prepare_optc.py')
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
        metadata = dict(conn.execute('SELECT key, value FROM metadata'))
        if metadata.get('index_id') != index_id:
            raise ValueError('Frequency index and candidate cache do not match; rebuild cache')
        rows = conn.execute('SELECT signature, COUNT(*) FROM events WHERE timestamp_ns < ? GROUP BY signature', (cutoff_ns,))
        counts = dict(rows)
        count, start, end = conn.execute('SELECT COUNT(*), MIN(timestamp_ns), MAX(timestamp_ns) FROM events WHERE timestamp_ns < ?', (cutoff_ns,)).fetchone()
    return counts, dict(history_edges=count, start_ns=start, last_event_ns=end,
                        cutoff_ns=cutoff_ns, comparison='timestamp_ns < poi.timestamp_ns',
                        scope='所提供 OPTC 日志中，同主机全部可用历史；未截取一半窗口')


def reference_evidence(e):
    raw, evidence = e['raw'], []
    props = raw.get('properties', {})
    if raw['object'] == 'FLOW' and '132.197.158.98' in (props.get('dest_ip'), props.get('src_ip')):
        evidence.append('PDF Day 1 C2 IP: 132.197.158.98')
    if 'runme.bat' in props.get('file_path', '').lower():
        evidence.append('PDF Day 1 runme.bat 文件指标（含相关元数据文件）')
    return evidence


def rescore(data, poi_id, budget_ratio=None):
    """Update one isolated cache value; truth only declares the manual seed."""
    started = time.monotonic()
    edges = data['edges']
    selected = next((i for i,e in enumerate(edges) if e['id'] == poi_id), None)
    if selected is None:
        raise ValueError('POI event ID is not in the candidate window')
    budget_ratio = data['algorithm']['budget_ratio'] if budget_ratio is None else budget_ratio
    if isinstance(budget_ratio, bool) or not isinstance(budget_ratio, (int,float)) or not 0 < budget_ratio <= 1:
        raise ValueError('budget must be a number in (0, 1]')
    counts, history = pre_poi_counts(data['history_index']['path'], edges[selected]['timestamp_ns'], data['history_index']['id'])
    if not history['history_edges']:
        raise ValueError('No available history before this POI')
    frequency = np.array([counts.get(signature_key(e), 0) for e in edges])
    rarity = 1 / (1 + frequency.astype(float))
    node_ids = sorted({e[k] for e in edges for k in ('source', 'target')})
    ids = {n:i for i,n in enumerate(node_ids)}
    rels = {r:i for i,r in enumerate(sorted({e['relation'] for e in edges}))}
    src, dst = [np.array([ids[e[k]] for e in edges]) for k in ('source', 'target')]
    relation = np.array([rels[e['relation']] for e in edges])
    timestamp = np.array([e['timestamp_ns'] for e in edges], dtype=np.int64)
    nodes = {}
    for e in edges:
        for side in ('source', 'target'):
            n = dict(id=e[side], label=e[side+'_label'], type=e[side+'_type'])
            if n['id'] not in nodes or nodes[n['id']]['label'] == n['id']: nodes[n['id']] = n
    poi = np.zeros(len(edges), dtype=bool)
    poi[selected] = True
    config = data['algorithm']['config']
    scores, diag = propagate(src,dst,relation,rarity,poi,np.array([nodes[n]['type']=='process' for n in node_ids]),config)
    backward = temporal_routes(src,dst,timestamp,poi)[0][0]
    parent,pivot,_,_ = temporal_fork_routes(src,dst,timestamp,poi,backward)
    ties = np.array([int(hashlib.sha256(e['id'].encode()).hexdigest()[:15],16) for e in edges])
    budget = max(1, int(len(edges)*budget_ratio))
    kept,_,_ = select_diverse(scores,poi,backward,parent,pivot,event_families(src,dst,relation),budget,ties,quality_weight=.05)
    for i,e in enumerate(edges):
        e.update(score=float(scores[i]), retained=bool(kept[i]), poi=bool(poi[i]),
                 historical_count=int(frequency[i]), historical_frequency=float(frequency[i]/history['history_edges']),
                 components=dict(rarity=float(rarity[i]),diffusion=float(diag['diffusion'][i])),
                 reason='手动指定 POI' if poi[i] else '评分与因果连接成组保留' if kept[i] else '无时序连接' if pivot[i]<0 else '预算内未入选')
        e['reference_evidence'] = reference_evidence(e)
    refs = np.array([bool(e['reference_evidence']) for e in edges])
    reference_without_poi = refs & ~poi
    matched, retained = int(refs.sum()), int((refs & kept).sum())
    stages=[]
    for label, mask in [('runme.bat 文件相关',np.array([any('runme.bat' in s for s in e['reference_evidence']) for e in edges])),
                        ('初始代理 PID 5452 的 C2',np.array([e['raw'].get('pid')==5452 and e['raw']['object']=='FLOW' for e in edges]) & refs),
                        ('提权代理 PID 2952 的 C2',np.array([e['raw'].get('pid')==2952 and e['raw']['object']=='FLOW' for e in edges]) & refs)]:
        stages.append(dict(label=label,matched=int(mask.sum()),retained=int((mask & kept).sum())))
    preset = next((p for p in data['poi_presets'] if p['event_id']==poi_id), None)
    data['poi'] = dict(event_id=poi_id,timestamp=edges[selected]['timestamp'],
                       label=preset['label'] if preset else '用户手动指定事件',
                       evidence=preset['evidence'] if preset else '用户手动输入；未声称此事件由 Ground Truth 证实',
                       groundtruth_backed=preset is not None)
    data['history'] = history
    data['metrics'] = dict(candidate_edges=len(edges),retained_edges=int(kept.sum()),candidate_nodes=len(nodes),
                           retained_nodes=len({e[k] for e in edges if e['retained'] for k in ('source','target')}),
                           budget_edges=budget,history_edges=history['history_edges'])
    data['nodes'] = list(nodes.values())
    data['truth'].update(matched_events=matched,retained_events=retained,seed_event_id=poi_id,
                         retention_rate=retained/matched if matched else None,
                         non_poi_matched=int(reference_without_poi.sum()),
                         non_poi_retained=int((reference_without_poi & kept).sum()),stages=stages,
                         note='PDF 指标匹配是参考证据，不是完整攻击边标注。POI 由配置或用户手动指定；参考标签不参与其余边的打分和选边。')
    data['algorithm'].update(budget_ratio=budget_ratio, rarity='1 / (1 + 严格早于 POI 的同语义交互次数)',
                             frequency='同语义交互次数 / POI 前全部历史事件数',
                             seed_source='manual groundtruth-backed configuration' if preset else 'manual user event ID')
    data['logs']=[f"读取 OPTC：{len(data['dataset'].get('sources',[]))} 份来源文件；主机 SysClient0201",
                  f"手动 POI：{data['poi']['label']} · {poi_id}",f"POI 时间 / 频率截止：{data['poi']['timestamp']}，严格小于，不含同刻事件",
                  f"累计历史：{history['history_edges']:,} 条；按原始事件 ID 去重，不按窗口对半切分",
                  f"候选窗口保持不变：{len(edges):,} 条（包含 POI 前后事件；仅评分历史截止 POI）",
                  f"RASP-D：保留 {int(kept.sum()):,} / {len(edges):,}，预算上限 {budget:,}",
                  f"PDF 指标参考保留 {retained} / {matched}；排除 POI 后 {data['truth']['non_poi_retained']} / {data['truth']['non_poi_matched']}",
                  f"重算完成，用时 {time.monotonic()-started:.2f} 秒"]
    return data
