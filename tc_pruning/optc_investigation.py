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
from tc_pruning.evidence_selection import select_evidence, audit_selection, validate_routes, witness_bundle
from collections import Counter
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack

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


def rescore(data, poi_id, budget_ratio=None, selection_mode=None, attack_quantile=None, detector=None):
    """Update one isolated cache value; truth only declares the manual seed."""
    started = time.monotonic()
    edges = sorted(data['edges'], key=lambda e:(e['timestamp_ns'],e['id']))
    data['edges'] = edges
    selection_mode = selection_mode or data['algorithm'].get('selection_mode', 'context')
    if selection_mode not in ('evidence','context'): raise ValueError('unknown selection mode')
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
    evidence = diag['contrast_only']
    certified = diag['positive_lift_certified']
    numerical_routes_valid = validate_routes(src,dst,timestamp,poi,backward,parent,pivot)
    semantic_ids={};semantic_family=np.array([semantic_ids.setdefault(signature_key(e),len(semantic_ids)) for e in edges])
    if selection_mode=='evidence':
        tie_keys=[(abs(e['timestamp_ns']-edges[selected]['timestamp_ns']),e['timestamp_ns'],e['id']) for e in edges]
        kept,audit=select_evidence(evidence,poi,backward,parent,pivot,semantic_family,budget,tie_keys,certified=certified)
        verified=audit_selection(kept,poi,backward,parent,pivot,audit,evidence,semantic_family,budget)
        trace=[dict(row,anchor=edges[row['anchor']]['id'],new_edges=[edges[j]['id'] for j in row['new_edges']]) for row in audit['trace']]
        certificate=dict(verified,temporal_links_valid=numerical_routes_valid,
                         objective=audit['objective'],objective_upper_bound=audit['objective_upper_bound'],
                         objective_fraction_of_upper_bound=audit['objective_fraction_of_upper_bound'],
                         stop_reason=audit['stop_reason'],unused_budget=audit['unused_budget'],
                         eligible_count=audit['eligible_count'])
    else:
        kept,anchors,legacy=select_diverse(scores,poi,backward,parent,pivot,event_families(src,dst,relation),budget,ties,quality_weight=.05,record_audit=True)
        owners=np.full(len(edges),-1,dtype=int)
        for i in sorted(np.flatnonzero(anchors),key=lambda i:(int(legacy['selected_step'][i]),edges[i]['id'])):
            for j in witness_bundle(int(i),backward,parent,pivot):
                if owners[j]<0: owners[j]=i
        audit=dict(owner=owners,step_of=legacy['selected_step'],eligible=(pivot>=0)&(scores>0),reasons=[
            'manual_poi' if poi[i] else 'context_anchor' if anchors[i] else 'causal_connector' if kept[i]
            else 'no_temporal_witness' if pivot[i]<0 else 'no_propagation_score' if scores[i]<=0 else 'context_bundle_exceeded_budget_at_attempt' if i in legacy['attempts'] else 'context_not_reached_before_stop' for i in range(len(edges))])
        trace=[dict(row,anchor=edges[row['anchor']]['id'],new_edges=[edges[j]['id'] for j in row['new_edges']]) for row in legacy['trace']]
        replayed=set(np.flatnonzero(poi))
        for row in legacy['trace']:
            needed=set(witness_bundle(row['anchor'],backward,parent,pivot))-replayed
            if needed!=set(row['new_edges']) or row['used_before']!=len(replayed) or row['used_after']!=len(replayed|needed):
                raise ValueError('context ledger replay mismatch')
            replayed|=needed
        if replayed!=set(np.flatnonzero(kept)):raise ValueError('context ledger final mismatch')
        kept_set=set(np.flatnonzero(kept))
        certificate=dict(budget_valid=int(kept.sum())<=budget,poi_preserved=bool(np.all(kept[poi])),
                         temporal_links_valid=numerical_routes_valid,
                         complete_witnesses=all(set(witness_bundle(int(i),backward,parent,pivot))<=kept_set for i in np.flatnonzero(anchors)),
                         ledger_replayed=True,unused_budget=budget-int(kept.sum()),
                         stop_reason='legacy_context_policy',eligible_count=int(audit['eligible'].sum()))
    reason_labels={'manual_poi':'手动 POI', 'evidence':'背景增益证据', 'causal_connector':'完整时序路径连接边',
                   'no_temporal_witness':'没有到 POI 的时序见证', 'no_positive_background_lift':'没有正的背景增益',
                   'background_lift_within_numeric_error':'背景增益未超出数值误差界',
                   'bundle_exceeds_remaining_budget':'完整路径新增边数超过剩余预算',
                   'context_anchor':'扩展上下文锚点（可仅有保底分）', 'no_propagation_score':'传播分为零',
                   'context_bundle_exceeded_budget_at_attempt':'考虑时整条路径超过剩余预算',
                   'context_not_reached_before_stop':'预算耗尽或队列结束前未轮到该锚点'}
    displayed_score=evidence if selection_mode=='evidence' else scores
    exact_ties=Counter(float(v) for v in displayed_score)
    shown_ties=Counter(format(float(v),'.9g') for v in displayed_score)
    data['decision_inputs']=dict(event_ids=[e['id'] for e in edges],src=src.tolist(),dst=dst.tolist(),
        timestamp_ns=timestamp.tolist(),poi=poi.tolist(),backward=backward.tolist(),parent=parent.tolist(),
        pivot=pivot.tolist(),family=semantic_family.tolist(),evidence=evidence.tolist(),certified=certified.tolist(),
        owner=audit['owner'].tolist(),eligible=audit['eligible'].tolist(),budget=budget,
        retained=kept.tolist(),quality=.05,propagation_score=scores.tolist(),legacy_family=event_families(src,dst,relation).tolist(),tie_order=ties.tolist())
    certificate['inputs_sha256']=hashlib.sha256(json.dumps(data['decision_inputs'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    data['decision_trace']=trace
    data['decision_certificate']=certificate
    data['decision_contract']=dict(mode=selection_mode,scalar_score_threshold=None,
        eligibility='两端 POI-PPR 超过背景 PPR，且超出迭代误差界；存在严格时序见证',
        numerical_bound='每次 PPR 的 L1 误差上界为 residual_l1 / restart；两端均须超过两个误差上界之和',
        selection='完整路径的总边际收益 / 新增边数贪心；不是单边分数阈值',
        tie_break='收益率、总收益、距 POI 时间、时间戳、事件 ID；不扰动分数',
        score_meaning='调查相关性证据，不是恶意概率',statistical_fpr_guarantee=False,
        calibration='没有独立、标注充分且满足适用假设的校准集，不报告误报率保证')
    if selection_mode=='context':
        data['decision_contract'].update(eligibility='旧传播分（含数值保底通道）大于零且存在时序见证',
            selection='旧 RASP-D 按锚点边际收益排序，完整路径计入预算；不是总路径收益贪心',
            tie_break='事件 ID SHA-256；不扰动分数')
    data['score_diagnostics']=dict(exact_unique=len(exact_ties),rounded_four_unique=len(set(format(float(v),'.4f') for v in displayed_score)),
        largest_exact_tie=max(exact_ties.values()),certified_evidence_edges=int(certified.sum()),
        retained_without_positive_contrast=int((kept & (evidence<=0)).sum()),
        threshold_equivalent=bool(not np.any(~kept) or float(np.min(displayed_score[kept]))>float(np.max(displayed_score[~kept]))))

    for i,e in enumerate(edges):
        e.update(score=float(displayed_score[i]), propagation_score=float(scores[i]), evidence_score=float(evidence[i]), retained=bool(kept[i]), poi=bool(poi[i]),
                 historical_count=int(frequency[i]), historical_frequency=float(frequency[i]/history['history_edges']),
                 components=dict(rarity=float(rarity[i]),diffusion=float(diag['diffusion'][i])),
                 reason=reason_labels[audit['reasons'][i]])
        owner=int(audit['owner'][i])
        witness=witness_bundle(owner,backward,parent,pivot) if owner>=0 else ()
        e['decision']=dict(context_attempt=legacy['attempts'].get(i) if selection_mode=='context' else None,code=audit['reasons'][i],certified_background_lift=bool(certified[i]),
                           background_margin_lower=float(diag['background_margin_lower'][i]),
                           temporal_witness=bool(pivot[i]>=0),step=int(audit['step_of'][i]),
                           owner_event_id=edges[owner]['id'] if owner>=0 else None,
                           witness_event_ids=[edges[j]['id'] for j in witness],
                           exact_tie_count=exact_ties[float(displayed_score[i])],display_tie_count=shown_ties[format(float(displayed_score[i]),'.9g')])
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
    groundtruth_backed=bool(preset and preset.get('groundtruth_backed',True))
    data['poi'] = dict(event_id=poi_id,timestamp=edges[selected]['timestamp'],
                       label=preset['label'] if preset else '用户手动指定事件',
                       evidence=preset['evidence'] if preset else '用户手动输入；未声称此事件由 Ground Truth 证实',
                       groundtruth_backed=groundtruth_backed)
    data['history'] = history
    data['metrics'] = dict(candidate_edges=len(edges),retained_edges=int(kept.sum()),candidate_nodes=len(nodes),
                           retained_nodes=len({e[k] for e in edges if e['retained'] for k in ('source','target')}),
                           budget_edges=budget,history_edges=history['history_edges'])
    data['nodes'] = list(nodes.values())
    by_id={e['id'] for e in edges}
    fixed_sample=[edges[i]['id'] for i in np.linspace(0,len(edges)-1,min(80,len(edges)),dtype=int)]
    data['display_event_ids']=list(dict.fromkeys(fixed_sample+[p['event_id'] for p in data['poi_presets'] if p['event_id'] in by_id]+[poi_id]))
    data['truth'].update(matched_events=matched,retained_events=retained,seed_event_id=poi_id,
                         retention_rate=retained/matched if matched else None,
                         non_poi_matched=int(reference_without_poi.sum()),
                         non_poi_retained=int((reference_without_poi & kept).sum()),stages=stages,
                         note='PDF 指标匹配是参考证据，不是完整攻击边标注。POI 由配置或用户手动指定；参考标签不参与其余边的打分和选边。')
    data['algorithm'].update(budget_ratio=budget_ratio, selection_mode=selection_mode, rarity='1 / (1 + 严格早于 POI 的同语义交互次数)',
                             frequency='同语义交互次数 / POI 前全部历史事件数',
                             seed_source='manual groundtruth-backed configuration' if groundtruth_backed else 'manual user event ID')
    quantile = attack_quantile if attack_quantile is not None else data.get('attack',{}).get('config',{}).get('anomaly_quantile',.90)
    data['attack'] = infer_attack(edges, poi_id, dict(anomaly_quantile=quantile),detector=detector if detector is not None else data.get('attack',{}).get('detector','rules'))
    data['attack']['evaluation'] = evaluate_attack(data['attack'], edges)
    attack_paths, attack_evidence = set(data['attack']['path_event_ids']), set(data['attack']['evidence_event_ids'])
    for e in edges:
        e['attack_role'] = 'path_and_evidence' if e['id'] in attack_paths & attack_evidence else 'path' if e['id'] in attack_paths else 'evidence' if e['id'] in attack_evidence else 'none'
    data['logs']=[f"读取 OPTC：{len(data['dataset'].get('sources',[]))} 份来源文件；主机 SysClient0201",
                  f"手动 POI：{data['poi']['label']} · {poi_id}",f"POI 时间 / 频率截止：{data['poi']['timestamp']}，严格小于，不含同刻事件",
                  f"累计历史：{history['history_edges']:,} 条；按原始事件 ID 去重，不按窗口对半切分",
                  f"候选窗口保持不变：{len(edges):,} 条（包含 POI 前后事件；仅评分历史截止 POI）",
                  f"RASP / {selection_mode}：保留 {int(kept.sum()):,} / {len(edges):,}，预算上限 {budget:,}",
                  f"PDF 指标参考保留 {retained} / {matched}；排除 POI 后 {data['truth']['non_poi_retained']} / {data['truth']['non_poi_matched']}",
                  f"判定审计：预算有效={certificate['budget_valid']}，完整时序见证={certificate['complete_witnesses']}，剩余预算={certificate['unused_budget']}",
                  f"攻击推断：{data['attack']['summary']['inferred_attack_nodes']} 个进程假设，{data['attack']['summary']['paths']} 条时序路径；独立于剪枝预算",
                  f"攻击节点评估：已知正例找回 {data['attack']['evaluation']['node_metrics']['tp']} / {data['attack']['evaluation']['node_metrics']['known_positive']}；未标注预测 {data['attack']['evaluation']['node_metrics']['unreviewed_predictions']} 个，不计为正常或误报",
                  f"重算完成，用时 {time.monotonic()-started:.2f} 秒"]
    return data
