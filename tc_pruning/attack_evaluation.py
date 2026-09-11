"""Truth is consumed only AFTER predictions, with unknown labels preserved."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

from tc_pruning.attack_inference import check_path, temporal_paths

REFERENCE = Path(__file__).resolve().parents[1] / 'poi/optc-day1-attack-reference.json'
PUBLIC_LABELS = REFERENCE.with_name('optc-0201-public-labels.json')
TAPAS_LABELS = REFERENCE.with_name('tapas-optc-slices.json')


def node_metrics(node_ids, predicted, labels):
    """Missing/None means unknown, never an implicit negative."""
    universe, predicted = set(node_ids), set(predicted)
    if not predicted <= universe: raise ValueError('prediction outside node universe')
    if not set(labels) <= universe: raise ValueError('label outside node universe')
    if any(v is not None and type(v) is not bool for v in labels.values()):
        raise ValueError('labels must be true, false or null')
    positive = {n for n in universe if labels.get(n) is True}
    negative = {n for n in universe if labels.get(n) is False}
    unknown = universe - positive - negative
    tp, fp = len(predicted & positive), len(predicted & negative)
    fn, tn = len(positive - predicted), len(negative - predicted)
    unreviewed = len(predicted & unknown)
    fully_labeled = not unknown
    return dict(tp=tp,fp=fp,fn=fn,tn=tn,predicted=len(predicted),known_positive=len(positive),
                known_negative=len(negative),unknown_nodes=len(unknown),unreviewed_predictions=unreviewed,
                known_positive_recall=tp/len(positive) if positive else None,
                precision=tp/len(predicted) if predicted and not unreviewed else None,
                recall=tp/(tp+fn) if fully_labeled and tp+fn else None,
                accuracy=(tp+tn)/len(universe) if fully_labeled and universe else None,
                f1=2*tp/(2*tp+fp+fn) if fully_labeled and 2*tp+fp+fn else None,
                precision_bounds=[tp/len(predicted),(tp+unreviewed)/len(predicted)] if predicted else None,
                complete_labels=fully_labeled)


def evaluate_attack(report, edges, reference=None):
    reference = json.loads(REFERENCE.read_text()) if reference is None else reference
    scoped = [e for e in edges if e['raw']['hostname'].lower()==reference['host'].lower()
              and e['timestamp'].startswith(reference['date'])]
    scoped_ids = {n for e in scoped for n in (e['source'],e['target'])}
    by_id = {e['id']:e for e in edges}
    predicted = {n['id'] for n in report['nodes'] if n['predicted_attack']}
    universe = {n['id'] for n in report['nodes']}
    resolved, labels = [], {}
    for spec in reference['processes']:
        matches = [n['id'] for n in report['nodes'] if n['id'] in scoped_ids and spec['pid'] in n['pids']
                   and any(s.lower().replace('/', '\\').split('\\')[-1]==spec['image_basename'].lower() for s in n['images'])]
        # OpTC officially documents duplicate process objects. Anchor this PDF
        # agent to its observed C2 actor; do not merge UUIDs merely by PID.
        c2_actors = {e['raw']['actorID'] for e in scoped if e['raw']['object']=='FLOW'
                     and e['raw'].get('pid')==spec['pid'] and reference['c2_ip'] in
                     (e['raw']['properties'].get('src_ip'),e['raw']['properties'].get('dest_ip'))}
        candidates = matches
        matches = sorted(set(matches) & c2_actors)
        entry = dict(**spec,node_ids=matches,pid_image_candidates=candidates,resolved=len(matches)==1,
                     resolution='host + date + PID + image + observed PDF C2 actor UUID; no PID-only merging')
        if len(matches)==1:
            labels[matches[0]]=True
            entry['predicted']=matches[0] in predicted
        resolved.append(entry)
    metrics = node_metrics(universe,predicted,labels)
    seeds = {n['id'] for n in report['nodes'] if n['seed_node']}
    metrics['excluding_seed_nodes']=node_metrics(universe-seeds,predicted-seeds,{n:v for n,v in labels.items() if n not in seeds})
    segments=[]
    for entry in resolved:
        if not entry['resolved']: continue
        nid=entry['node_ids'][0]
        expected={e['id'] for e in scoped if e['raw']['actorID']==nid and e['raw']['object']=='FLOW'
                  and reference['c2_ip'] in (e['raw']['properties'].get('src_ip'),e['raw']['properties'].get('dest_ip'))}
        recovered=sorted(expected & set(report['path_event_ids']))
        segments.append(dict(label=entry['label']+' ↔ C2 通信片段',process_id=nid,
                             observable=bool(expected),candidate_events=len(expected),
                             recovered=bool(recovered),recovered_event_ids=recovered))
    # A narrative transition is not a fabricated ground-truth edge/path.
    gaps=[]
    if len(resolved)==2 and all(r['resolved'] for r in resolved):
        initial,elevated=(r['node_ids'][0] for r in resolved)
        source_files=sorted({e['raw']['objectID'] for e in scoped if e['raw']['object']=='FILE'
                            and e['raw']['properties'].get('file_path','').lower().replace('/', '\\').split('\\')[-1]==reference['download_basename']})
        queries=[('下载文件 → 初始代理',source_files,initial),('初始代理 → 提权代理',[initial],elevated)]
        for label,sources,target in queries:
            full_paths=[]
            for source in sources:
                # Structural observability within the window, not proof of malice.
                path=temporal_paths(scoped,source,min(e['timestamp_ns'] for e in scoped)-1).get(target)
                if path: full_paths.append(list(path))
            emitted=any(any(s in p['node_ids'][:p['node_ids'].index(target)] for s in sources)
                        for p in report['paths'] if target in p['node_ids'])
            gaps.append(dict(label=label,observable_in_window=bool(full_paths),
                             recovered=emitted,example_observed_path=full_paths[0] if full_paths else [],
                             attack_mechanism_verified=False,
                             note='只检查遥测连通性；共享缓存等依赖不能证明提权或载荷传递，缺失时不补边'))
    observable=sum(s['observable'] for s in segments)
    result = dict(source=reference['source'],page=reference['page'],scope_note=reference['scope_note'],
                resolved_processes=resolved,node_metrics=metrics,reference_segments=segments,
                path_metrics=dict(emitted=len(report['paths']),
                                  structurally_valid=sum(check_path(p['event_ids'],by_id) for p in report['paths']),
                                  observable_reference_segments=observable,
                                  recovered_reference_segments=sum(s['recovered'] for s in segments),
                                  reference_segment_coverage=sum(s['recovered'] for s in segments)/observable if observable else None,
                                  full_attack_path_precision=None,full_attack_path_recall=None),
                narrative_gaps=gaps,
                limitation='已知正例找回率不是完整召回率；没有完整正常/攻击标签时 accuracy、F1 与完整路径准确率不报告。')
    digest=lambda ids:hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest()
    extra=PUBLIC_LABELS.parent/'example-labels'/f'{digest(by_id)}.json'
    label_file=extra if extra.is_file() else PUBLIC_LABELS
    if label_file.is_file():
        benchmark=json.loads(label_file.read_text())
        if (digest(by_id)==benchmark['scope']['event_ids_sha256'] and
            digest(universe)==benchmark['scope']['process_ids_sha256']):
            labels=benchmark['node_labels']
            bm=node_metrics(universe,predicted,labels)
            bm['excluding_seed_nodes']=node_metrics(universe-seeds,predicted-seeds,{n:v for n,v in labels.items() if n not in seeds})
            emitted_events=set(report['path_event_ids']);malicious=set(benchmark['malicious_event_ids'])
            all_labeled=sum(set(p['event_ids'])<=malicious for p in report['paths'])
            path_processes=set(n for p in report['paths'] for n in p['node_ids']) & universe
            activity=set(report.get('activity_event_ids',[]));activity_matches=len(activity & malicious)
            result['published_benchmark']=dict(repository=benchmark['repository'],commit=benchmark['commit'],
                policy=benchmark['policy'],labels=labels,node_metrics=bm,
                activity_event_metrics=dict(predicted_events=len(activity),labeled_malicious_events=len(malicious),matched_events=activity_matches,
                    false_positive_events=len(activity-malicious),missed_events=len(malicious-activity),
                    missed_event_ids=sorted(malicious-activity),false_positive_event_ids=sorted(activity-malicious),
                    precision=activity_matches/len(activity) if activity else None,recall=activity_matches/len(malicious) if malicious else None),
                missed_process_ids=sorted(n for n,v in labels.items() if v is True and n not in predicted),
                false_positive_process_ids=sorted(n for n,v in labels.items() if v is False and n in predicted),
                path_event_metrics=dict(predicted_events=len(emitted_events),labeled_malicious_events=len(malicious),
                                        matched_events=len(emitted_events & malicious),
                                        precision=len(emitted_events & malicious)/len(emitted_events) if emitted_events else None,
                                        recall=len(emitted_events & malicious)/len(malicious) if malicious else None,
                                        paths_with_all_events_labeled_malicious=all_labeled),
                path_process_coverage=node_metrics(universe,path_processes,labels),
                note='公开标签按其作者的补集规则计正常；含继承标签和已知数据错误。过程节点、路径上的上下文节点、逐事件与完整路径是不同评估单位，不能互换。')
    if TAPAS_LABELS.is_file():
        tapas=json.loads(TAPAS_LABELS.read_text())
        scope=tapas['windows'].get(digest(by_id))
        observed_nodes={n for e in edges for n in (e['source'],e['target'])}
        if scope and digest(observed_nodes)==scope['node_ids_sha256']:
            positive=set(scope['positive_node_ids']);labels={n:n in positive for n in universe}
            metrics=node_metrics(universe,predicted,labels)
            metrics['excluding_seed_nodes']=node_metrics(universe-seeds,predicted-seeds,{n:v for n,v in labels.items() if n not in seeds})
            published=result.get('published_benchmark',{}).get('labels',{})
            conflicts=[n for n in sorted(universe) if n in published and published[n] is not None and published[n]!=labels[n]]
            result['tapas_benchmark']=dict(source=tapas['source_path'],sha256=tapas['source_sha256'],
                source_node_count=tapas['source_node_count'],granularity=tapas['granularity'],limitation=tapas['limitation'],
                matched_types=scope['matched_types'],labels=labels,node_metrics=metrics,
                missed_process_ids=sorted(n for n in universe if labels[n] and n not in predicted),
                false_positive_process_ids=sorted(n for n in predicted if not labels[n]),
                disagreement_with_published_process_ids=conflicts,
                full_attack_path_precision=None,full_attack_path_recall=None)
    return result
