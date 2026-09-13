"""Page-cited narrative resolution; no detector imports or implicit negatives."""
from datetime import datetime
import hashlib
from pathlib import Path
import re


def ns(value):
    return int(datetime.fromisoformat(value).timestamp()*1_000_000_000)


def host(value):
    return value.lower().split('.')[0]


def validate_reference(pdf_path, reference):
    from pypdf import PdfReader
    path=Path(pdf_path)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=reference['sha256']:
        raise ValueError('PDF source hash mismatch')
    clean=lambda s:re.sub(r'\s+','',s).lower()
    pages=[clean(p.extract_text()) for p in PdfReader(path).pages]
    for item in reference.get('agents',[])+reference.get('artifacts',[])+reference.get('activities',[]):
        if not item.get('excerpt') or clean(item['excerpt']) not in pages[item['page']-1]:
            raise ValueError('PDF source excerpt mismatch: '+item.get('id',item.get('kind','item')))
    def citation(spec):
        if clean(spec['excerpt']) not in pages[spec['page']-1]:raise ValueError('PDF source excerpt mismatch')
        return spec['excerpt']
    for item in reference['agents']:
        parts=item['excerpt'].split()
        if len(parts)!=4 or (host(parts[0]),parts[1],parts[2],parts[3])!=(host(item['host']),item['id'],item['reported_ip'],str(item['pid'])):
            raise ValueError('PDF source identity fields mismatch')
        if item['c2_ip'] not in citation(item['c2_source']).split():raise ValueError('PDF C2 source mismatch')
    for item in reference['agents']+reference.get('artifacts',[]):
        for key,source in [('active_start' if 'pid' in item else 'start','start_source'),('active_end' if 'pid' in item else 'end','end_source')]:
            prefix=citation(item[source])[:17]
            parsed=datetime.strptime(prefix,'%m/%d/%y %H:%M:%S')
            actual=datetime.fromisoformat(item[key])
            if actual.replace(tzinfo=None)!=parsed or actual.utcoffset().total_seconds()!=-14400:
                raise ValueError('PDF source time mismatch')
        if 'date' in item and item['date']!=item['active_start'][:10]:raise ValueError('PDF source date mismatch')
    for item in reference.get('artifacts',[]):
        if item['basename'].lower() not in item['excerpt'].lower() or host(item['host']) not in item['excerpt'].lower():
            raise ValueError('PDF source artifact mismatch')
    return True


def resolve_pdf_reference(edges, reference):
    labels={};agents=[];resources=[];reference_events=set()
    hosts={host(e['raw']['hostname']) for e in edges}
    first=min((e['timestamp_ns'] for e in edges),default=0);last=max((e['timestamp_ns'] for e in edges),default=0)
    tolerance=reference.get('resolution_tolerance_seconds',0)*1_000_000_000
    for spec in reference['agents']:
        start=ns(spec['active_start'])-tolerance;end=ns(spec['active_end'])+tolerance
        scoped=[e for e in edges if host(e['raw']['hostname'])==host(spec['host']) and
                e['timestamp'].startswith(spec['date']) and start<=e['timestamp_ns']<=end]
        candidates={};pid_nodes=set()
        for e in scoped:
            r=e['raw'];p=r.get('properties',{})
            # On CREATE, pid denotes the child, never the actor.
            nid=r['objectID'] if (r['object'],r['action'])==('PROCESS','CREATE') else r['actorID']
            if str(r.get('pid'))==str(spec['pid']):pid_nodes.add(nid)
            if r['object']=='FLOW' and str(r.get('pid'))==str(spec['pid']) and spec['c2_ip'] in (p.get('src_ip'),p.get('dest_ip')):
                candidates.setdefault(r['actorID'],[]).append(e['id'])
        status='outside_dataset' if host(spec['host']) not in hosts else 'outside_window' if last<start or first>end else 'resolved' if len(candidates)==1 else 'ambiguous' if candidates else 'unobserved'
        ids=sorted(candidates) if status=='resolved' else []
        evidence=sorted(i for n in ids for i in candidates[n])
        if ids:
            labels[ids[0]]=True;reference_events.update(evidence)
            sockets=sorted({e['raw']['objectID'] for e in scoped if e['id'] in set(evidence)})
            resources.append(dict(kind='documented_c2_endpoint',agent_id=spec['id'],node_ids=sockets,event_ids=evidence,
                                  page=spec['page'],label_as_compromised_process=False))
        agents.append(dict(**spec,status=status,node_ids=ids,candidate_node_ids=sorted(candidates),pid_candidate_node_ids=sorted(pid_nodes),evidence_event_ids=evidence))
    for spec in reference.get('artifacts',[]):
        matched=[e for e in edges if host(e['raw']['hostname'])==host(spec['host']) and e['raw']['object']=='FILE' and
                 ns(spec['start'])-tolerance<=e['timestamp_ns']<=ns(spec['end'])+tolerance and
                 e['raw'].get('properties',{}).get('file_path','').replace('/','\\').split('\\')[-1].lower()==spec['basename'].lower()]
        ids=sorted({e['raw']['objectID'] for e in matched})
        # The narrative names a file, not a UUID. Keep multiple observed identities explicit.
        resources.append(dict(**spec,node_ids=ids,event_ids=sorted(e['id'] for e in matched),kind='documented_artifact',
                              status='observed_name_time_matches' if ids else 'unobserved',label_as_compromised_process=False))
        reference_events.update(e['id'] for e in matched)
    return dict(source=reference['source'],sha256=reference['sha256'],source_kind='user_provided_red_team_pdf',
                labels=labels,agents=agents,resources=resources,activities=reference.get('activities',[]),
                reference_event_ids=sorted(reference_events),resolution_tolerance_seconds=reference.get('resolution_tolerance_seconds',0),
                policy='只将 PDF 明确列出的代理绑定到唯一的主机、时段、PID 与 C2 actor UUID；未列出节点保持未知。资源名匹配单列，不推断失败注入目标已失陷。',
                complete_node_labels=False,complete_path_labels=False)


def evaluate_pdf(report, edges, reference):
    # Deferred import keeps the resolver independent from detection/evaluation modules.
    from tc_pruning.attack_evaluation import node_metrics
    resolved=resolve_pdf_reference(edges,reference)
    universe={n['id'] for n in report['nodes']};predicted={n['id'] for n in report['nodes'] if n['predicted_attack']}
    seeds={n['id'] for n in report['nodes'] if n['seed_node']};labels=resolved['labels']
    if not set(labels)<=universe:raise ValueError('PDF process outside inference universe')
    metrics=node_metrics(universe,predicted,labels)
    metrics['excluding_seed_nodes']=node_metrics(universe-seeds,predicted-seeds,{k:v for k,v in labels.items() if k not in seeds})
    events=set(resolved['reference_event_ids']);by_id={e['id']:e for e in edges}
    def coverage(ids):
        chosen=set(ids);return dict(reference_events=len(events),matched_events=len(chosen&events),selected_events=len(chosen),
            reference_event_retention=len(chosen&events)/len(events) if events else None,
            full_attack_path_recall=None,full_attack_path_precision=None)
    resolved.update(node_metrics=metrics,unreviewed_prediction_ids=sorted(predicted-set(labels)),
        missed_confirmed_node_ids=sorted(set(labels)-predicted),
        pruning=coverage(e['id'] for e in edges if e.get('retained')),
        activity=coverage(report.get('activity_event_ids',[])),paths=coverage(report.get('path_event_ids',[])),
        resolved_count=sum(a['status']=='resolved' for a in resolved['agents']),
        ambiguous_count=sum(a['status']=='ambiguous' for a in resolved['agents']))
    return resolved


def load_reference(path=None):
    import json
    path=Path(path or Path(__file__).resolve().parents[1]/'poi/optc-pdf-reference.json')
    ref=json.loads(path.read_text())
    pdf=path.parent.parent/ref['source']
    actual_hash=hashlib.sha256(pdf.read_bytes()).hexdigest()
    if actual_hash!=ref['sha256']:raise ValueError('PDF source hash mismatch')
    _validate_cached(str(pdf),actual_hash,hashlib.sha256(path.read_bytes()).hexdigest(),str(path))
    return ref


from functools import lru_cache
@lru_cache(maxsize=4)
def _validate_cached(pdf_path,pdf_hash,reference_hash,reference_path):
    import json
    validate_reference(pdf_path,json.loads(Path(reference_path).read_text()))
