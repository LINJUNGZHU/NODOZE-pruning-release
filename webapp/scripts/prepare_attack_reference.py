"""Extract a small, pinned public-label benchmark for the exact candidate slice.

Downloads remain in ignored runtime/. Only public-domain IDs and attribution
are exported; no third-party implementation or raw logs are redistributed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.attack_inference import process_metadata

COMMIT='64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa'


def ids_hash(ids):
    return hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest()


def build(cache, archives):
    edges=cache['edges'];by_id={e['id']:e for e in edges};nodes=process_metadata(edges)
    with zipfile.ZipFile(archives/'tasks.zip') as z:
        tasks=json.load(z.open('tasks.json'))
    positive,negative,refs=set(),set(),[]
    hosts={e['raw']['hostname'].lower() for e in edges}
    for t in tasks:
        labels=set(t.get('labels') or [])
        if t.get('hostname','').lower() not in hosts or not t.get('event_id') or t.get('object_id') not in nodes: continue
        if 'process' not in labels or 'invalid' in labels: continue
        if 'malicious' in labels: positive.add(t['object_id'])
        if 'benign' in labels: negative.add(t['object_id'])
        refs.append({k:t.get(k) for k in ('object_id','event_id','pid','labels')})
    conflict=positive & negative
    labels={n:None if n in conflict else n in positive for n in sorted(nodes)}
    malicious_events=set();mismatch=[];count=0
    with zipfile.ZipFile(archives/'malicious.zip') as z:
        with z.open('malicious.json') as f:
            for line in f:
                count+=1
                # Pre-filter only the host to keep the 1.5 GB stream inexpensive.
                if not any(host.encode() in line.lower() for host in hosts): continue
                raw=json.loads(line)
                if raw['id'] not in by_id: continue
                local=by_id[raw['id']]['raw']
                if any(raw[k]!=local[k] for k in ('id','actorID','objectID','timestamp','hostname','object','action')):
                    mismatch.append(raw['id']);continue
                malicious_events.add(raw['id'])
    if mismatch: raise ValueError(f'public labels disagree with local event identity: {mismatch[:5]}')
    return dict(schema_version=1,repository='https://github.com/AT03380/optc-labels',commit=COMMIT,
                paper_doi='10.1109/CIoT63799.2024.10757066',
                label_definition_url=f'https://github.com/AT03380/optc-labels/blob/{COMMIT}/supplementary/labels.md',
                archive_sha256={name:hashlib.sha256((archives/name).read_bytes()).hexdigest() for name in ('tasks.zip','malicious.zip')},
                scope=dict(event_ids_sha256=ids_hash(by_id),process_ids_sha256=ids_hash(nodes),
                           event_count=len(edges),process_count=len(nodes),hosts=sorted(hosts),
                           start=edges[0]['timestamp'],end=edges[-1]['timestamp']),
                node_labels=labels,process_tasks=refs,conflicting_process_ids=sorted(conflict),
                malicious_event_ids=sorted(malicious_events),archive_events_scanned=count,
                policy='Published closed-world benchmark: process-granularity malicious tasks are positive; remaining processes negative by the authors complement convention. Invalid tasks ignored; conflicting labels unknown. Do not equate this convention to independently reviewed benign truth.',
                license='Labels and reproduced OpTC data released into the public domain by the authors; implementation not copied.',
                errata_url=f'https://github.com/AT03380/optc-labels/blob/{COMMIT}/supplementary/errata.md')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,default=ROOT/'webapp/runtime/optc-demo.json')
    p.add_argument('--archives',type=Path,default=ROOT/'webapp/runtime/research/optc-labels')
    p.add_argument('--output',type=Path,default=ROOT/'poi/optc-0201-public-labels.json')
    a=p.parse_args();report=build(json.loads(a.cache.read_text()),a.archives)
    a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(positive=sum(v is True for v in report['node_labels'].values()),
                         negative=sum(v is False for v in report['node_labels'].values()),
                         malicious_events=len(report['malicious_event_ids']),scope=report['scope']),ensure_ascii=False))
