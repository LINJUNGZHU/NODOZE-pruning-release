"""Prepare a customer eCAR JSONL ledger without truth documents, preset POIs or detectors."""
from __future__ import annotations
import argparse
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.optc import timestamp_ns
from webapp.scripts.prepare_optc import build_index


def aware_time(value):
    parsed=datetime.fromisoformat(value)
    if parsed.tzinfo is None:raise ValueError('timestamp must include a timezone offset')
    return timestamp_ns(value)


def prepare(inputs,host,start,end,dataset_id,name,output,catalog=None):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',dataset_id):raise ValueError('invalid dataset ID')
    if aware_time(start)>=aware_time(end):raise ValueError('start must precede end')
    if output.exists():raise ValueError('output already exists; use a new versioned filename')
    entries=json.loads(catalog.read_text()) if catalog and catalog.exists() else []
    if any(e['id']==dataset_id for e in entries):raise ValueError('dataset ID already exists in catalog')
    output.parent.mkdir(parents=True,exist_ok=True)
    database=output.parent/f'customer-history-{uuid.uuid4().hex}.sqlite'
    stats=dict(read_records=0,other_host_records=0,unsupported_records=0)
    seen={}
    def records():
        for path in inputs:
            opener=gzip.open if path.suffix=='.gz' else open
            with opener(path,'rt',encoding='utf-8') as stream:
                for line_number,line in enumerate(stream,1):
                    if not line.strip():continue
                    raw=json.loads(line);stats['read_records']+=1
                    if raw['hostname'].lower()!=host.lower():stats['other_host_records']+=1;continue
                    aware_time(raw['timestamp'])
                    if raw['object'] not in ('FILE','PROCESS','FLOW'):stats['unsupported_records']+=1;continue
                    for field in ('id','actorID','objectID','action'):
                        if not isinstance(raw.get(field),str) or not raw[field]:raise ValueError(f'missing or invalid {field}')
                    fingerprint=hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).digest()
                    previous=seen.setdefault(raw['id'],fingerprint)
                    if previous!=fingerprint:raise ValueError('conflicting event identity: '+raw['id'])
                    yield str(path.resolve()),line_number,raw
    try:
        edges,index_id=build_index(records(),database,host=host,start=start,end=end)
        data=dict(schema_version=2,dataset=dict(id=dataset_id,name=name,description=f'{host} · {start} – {end}',
            host=host,window_start=start,window_end=end,sources=[str(p.resolve()) for p in inputs]),
            edges=edges,history_index=dict(path=str(database.resolve()),id=index_id),
            metrics=dict(candidate_edges=len(edges),candidate_nodes=len({e[k] for e in edges for k in ('source','target')})),
            ingestion=stats,algorithm=dict(name='RASP-D',budget_ratio=.05,selection_mode='evidence',
                config=json.loads((ROOT/'configs/rasp_v1.json').read_text())))
        temporary=output.with_name(output.name+'.'+uuid.uuid4().hex+'.tmp')
        try:
            temporary.write_text(json.dumps(data,ensure_ascii=False,allow_nan=False))
            temporary.replace(output)
        finally:temporary.unlink(missing_ok=True)
        if catalog:
            entries.append(dict(id=dataset_id,name=name,description=data['dataset']['description'],
                metrics=data['metrics'],cache_path=str(output.resolve()),window_start=start,window_end=end))
            catalog.parent.mkdir(parents=True,exist_ok=True)
            temporary=catalog.with_name(catalog.name+'.'+uuid.uuid4().hex+'.tmp')
            try:temporary.write_text(json.dumps(entries,ensure_ascii=False,indent=2));temporary.replace(catalog)
            finally:temporary.unlink(missing_ok=True)
        return dict(dataset_id=dataset_id,metrics=data['metrics'],ingestion=stats,index_id=index_id)
    except BaseException:
        # A ledger already published references its index, so never unlink that index.
        if not output.exists():database.unlink(missing_ok=True)
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,nargs='+',required=True)
    for flag in ('host','start','end','dataset-id','name'):p.add_argument('--'+flag,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--catalog',type=Path)
    a=p.parse_args()
    try:print(json.dumps(prepare(a.input,a.host,a.start,a.end,a.dataset_id,a.name,a.output,a.catalog),ensure_ascii=False))
    except (ValueError,KeyError,OSError) as exc:p.error(str(exc))


if __name__=='__main__':main()
