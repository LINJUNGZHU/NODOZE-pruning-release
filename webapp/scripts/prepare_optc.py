"""Index all supplied pre-POI history and build an explicit manual-POI investigation."""
from __future__ import annotations
import argparse
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import numpy as np
from pypdf import PdfReader
from tc_pruning.optc import parse_event, timestamp_ns
from tc_pruning.optc_investigation import signature_key, validate_presets, rescore

START = '2019-09-23T11:20:00-04:00'
END = '2019-09-23T11:30:00-04:00'


def build_index(records, database, host='SysClient0201.systemia.com', start=START, end=END):
    """Unsorted multi-file input is deduplicated; history has no fixed lower bound."""
    start_ns, end_ns = [timestamp_ns(t) for t in (start,end)]
    index_id = uuid.uuid4().hex
    candidates = {}
    with sqlite3.connect(database) as conn:
        conn.execute('CREATE TABLE events (event_id TEXT PRIMARY KEY, timestamp_ns INTEGER NOT NULL, signature TEXT NOT NULL)')
        conn.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        conn.execute('INSERT INTO metadata VALUES (?, ?)', ('index_id',index_id))
        batch = []
        for source,line_number,raw in records:
            if raw['hostname'].lower() != host.lower(): continue
            ts = timestamp_ns(raw['timestamp'])
            if ts >= end_ns: continue
            e = parse_event(raw)
            if e is None: continue
            batch.append((e['id'], e['timestamp_ns'], signature_key(e)))
            if start_ns <= ts:
                e.update(source_file=source, source_line=line_number)
                candidates.setdefault(e['id'],e)
            if len(batch) >= 10000:
                conn.executemany('INSERT OR IGNORE INTO events VALUES (?,?,?)',batch)
                batch.clear()
        conn.executemany('INSERT OR IGNORE INTO events VALUES (?,?,?)',batch)
        conn.execute('CREATE INDEX events_timestamp ON events(timestamp_ns)')
        count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    print(f'Indexed {count:,} historical/candidate events', flush=True)
    edges = sorted(candidates.values(),key=lambda e:(e['timestamp_ns'],e['id']))
    if not edges: raise ValueError('No candidate events in configured window')
    return edges,index_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,nargs='+',default=sorted(Path('/root/TAPAS-artifact/data/optc/logs').glob('AIA-201-225*.json.gz')))
    parser.add_argument('--truth',type=Path,default=ROOT/'OpTCRedTeamGroundTruth.pdf')
    parser.add_argument('--poi-config',type=Path,default=ROOT/'poi/optc-day1-groundtruth-pois.json')
    parser.add_argument('--poi',help='Explicit event ID; defaults to the ground-truth manifest default')
    parser.add_argument('--output',type=Path,default=ROOT/'webapp/runtime/optc-demo.json')
    parser.add_argument('--budget',type=float,default=.2)
    parser.add_argument('--selection-mode',choices=['evidence','context'],default='context')
    args = parser.parse_args()
    if not args.input: parser.error('No source files found; specify --input')
    manifest = json.loads(args.poi_config.read_text())
    pdf_text = '\n'.join(p.extract_text() for p in PdfReader(args.truth).pages)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    # Versioned sidecar prevents readers from mixing a new index with an old cache.
    database = args.output.parent/f'optc-history-{uuid.uuid4().hex}.sqlite'
    def records():
        for path in args.input:
            print(f'Reading {path}',flush=True)
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path,'rt',encoding='utf-8') as stream:
                for n,line in enumerate(stream,1):
                    if manifest['host'].lower() in line.lower():
                        yield str(path.resolve()),n,json.loads(line)
    try:
        edges,index_id = build_index(records(),database,host=manifest['host'])
        validate_presets(edges,manifest,pdf_text)
        data = dict(schema_version=2,dataset=dict(id='optc-0201',name='OPTC · SysClient0201',
                     description='2019-09-23 11:20–11:30 (UTC−04:00)',
                     source='; '.join(str(p.resolve()) for p in args.input),sources=[str(p.resolve()) for p in args.input]),
                    edges=edges,history_index=dict(path=str(database.resolve()),id=index_id),
                    display_event_ids=[edges[i]['id'] for i in np.linspace(0,len(edges)-1,min(80,len(edges)),dtype=int)],
                    poi_presets=manifest['pois'],
                    truth=dict(source=args.truth.name,sha256=hashlib.sha256(args.truth.read_bytes()).hexdigest()),
                    algorithm=dict(name='RASP-D',budget_ratio=args.budget,quality_weight=.05,
                                   config=json.loads((ROOT/'configs/rasp_v1.json').read_text())))
        rescore(data,args.poi or manifest['default_event_id'],args.budget,args.selection_mode)
        tmp = args.output.with_suffix('.tmp')
        tmp.write_text(json.dumps(data,ensure_ascii=False,allow_nan=False),encoding='utf-8')
        tmp.replace(args.output)
        print(json.dumps(dict(metrics=data['metrics'],truth=data['truth'],poi=data['poi'],history=data['history']),ensure_ascii=False,indent=2))
    except BaseException:
        database.unlink(missing_ok=True)
        raise

if __name__=='__main__': main()
