"""Build a deduplicated raw-event corpus for real examples and temporal training."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.optc import parse_event,timestamp_ns
from tc_pruning.optc_investigation import signature_key


def build(inputs,database,host,end):
    cutoff=timestamp_ns(end);index_id=uuid.uuid4().hex
    if database.exists():raise ValueError('Output database already exists; use another output or its saved manifest')
    with sqlite3.connect(database) as c:
        c.execute('CREATE TABLE events(event_id TEXT PRIMARY KEY,timestamp_ns INTEGER NOT NULL,signature TEXT NOT NULL)')
        c.execute('CREATE TABLE records(event_id TEXT PRIMARY KEY,payload TEXT NOT NULL,source_file TEXT,source_line INTEGER)')
        c.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        c.execute('INSERT INTO metadata VALUES (?,?)',('index_id',index_id))
        batch=[];raws=[]
        for path in inputs:
            print('Reading',path,flush=True)
            with gzip.open(path,'rb') as f:
                for lineno,line in enumerate(f,1):
                    if host.lower().encode() not in line.lower():continue
                    raw=json.loads(line)
                    if raw['hostname'].lower()!=host.lower() or timestamp_ns(raw['timestamp'])>=cutoff:continue
                    e=parse_event(raw)
                    if e is None:continue
                    batch.append((e['id'],e['timestamp_ns'],signature_key(e)))
                    raws.append((e['id'],line.decode().strip(),str(path),lineno))
                    if len(batch)>=10000:
                        c.executemany('INSERT OR IGNORE INTO events VALUES (?,?,?)',batch)
                        c.executemany('INSERT OR IGNORE INTO records VALUES (?,?,?,?)',raws)
                        batch.clear();raws.clear();c.commit()
            print('Indexed so far',c.execute('SELECT COUNT(*) FROM events').fetchone()[0],flush=True)
        c.executemany('INSERT OR IGNORE INTO events VALUES (?,?,?)',batch)
        c.executemany('INSERT OR IGNORE INTO records VALUES (?,?,?,?)',raws)
        c.execute('CREATE INDEX events_time ON events(timestamp_ns)')
        count,start,last=c.execute('SELECT COUNT(*),MIN(timestamp_ns),MAX(timestamp_ns) FROM events').fetchone()
        digest=hashlib.sha256()
        for row in c.execute('SELECT event_id FROM events ORDER BY event_id'):digest.update((row[0]+'\n').encode())
    return dict(path=str(database.resolve()),id=index_id,host=host,end=end,events=count,
                start_ns=start,last_ns=last,event_ids_sha256=digest.hexdigest(),
                sources=[dict(path=str(p.resolve()),bytes=p.stat().st_size) for p in inputs])


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,nargs='+',default=sorted(Path('/root/TAPAS-artifact/data/optc/logs').glob('AIA-201-225*.json.gz')))
    p.add_argument('--output',type=Path,default=ROOT/'webapp/runtime/optc-corpus.sqlite')
    p.add_argument('--host',default='SysClient0201.systemia.com');p.add_argument('--end',default='2019-09-23T12:20:00-04:00')
    a=p.parse_args();result=build(a.input,a.output,a.host,a.end)
    a.output.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
