"""Export exact-window projections of TAPAS's static node list for evaluation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))


def digest(ids):return hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest()


def build(path,cases):
    content=path.read_bytes();ids=set(content.decode().splitlines())
    if not ids:raise ValueError('empty TAPAS reference')
    for value in ids:uuid.UUID(value)
    windows={}
    for data in cases:
        nodes={n['id']:n['type'] for n in data['nodes']};events={e['id'] for e in data['edges']}
        windows[digest(events)]=dict(dataset_id=data['dataset']['id'],event_count=len(events),
            node_ids_sha256=digest(nodes),positive_node_ids=sorted(ids & nodes.keys()),
            matched_types={t:sum(n in ids and kind==t for n,kind in nodes.items()) for t in ('process','file','flow')})
    return dict(source_path=str(path),source_sha256=hashlib.sha256(content).hexdigest(),source_node_count=len(ids),
                granularity='static node membership; TAPAS optc.py decompose assigns a graph positive when any listed node is present',
                limitation='No timestamps or reviewed negative labels in this file. Process projection uses closed-world membership solely as a secondary benchmark; not time-local confirmed malice.',windows=windows)


def main():
    p=argparse.ArgumentParser();p.add_argument('--groundtruth',type=Path,default=Path('/root/TAPAS-artifact/groundtruth/optc.txt'))
    p.add_argument('--output',type=Path,default=ROOT/'poi/tapas-optc-slices.json');a=p.parse_args()
    catalog=json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text())
    cases=[json.loads(Path(c['cache_path']).read_text()) for c in catalog]
    result=build(a.groundtruth,cases);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v['matched_types'] for k,v in result['windows'].items()}))
if __name__=='__main__':main()
