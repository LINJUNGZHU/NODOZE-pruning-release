import json
import subprocess
import sys
from pathlib import Path
from webapp.backend.app import create_app

ROOT=Path(__file__).resolve().parents[2]


def records():
    return [dict(id=f'e{i}',actorID='proc',objectID='file',hostname='customer-host',pid=7,
        object='FILE',action='WRITE',timestamp=f'2026-09-27T10:0{i}:00+08:00',
        properties={'image_path':'customer.exe','file_path':'customer.txt'}) for i in range(3)]


def invoke(tmp_path,rows):
    source=tmp_path/'events.jsonl';source.write_text('\n'.join(json.dumps(r) for r in rows))
    out=tmp_path/'customer.json';catalog=tmp_path/'catalog.json'
    args=[sys.executable,str(ROOT/'webapp/scripts/prepare_customer.py'),'--input',str(source),'--host','customer-host',
          '--start','2026-09-27T10:01:00+08:00','--end','2026-09-27T10:03:00+08:00',
          '--dataset-id','customer','--name','Customer','--output',str(out),'--catalog',str(catalog)]
    return subprocess.run(args,capture_output=True,text=True),out,catalog


def test_customer_import_needs_no_truth_poi_or_external_alert(tmp_path):
    result,out,catalog=invoke(tmp_path,records())
    assert result.returncode==0,result.stderr
    data=json.loads(out.read_text());assert {e['id'] for e in data['edges']}=={'e1','e2'}
    assert 'truth' not in data and 'poi' not in data and 'attack' not in data
    c=create_app(out,catalog,run_store=tmp_path/'runs').test_client()
    response=c.post('/api/investigations',json=dict(dataset_id='customer',node_id='proc',anchor_event_id='e1',budget_edges=1))
    assert response.status_code==201,response.json
    assert response.json['metrics']['candidate_edges']==2
    assert response.json['history']['history_edges']==1
    again,_,_=invoke(tmp_path,records());assert again.returncode!=0


def test_conflicting_duplicate_ids_are_rejected(tmp_path):
    rows=records();rows[2]['id']='e1'
    result,out,catalog=invoke(tmp_path,rows)
    assert result.returncode!=0 and 'conflicting event identity' in result.stderr
    assert not out.exists() and not catalog.exists()


def test_timezone_missing_is_rejected(tmp_path):
    rows=records();rows[0]['timestamp']='2026-09-27T10:00:00'
    result,out,_=invoke(tmp_path,rows)
    assert result.returncode!=0 and 'timezone offset' in result.stderr and not out.exists()
