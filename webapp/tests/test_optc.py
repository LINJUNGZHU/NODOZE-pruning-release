from datetime import datetime
import copy
import json
from pathlib import Path
import numpy as np
import pytest
from tc_pruning.optc import parse_event, signature
from tc_pruning.optc_investigation import pre_poi_counts, rescore, signature_key, validate_presets
from webapp.scripts.prepare_optc import build_index
from webapp.backend.app import create_app

ROOT=Path(__file__).resolve().parents[2]
PDF='Sysclient0201 runme.bat 132.197.158.98 5452 2952'


def record(id, minute, obj='FILE', action='WRITE', props=None):
    return dict(id=id,actorID='process-a',objectID='object-'+id,hostname='SysClient0201.systemia.com',pid=5452,
                object=obj,action=action,timestamp=f'2019-09-23T11:{minute}:00-04:00',
                properties=props or {'image_path':'cmd.exe','file_path':'normal.txt'})


@pytest.fixture
def dataset(tmp_path):
    rows=[record('early','01'),record('history','15'),record('before','22'),record('seed','23'),
          record('equal','23'),record('later','24'),record('seed2','25'),record('after','26')]
    other=record('foreign','10');other['hostname']='SysClient0202.systemia.com'
    # Unsorted, duplicate and multi-host input, including candidate events before POI.
    rows=list(reversed(rows))+[other,rows[0]]
    db=tmp_path/'history.sqlite'
    edges,index_id=build_index((('fixture',i,r) for i,r in enumerate(rows,1)),db)
    data=dict(schema_version=2,edges=edges,history_index=dict(path=str(db),id=index_id),
              dataset=dict(id='optc-0201',name='test',description='test',sources=['fixture']),
              poi_presets=[dict(event_id='seed',label='fixture POI',evidence='fixture evidence')],
              truth=dict(source='fixture'),display_event_ids=[e['id'] for e in edges],
              algorithm=dict(name='RASP-D',budget_ratio=.5,config=json.loads((ROOT/'configs/rasp_v1.json').read_text())))
    return data


def test_information_flow_and_timezone():
    raw=record('read','21',action='READ');e=parse_event(raw)
    assert (e['source'],e['target'])==('object-read','process-a')
    assert e['timestamp_ns']==int(datetime.fromisoformat(raw['timestamp']).timestamp()*1e9)
    raw=record('net','21','FLOW','START',{'direction':'inbound','src_ip':'1','dest_ip':'2'})
    assert parse_event(raw)['target']=='process-a'
    assert parse_event(record('thread','21','THREAD','CREATE')) is None
    child=parse_event(record('child','21','PROCESS','CREATE',{'image_path':'child.exe','parent_image_path':'parent.exe'}))
    assert child['source_label']=='parent.exe' and child['target_label']=='child.exe'


def test_flow_frequency_ignores_ephemeral_client_port():
    raw=record('net','21','FLOW','START',{'image_path':'powershell.exe','direction':'outbound','src_port':'49152','dest_port':'80','dest_ip':'1.2.3.4'})
    a=signature(parse_event(raw));raw['properties']['src_port']='49153'
    assert a==signature(parse_event(raw))
    raw['properties']['dest_port']='443'
    assert a!=signature(parse_event(raw))


def test_strict_cutoff_counts_all_history_and_excludes_same_time(dataset):
    data=rescore(dataset,'seed')
    assert data['history']['history_edges']==3  # 11:01, 11:15, 11:22; not 11:23
    assert data['history']['last_event_ns']<data['history']['cutoff_ns']
    assert all(e['historical_count']==3 for e in data['edges'])
    assert all(e['historical_frequency']==1 for e in data['edges'])
    assert data['truth']['seed_event_id']=='seed'
    assert len(data['edges'])==6
    assert data['metrics']['retained_edges']<=3
    assert all(np.isfinite(e['score']) for e in data['edges'])
    assert sum(e['poi'] for e in data['edges'])==1
    data=rescore(data,'seed2')
    assert data['history']['history_edges']==6
    assert all(e['historical_count']==6 for e in data['edges'])
    assert data['poi']['groundtruth_backed'] is False


def test_future_events_do_not_leak_into_frequency(dataset):
    data=rescore(dataset,'seed')
    import sqlite3
    e=data['edges'][-1]
    with sqlite3.connect(data['history_index']['path']) as conn:
        conn.executemany('INSERT INTO events VALUES (?,?,?)',[(f'future{i}',e['timestamp_ns'],signature_key(e)) for i in range(100)])
    counts,history=pre_poi_counts(data['history_index']['path'],data['history']['cutoff_ns'],data['history_index']['id'])
    assert history['history_edges']==3
    assert counts[signature_key(e)]==3


@pytest.mark.parametrize('budget',[0,2,True,'0.2',float('nan')])
def test_invalid_budget(dataset,budget):
    with pytest.raises(ValueError,match='budget'):rescore(dataset,'seed',budget)


def test_index_mismatch_and_unknown_poi(dataset):
    with pytest.raises(ValueError,match='POI event ID'):rescore(dataset,'missing')
    dataset['history_index']['id']='wrong'
    with pytest.raises(ValueError,match='do not match'):rescore(dataset,'seed')


def test_preset_validation_requires_uuid_and_matching_evidence():
    raw=record('seed','23','FLOW','START',{'dest_ip':'132.197.158.98','dest_port':'80'})
    preset=dict(event_id='seed',timestamp=raw['timestamp'],object='FLOW',action='START',pid=5452,dest_ip='132.197.158.98',dest_port='80')
    manifest=dict(host=raw['hostname'],pois=[preset])
    validate_presets([parse_event(raw)],manifest,PDF)
    preset['pid']=2952
    with pytest.raises(ValueError,match='evidence mismatch'):validate_presets([parse_event(raw)],manifest,PDF)
    with pytest.raises(ValueError,match='PDF missing'):validate_presets([],manifest,'wrong')


def test_api_recomputes_and_persists_manual_selection(dataset,tmp_path):
    cache=tmp_path/'cache.json';cache.write_text(json.dumps(rescore(dataset,'seed')))
    client=create_app(cache).test_client()
    response=client.post('/api/datasets/optc-0201/prune',json=dict(poi_event_id='seed2'))
    assert response.status_code==200
    assert response.json['history']['history_edges']==6
    assert response.json['poi']['event_id']=='seed2'
    assert json.loads(cache.read_text())['poi']['event_id']=='seed2'
    saved=cache.read_bytes()
    for body in [None,{},[],dict(poi_event_id='missing'),dict(poi_event_id='seed',budget_ratio=0)]:
        assert client.post('/api/datasets/optc-0201/prune',json=body).status_code==400
        assert cache.read_bytes()==saved
    assert client.post('/api/datasets/unknown/prune',json=dict(poi_event_id='seed')).status_code==404
    assert client.post('/api/datasets/optc-0201/prune',json=dict(poi_event_id='seed')).status_code==200


def test_both_mode_audits_can_be_downloaded_and_replayed(dataset,tmp_path):
    from webapp.scripts.verify_decision_audit import verify
    cache=tmp_path/'cache.json'
    for mode in ('evidence','context'):
        data=rescore(copy.deepcopy(dataset),'seed',selection_mode=mode)
        cache.write_text(json.dumps(data))
        client=create_app(cache).test_client()
        response=client.get('/api/datasets/optc-0201/decision-audit')
        assert response.status_code==200
        assert verify(response.json)['greedy_ranking_replayed']
        assert response.json['decision_contract']['scalar_score_threshold'] is None
        assert response.json['decision_contract']['statistical_fpr_guarantee'] is False
        assert client.get('/api/datasets/missing/decision-audit').status_code==404


def test_reference_labels_do_not_influence_decisions(dataset,monkeypatch):
    import tc_pruning.optc_investigation as pipeline
    a=rescore(copy.deepcopy(dataset),'seed',selection_mode='evidence')
    monkeypatch.setattr(pipeline,'reference_evidence',lambda e:['fake label on every edge'])
    b=rescore(copy.deepcopy(dataset),'seed',selection_mode='evidence')
    assert [(e['score'],e['retained']) for e in a['edges']]==[(e['score'],e['retained']) for e in b['edges']]
    assert a['decision_trace']==b['decision_trace']
    assert {k:v for k,v in a['attack'].items() if k not in ('runtime_seconds','evaluation')}=={k:v for k,v in b['attack'].items() if k not in ('runtime_seconds','evaluation')}


def test_attack_api_report_and_threshold_persistence(dataset,tmp_path):
    from webapp.scripts.verify_attack_report import verify
    cache=tmp_path/'cache.json';cache.write_text(json.dumps(rescore(dataset,'seed')))
    client=create_app(cache).test_client()
    response=client.get('/api/datasets/optc-0201/attack-report')
    assert response.status_code==200 and 'attachment' in response.headers['Content-Disposition']
    assert verify(response.json)['strict_temporal_paths_verified']
    assert client.get('/api/datasets/missing/attack-report').status_code==404
    r=client.post('/api/datasets/optc-0201/prune',json=dict(poi_event_id='seed',attack_quantile=.95))
    assert r.status_code==200 and r.json['attack']['config']['anomaly_quantile']==.95
    previous=cache.read_bytes()
    r=client.post('/api/datasets/optc-0201/prune',json=dict(poi_event_id='seed',attack_quantile=1))
    assert r.status_code==400 and cache.read_bytes()==previous


def test_attack_predictions_do_not_depend_on_pruning_budget_or_mode(dataset):
    reports=[rescore(copy.deepcopy(dataset),'seed',b,m)['attack'] for b,m in [(1.,'context'),(.01,'evidence')]]
    strip=lambda a:{k:v for k,v in a.items() if k!='runtime_seconds'}
    assert strip(reports[0])==strip(reports[1])
