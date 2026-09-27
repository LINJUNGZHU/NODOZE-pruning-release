import copy
import csv
import hashlib
import io
import json
import numpy as np
import pytest
from webapp.tests.test_rcvp_web import optc_candidate
from webapp.backend.app import create_app
from tc_pruning.optc_investigation import rescore
from tc_pruning.rasp import propagate


def test_node_focus_changes_propagation_and_rejects_unrelated_node():
    config=dict(restart=.15,iterations=100,tolerance=1e-10,rarity_floor=.1)
    args=(np.array([0,1,0,2]),np.array([1,2,3,4]),np.zeros(4),np.ones(4),np.array([True,False,False,False]),np.ones(5),config)
    left,_=propagate(*args,focal_node=0)
    right,_=propagate(*args,focal_node=1)
    assert not np.allclose(left[1:],right[1:])
    assert left[0]==right[0]==1
    with pytest.raises(ValueError):propagate(*args,focal_node=4)


def test_pruning_only_never_reads_truth_or_runs_detector(optc_candidate,monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError('product reached detector/truth')
    monkeypatch.setattr('tc_pruning.optc_investigation.reference_evidence',forbidden)
    monkeypatch.setattr('tc_pruning.optc_investigation.infer_attack',forbidden)
    candidate=copy.deepcopy(optc_candidate)
    candidate.pop('truth');candidate.pop('poi_presets')
    result=rescore(candidate,'seed',.6,'evidence',focal_node_id='process-a',pruning_only=True)
    assert 'attack' not in result and 'truth' not in result
    assert result['decision_certificate']['poi_preserved']
    assert result['decision_certificate']['complete_witnesses']
    assert result['metrics']['retained_edges']<=3
    assert result['poi']['node_id']=='process-a'


@pytest.fixture
def product(tmp_path,optc_candidate):
    cache=tmp_path/'candidate.json'
    cache.write_text(json.dumps(optc_candidate))
    app=create_app(cache,run_store=tmp_path/'runs')
    app.testing=True
    return app,cache,tmp_path/'runs'


def make_run(client,budget=3,node='process-a',anchor='seed'):
    return client.post('/api/investigations',json=dict(dataset_id='optc-0201',node_id=node,anchor_event_id=anchor,budget_edges=budget))


def test_runs_are_independent_persistent_and_export_complete(product):
    app,cache,store=product;client=app.test_client();before=hashlib.sha256(cache.read_bytes()).hexdigest()
    a=make_run(client).get_json();b=make_run(client,2).get_json()
    assert 'run' in a,a
    assert a['run']['id']!=b['run']['id']
    assert a['metrics']['budget_edges']==3 and b['metrics']['budget_edges']==2
    assert hashlib.sha256(cache.read_bytes()).hexdigest()==before
    reopened=create_app(cache,run_store=store).test_client().get('/api/investigations/'+a['run']['id']).get_json()
    assert reopened['run']==a['run']
    exported=client.get('/api/investigations/'+a['run']['id']+'/export').get_json()
    assert len(exported['events'])==a['metrics']['retained_edges']
    assert 'seed' in {e['id'] for e in exported['events']}
    assert exported['run']['candidate_sha256']
    rows=list(csv.DictReader(io.StringIO(client.get('/api/investigations/'+a['run']['id']+'/export.csv').get_data(as_text=True))))
    assert len(rows)==len(exported['events'])


def test_nodes_events_and_invalid_inputs(product):
    app,_,_=product;c=app.test_client()
    nodes=c.get('/api/datasets/optc-0201/nodes?q=process-a').get_json()
    assert nodes['nodes'][0]['id']=='process-a'
    assert nodes['nodes'][0]['event_count']==4
    events=c.get('/api/datasets/optc-0201/nodes/process-a/events').get_json()
    assert {e['id'] for e in events['events']}=={'before','seed','later','after'}
    assert make_run(c,node='object-before').status_code==400
    for invalid in [0,True,2.5,6,'3',None]:assert make_run(c,invalid).status_code==400
    assert make_run(c,anchor='history').status_code==400
    assert c.get('/api/investigations/../../etc/passwd').status_code==404


def test_access_control_and_cross_origin_write_protection(tmp_path,optc_candidate,monkeypatch):
    cache=tmp_path/'cache.json';cache.write_text(json.dumps(optc_candidate))
    token='a'*40
    monkeypatch.setenv('NODOZE_ACCESS_TOKEN',token)
    monkeypatch.setenv('NODOZE_SESSION_SECRET','s'*40)
    c=create_app(cache,run_store=tmp_path/'runs').test_client()
    assert c.get('/api/datasets').status_code==401
    assert c.post('/api/session',json={'token':'wrong'}).status_code==401
    assert c.post('/api/session',json={'token':token}).status_code==200
    assert c.get('/api/datasets').status_code==200
    assert c.post('/api/investigations',json={},headers={'Origin':'https://evil.example'}).status_code==403
    assert make_run(c).status_code==201
    assert c.delete('/api/session').status_code==200
    assert c.get('/api/investigations').status_code==401


def test_rejects_duplicate_event_identity_without_saving(product):
    app,cache,_=product
    data=json.loads(cache.read_text());data['edges'].append(copy.deepcopy(data['edges'][0]));cache.write_text(json.dumps(data))
    c=app.test_client()
    assert make_run(c).status_code==400
    assert c.get('/api/investigations').json['runs']==[]


def test_csv_neutralizes_log_formulas(product):
    app,cache,_=product;data=json.loads(cache.read_text())
    for edge in data['edges']:edge['source_label']='=HYPERLINK("bad")'
    cache.write_text(json.dumps(data));c=app.test_client();r=make_run(c).json
    rows=list(csv.DictReader(io.StringIO(c.get('/api/investigations/'+r['run']['id']+'/export.csv').get_data(as_text=True).lstrip('\ufeff'))))
    assert rows and all(row['source_label'].startswith("'=") for row in rows)


def test_node_counts_self_loop_once(product):
    app,cache,_=product;data=json.loads(cache.read_text());edge=data['edges'][0]
    edge['target']=edge['source'];edge['target_label']=edge['source_label'];edge['target_type']=edge['source_type']
    cache.write_text(json.dumps(data));c=app.test_client()
    assert c.get('/api/datasets/optc-0201/nodes?q=process-a').json['nodes'][0]['event_count']==4


def test_history_paginates_product_runs_without_research_hiding_them(product):
    app,_,store_path=product;c=app.test_client()
    from webapp.backend.investigations import RunStore
    store=RunStore(store_path)
    data=make_run(c).json
    for i in range(35):
        store.save(dict(dataset={'id':'demo'}),dict(algorithm_version='research'))
    for i in range(31):
        store.save(dict(dataset={'id':'demo'}),dict(algorithm_version='node_focus_rasp_v1'))
    first=c.get('/api/investigations?page=0').json
    second=c.get('/api/investigations?page=1').json
    assert first['total']==32 and len(first['runs'])==30
    assert len(second['runs'])==2
    assert data['run']['id'] in {r['id'] for r in second['runs']}
    assert all(r['algorithm_version']=='node_focus_rasp_v1' for r in first['runs'])
    assert c.get('/api/investigations?page=-1').status_code==400


def test_frozen_run_still_serves_when_live_cache_removed(product):
    app,cache,store=product;c=app.test_client();r=make_run(c).json
    cache.unlink()
    client=create_app(cache,run_store=store).test_client()
    assert client.get('/api/investigations/'+r['run']['id']).status_code==200
    assert client.get('/api/investigations/'+r['run']['id']+'/events').status_code==200
    assert client.get('/api/investigations/'+r['run']['id']+'/export').status_code==200


def test_malformed_session_body_and_missing_data_return_structured_errors(product):
    app,_,_=product;c=app.test_client()
    assert c.post('/api/session',json=['bad']).status_code==400
    assert c.get('/api/investigations/not-a-run').is_json
    assert c.get('/api/investigations?page=oops').status_code==400


def test_product_export_replays_offline_without_source_or_truth(product):
    from webapp.scripts.verify_decision_audit import verify
    app,cache,_=product;c=app.test_client();run=make_run(c).json
    exported=c.get('/api/investigations/'+run['run']['id']+'/export').json
    cache.unlink()
    result=verify(exported)
    assert result['budget_valid'] and result['complete_witnesses'] and result['greedy_ranking_replayed']
