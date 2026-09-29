import sqlite3
from pathlib import Path
import pytest


def module():
    from scripts import chain_workbench_inputs
    return chain_workbench_inputs


def row(event, a, b, timestamp, poi=False):
    return dict(event_id=event,src=a,dst=b,relation='EVENT_WRITE',timestamp_ns=timestamp,
                host='h',src_type='process',dst_type='file',src_semantic='process:service',
                dst_semantic='file:'+b,is_declared_poi=poi)


def source(tmp_path, rows):
    from tc_pruning.store import ProvenanceStore
    from tc_pruning.models import NodeRecord, EdgeRecord
    p=tmp_path/'input.db'
    with ProvenanceStore(p) as store:
        nodes={}
        for r in rows:
            for side in ('src','dst'):
                nodes[r[side]]=NodeRecord(r[side],r[side+'_type'],r[side+'_semantic'],'h',r[side+'_semantic'])
        store.ingest(list(nodes.values())+[EdgeRecord(r['event_id'],r['src'],r['dst'],r['relation'],r['timestamp_ns'],'h') for r in rows])
    return p


def test_extends_only_active_cohort_boundary_and_preserves_base(tmp_path):
    ns=10**9
    rows=[row('seed','p','a',40*ns,True),row('active','p','b',99*ns),row('continuation','p','c',115*ns),row('later','p','d',151*ns)]
    db=source(tmp_path,rows)
    before=db.read_bytes()
    kept,diag=module().expand_candidate_window(db,rows[:2],start_ns=0,end_ns=100*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=40,boundary_seconds=10,max_events=20)
    assert {r['event_id'] for r in kept}=={'seed','active','continuation'}
    assert diag['final_start_ns']=='0'
    assert diag['final_end_ns']==str(140*ns)
    assert diag['added_events']==1
    assert diag['ground_truth_used'] is False
    assert db.read_bytes()==before
    assert any(x['reason']=='extension_limit' for x in diag['stopping_reasons'])


def test_unrelated_activity_does_not_expand_and_inactive_boundary_stops(tmp_path):
    ns=10**9
    rows=[row('seed','p','a',40*ns,True),row('unrelated','q','b',99*ns),row('outside','p','c',115*ns)]
    db=source(tmp_path,rows)
    kept,diag=module().expand_candidate_window(db,rows[:2],start_ns=0,end_ns=100*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=40,boundary_seconds=10,max_events=20)
    assert len(kept)==2 and diag['added_events']==0
    assert diag['rounds']==[]


def test_cap_is_explicit_without_losing_base_or_poi(tmp_path):
    ns=10**9
    rows=[row('seed','p','a',40*ns,True),row('active','p','b',99*ns)]+[row('extra'+str(k),'p','x'+str(k),(101+k)*ns) for k in range(10)]
    db=source(tmp_path,rows)
    kept,diag=module().expand_candidate_window(db,rows[:2],start_ns=0,end_ns=100*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=40,boundary_seconds=10,max_events=4)
    assert len(kept)==4
    assert {'seed','active'} <= {r['event_id'] for r in kept}
    assert diag['incomplete'] and diag['truncation_reason']=='candidate_event_limit'
    assert next(r for r in kept if r['event_id']=='seed')['is_declared_poi']


def test_process_child_extends_cohort_without_labels(tmp_path):
    ns=10**9
    seed=row('seed','p','a',40*ns,True)
    child=dict(row('fork','p','child',50*ns),dst_type='process',dst_semantic='process:child',relation='EVENT_FORK')
    rows=[seed,child,row('active','child','b',99*ns),row('outside','child','c',110*ns)]
    db=source(tmp_path,rows)
    base=[dict(r,attack=False,ground_truth=['unrelated']) for r in rows[:3]]
    kept,diag=module().expand_candidate_window(db,base,start_ns=0,end_ns=100*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=20,boundary_seconds=10,max_events=20)
    assert len(kept)==4 and diag['cohort_process_count']==2


def test_equal_boundary_events_included_once_and_semantics_hydrated(tmp_path):
    ns=10**9
    rows=[row('seed','p','a',40*ns,True),row('active','p','b',100*ns),row('at-next','p','c',120*ns)]
    db=source(tmp_path,rows)
    kept,diag=module().expand_candidate_window(db,rows[:2],start_ns=0,end_ns=100*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=20,boundary_seconds=10,max_events=20)
    assert len(kept)==3
    assert kept[-1]['dst_semantic']=='file:c'
    assert kept[-1]['timestamp_ns']==120*ns


@pytest.mark.parametrize('updates',[
    {'start_ns':101*10**9},{'max_events':1},{'step_seconds':0},
    {'max_extension_seconds':-1},{'boundary_seconds':float('nan')},{'poi_event_ids':['missing']},
])
def test_invalid_configuration_rejected(tmp_path,updates):
    rows=[row('seed','p','a',40*10**9,True),row('active','p','b',99*10**9)]
    db=source(tmp_path,rows)
    kwargs=dict(start_ns=0,end_ns=100*10**9,poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=40,boundary_seconds=10,max_events=20)
    kwargs.update(updates)
    with pytest.raises(ValueError):module().expand_candidate_window(db,rows,**kwargs)


@pytest.mark.parametrize('discovery_direction',['backward','forward'])
def test_cohort_growth_reactivates_previously_inactive_opposite_boundary(tmp_path,discovery_direction):
    ns=10**9
    seed=row('seed','p','seed-file',150*ns,True)
    if discovery_direction=='backward':
        base=[seed,row('left','p','left-file',100*ns),row('right','q','right-file',199*ns)]
        link=dict(row('new-link','q','p',95*ns),dst_type='process',dst_semantic='process:p',relation='EVENT_FORK')
        continuation=row('continuation','q','outside',205*ns)
    else:
        base=[seed,row('left','q','left-file',100*ns),row('right','p','right-file',199*ns)]
        link=dict(row('new-link','p','q',205*ns),dst_type='process',dst_semantic='process:q',relation='EVENT_FORK')
        continuation=row('continuation','q','outside',95*ns)
    db=source(tmp_path,base+[link,continuation])
    kept,diag=module().expand_candidate_window(db,base,start_ns=100*ns,end_ns=200*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=20,boundary_seconds=10,max_events=20)
    assert {r['event_id'] for r in kept}=={r['event_id'] for r in base+[link,continuation]}
    assert diag['final_start_ns']==str(80*ns)
    assert diag['final_end_ns']==str(220*ns)
    assert diag['cohort_process_count']==2
    assert not diag['incomplete']
    assert not any(r['reason']=='no_active_cohort_at_boundary' for r in diag['stopping_reasons'])


def test_truncated_interval_is_not_claimed_complete(tmp_path):
    ns=10**9
    base=[row('seed','p','a',150*ns,True),row('active','p','b',199*ns)]
    rows=base+[row('extra-'+str(k),'p','x'+str(k),(201+k)*ns) for k in range(4)]
    db=source(tmp_path,rows)
    kept,diag=module().expand_candidate_window(db,base,start_ns=100*ns,end_ns=200*ns,
        poi_event_ids=['seed'],step_seconds=20,max_extension_seconds=20,boundary_seconds=10,max_events=3)
    assert len(kept)==3
    assert diag['rounds'][-1]['truncated'] is True
    assert diag['incomplete'] is True
    assert diag['truncation_reason']=='candidate_event_limit'
    assert diag['candidate_boundary_completeness']=='unverified'
