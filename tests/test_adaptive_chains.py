import numpy as np
import pytest


def rows():
    return [dict(event_id=f'e{i}',src=a,dst=b,timestamp_ns=t,relation='WRITE',
                 src_type='process',dst_type='process',src_semantic=a,dst_semantic=b,
                 is_declared_poi=(i==1),components={'rarity':.5})
            for i,(a,b,t) in enumerate([('root','a',1),('a','b',2),('b','c',3),('c','end',4),('noise','hub',5)])]


def module():
    from tc_pruning import adaptive_chains
    return adaptive_chains


def test_observed_chain_extends_both_sides_of_alert_and_preserves_low_score_bridge():
    m=module(); events=rows()
    bundles,diagnostics=m.build_chain_bundles(events,np.array([.2,1,.001,.9,0.]))
    assert any(set(b['event_indices'])=={0,1,2,3} and b['complete_in_candidate'] for b in bundles)
    mask,audit=m.select_chain_bundles(events,np.array([.2,1,.001,.9,0.]),bundles,4)
    assert mask.tolist()==[True,True,True,True,False]
    assert audit['retained_complete_bundles']>=1


def test_budget_never_silently_overflows_when_full_alert_chain_does_not_fit():
    m=module();events=rows();scores=np.array([.2,1,.1,.9,0.])
    bundles,_=m.build_chain_bundles(events,scores)
    mask,audit=m.select_chain_bundles(events,scores,bundles,2)
    assert mask.sum()<=2 and mask[1]
    assert audit['retained_complete_bundles']==0
    assert audit['blocked_by_budget']>0
    assert audit['minimum_alert_bundle_edges']==4


def test_equal_time_continuation_not_claimed_as_temporal_path():
    m=module();events=rows();events[2]['timestamp_ns']=2
    bundles,_=m.build_chain_bundles(events,np.ones(5))
    for b in bundles:
        for path in b['paths']:
            times=[events[i]['timestamp_ns'] for i in path]
            assert all(a<b for a,b in zip(times,times[1:]))


def test_hop_limit_is_disclosed_not_called_complete():
    m=module();events=rows()
    bundles,diag=m.build_chain_bundles(events,np.ones(5),max_hops=2)
    assert diag['truncated_bundles']>0
    assert not any(b['complete_in_candidate'] for b in bundles if 1 in b['event_indices'])


def test_no_groundtruth_dependency_and_row_order_determinism():
    m=module();events=rows();scores=np.array([.2,1,.1,.9,0.])
    a,_=m.run_adaptive(events,scores,budget=4)
    changed=[dict(r,attack=True,groundtruth='ignore',label='malicious') for r in events]
    b,_=m.run_adaptive(changed,scores,budget=4)
    assert np.array_equal(a,b)
    order=[4,2,0,3,1]
    c,_=m.run_adaptive([events[i] for i in order],scores[order],budget=4)
    assert {events[i]['event_id'] for i in np.flatnonzero(a)}=={events[order[i]]['event_id'] for i in np.flatnonzero(c)}


def test_invalid_input_and_poi_infeasibility():
    m=module();events=rows()
    with pytest.raises(ValueError):m.run_adaptive(events,np.ones(5),budget=0)
    with pytest.raises(ValueError):m.build_chain_bundles(events,np.array([1,1,np.nan,1,1]))
    with pytest.raises(ValueError):m.build_chain_bundles(events+[events[0]],np.ones(6))


def test_causal_execute_direction():
    m=module();events=rows()[:2]
    events[0].update(src='a',dst='root',relation='EVENT_EXECUTE')
    bundles,_=m.build_chain_bundles(events,np.ones(2))
    assert any(b['paths']==[[0,1]] for b in bundles)


@pytest.mark.parametrize('edges',[
    [('x','b',1,False),('a','b',2,True)],
    [('a','b',1,True),('a','c',2,False)]])
def test_shared_alert_endpoint_is_real_branch_not_fake_directed_path(edges):
    m=module()
    events=[dict(event_id=f'p{i}',src=a,dst=b,timestamp_ns=t,relation='WRITE',is_declared_poi=poi) for i,(a,b,t,poi) in enumerate(edges)]
    bundles,_=m.build_chain_bundles(events,np.ones(2))
    for bundle in bundles:
        for path in bundle['paths']:
            assert all(m.causal_endpoints(events[a])[1]==m.causal_endpoints(events[b])[0] for a,b in zip(path,path[1:]))


@pytest.mark.parametrize('timestamp',[True,1.8,1.0,'1.8'])
def test_fractional_or_boolean_timestamps_are_not_silently_coerced(timestamp):
    events=rows();events[0]['timestamp_ns']=timestamp
    with pytest.raises(ValueError):module().build_chain_bundles(events,np.ones(5))


def test_bounded_completion_does_not_remove_existing_candidate_coverage():
    m=module();events=rows();scores=np.array([.2,1,.1,.9,0.])
    bundles,diag=m.build_chain_bundles(events,scores,max_hops=2)
    kept,audit=m.select_adaptive_bundles(events,scores,bundles,4)
    assert kept.tolist()==[True,True,True,True,False]
    assert audit['fallback_witnesses']>0
    assert audit['retained_complete_bundles']==0


def test_anchor_sampling_limit_has_fallback_instead_of_coverage_gate():
    m=module();events=rows();scores=np.array([.2,1,.1,.9,0.])
    bundles,diag=m.build_chain_bundles(events,scores,max_anchors=1)
    kept,audit=m.select_adaptive_bundles(events,scores,bundles,4)
    assert kept.tolist()==[True,True,True,True,False]
