import numpy as np
from tc_pruning.deferred_event_groups import GroupIndex


def test_total_span_does_not_chain_and_relation_policy_is_explicit():
    # 0, 9, 18 seconds share an endpoint pair; 18 must start another group.
    src=np.array([0,0,0,0]);dst=np.array([1,1,1,1]);rel=np.array([1,2,1,1]);ts=np.array([0,9,18,0])*10**9
    tie=np.array([10,11,12,13],np.uint64)
    across=GroupIndex.from_events(src,dst,rel,ts,tie,10**10,'across_relations')
    assert across.group_of[0]==across.group_of[1]==across.group_of[3]
    assert across.group_of[2]!=across.group_of[0]
    assert len(across.members(across.group_of[0]))==3
    exact=GroupIndex.from_events(src,dst,rel,ts,tie,10**10,'same_relation')
    assert exact.group_of[0]!=exact.group_of[1]
    assert np.all(exact.end_ns-exact.start_ns<=10**10)


def test_host_qualified_node_indices_do_not_cross_group():
    src=np.array([0,2]);dst=np.array([1,3]);rel=np.array([1,1]);ts=np.array([0,0]);tie=np.array([1,2])
    g=GroupIndex.from_events(src,dst,rel,ts,tie,10,'across_relations')
    assert g.group_of[0]!=g.group_of[1]
