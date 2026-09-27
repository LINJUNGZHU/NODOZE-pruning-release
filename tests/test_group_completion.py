import math
import numpy as np
import pytest
from tc_pruning.group_completion import Bundle, Snapshot, select, marginal_gain, build_pool
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.alternative_witnesses import validate_witness


def snapshot(actions,group_of,weights,scores=None):
    n=len(group_of)
    return Snapshot(tuple(actions),np.zeros(n) if scores is None else np.array(scores,float),np.array(group_of),np.array(weights,float),(),tuple(range(n)))


def test_exact_marginal_counts_every_group_affected_by_connectors():
    pool=snapshot([Bundle((1,),(0,1,2),('w1',),1,'full')],[0,1,2],[0,1,2])
    assert marginal_gain(pool,{0},pool.actions[0],'concave',1)==3
    assert marginal_gain(pool,{0,1},pool.actions[0],'concave',1)==2


def test_shared_witness_cost_is_an_event_union():
    pool=snapshot([Bundle((1,),(0,1,2),('w1',),1,'representative'),Bundle((3,),(0,2,3),('w3',),1,'full')],[0,1,1,1],[0,1])
    result=select(pool,{0},4,'concave')
    assert result.selected_events==(0,1,2,3)
    assert result.budget_used==4
    assert result.objective_value==pytest.approx(math.sqrt(3))
    assert result.trace[-1]['added_events']==[3]
    assert result.trace[-1]['used_before']==3 and result.trace[-1]['used_after']==4


def test_best_single_bundle_protects_against_density_trap():
    pool=snapshot([Bundle((1,),(0,1),('small',),1,'representative'),Bundle((2,3,4),(0,2,3,4),('big',),2,'full')],[0,1,2,2,2],[0,3,8/math.sqrt(3)])
    result=select(pool,{0},4,'concave')
    assert result.selected_events==(0,2,3,4)
    assert result.policy=='best_single_bundle'
    assert result.objective_value==pytest.approx(8)


def tiny_pool(cap=4,max_examined=100,builder=build_pool):
    src=np.array([1,0,0,0]);dst=np.array([2,1,1,1]);t=np.array([10,1,2,3]);poi=np.array([True,False,False,False]);ties=np.array([0,1,2,3])
    data=dict(ids=['seed','a','b','c'],src=src,dst=dst,timestamp=t,poi=poi,tie=ties,relation=np.zeros(4,int))
    groups=GroupIndex.from_events(src,dst,np.zeros(4),t,ties,20)
    back=temporal_routes(src,dst,t,poi)[0][0];parent,pivot,_,_=temporal_fork_routes(src,dst,t,poi,back)
    pool,diag=builder(data,np.array([1.,1.,0.,0.]),groups,(back,parent,pivot),{0},cap,max_examined)
    return data,pool,diag


def test_full_group_can_admit_zero_score_members_with_real_witnesses():
    data,pool,diag=tiny_pool()
    assert any(set(a.anchors)=={1,2,3} and a.level=='full' for a in pool.actions)
    assert set(pool.materialized_events)=={0,1,2,3}
    assert diag['zero_score_details_admitted']==2
    assert all(validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']) for w in pool.certificates)
    result=select(pool,{0},4,'concave')
    assert result.selected_events==(0,1,2,3)


def test_candidate_cap_counts_all_certificates_and_never_claims_unseen_members():
    data,pool,diag=tiny_pool(cap=3)
    assert len(pool.materialized_events)<=3
    assert all(set(a.events)<=set(pool.materialized_events) for a in pool.actions)
    assert not any(set(a.anchors)=={1,2,3} for a in pool.actions)
    _,pool,diag=tiny_pool(max_examined=1)
    assert diag['examined_events']<=1
    assert diag['scan_truncated']
    assert not any(set(a.anchors)=={1,2,3} and a.level=='full' for a in pool.actions)


def test_unreachable_zero_score_detail_has_no_executable_action():
    data,pool,_=tiny_pool()
    src=data['src'].copy();dst=data['dst'].copy();src[3]=5;dst[3]=6
    data=data|dict(src=src,dst=dst)
    groups=GroupIndex.from_events(src,dst,data['relation'],data['timestamp'],data['tie'],20)
    back=temporal_routes(src,dst,data['timestamp'],data['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(src,dst,data['timestamp'],data['poi'],back)
    p,diag=build_pool(data,np.array([1.,1.,0.,0.]),groups,(back,parent,pivot),{0},4,100)
    assert not any(3 in a.anchors for a in p.actions)


def test_edge_ablation_does_not_reward_unscored_detail():
    pool=snapshot([Bundle((1,),(0,1),('x',),1,'representative')],[0,1],[0,1])
    assert select(pool,{0},2,'edge').selected_events==(0,)
    assert select(pool,{0},2,'concave').selected_events==(0,1)


def test_infeasible_mandatory_and_bad_budget_are_explicit():
    pool=snapshot([], [0,0],[1])
    assert select(pool,{0,1},1,'concave').status=='infeasible_mandatory_budget'
    with pytest.raises(ValueError):select(pool,{0},True,'concave')


def test_diagnostics_are_json_serializable_and_rejected_witnesses_not_cached():
    import json
    _,pool,diag=tiny_pool(cap=2)
    json.dumps(diag)
    assert diag['cached_certificates']==len(pool.certificates)
    assert diag['cached_certificates']<=2


def test_independent_replay_rejects_incorrect_union():
    from scripts.evaluate_group_completion_v8 import verify
    data,_,_=tiny_pool()
    decision=dict(selected_ids=['seed','a'],mandatory_ids=['seed'],budget=2,certificates=[])
    with pytest.raises(ValueError,match='certificate union'):verify(decision,None,data)


def test_final_representative_does_not_shrink_or_claim_complete_group():
    _,pool,diag=tiny_pool()
    assert not any(a.anchors==(1,) and a.level=='full' for a in pool.actions)
    assert diag['cached_certificates']==len(pool.certificates)


def test_unknown_pool_hash_cannot_disable_independent_replay():
    from scripts.evaluate_group_completion_v8 import resolve_pool
    with pytest.raises(ValueError,match='missing frozen'):
        resolve_pool(dict(pool_sha256='missing',candidate_scope='bounded'),{})
    with pytest.raises(ValueError,match='unknown frozen'):
        resolve_pool(dict(pool_sha256='missing',candidate_scope='full_ledger'),{})


def test_rrf_adapter_uses_only_unlabeled_views_and_same_witness_contract():
    from tc_pruning.group_completion_rrf import RankedGroups
    data,pool,diag=tiny_pool()
    g=GroupIndex.from_events(data['src'],data['dst'],data['relation'],data['timestamp'],data['tie'],20)
    order=np.array([1,0]);ranked=RankedGroups(g,order)
    assert np.array_equal(ranked.ranked_descriptors(np.ones(4),data['tie']),order)
    assert np.array_equal(ranked.group_of,g.group_of)


def test_expansion_reserve_is_spent_on_previously_explored_groups():
    from tc_pruning.group_completion_expansion import build_pool as fixed
    data,pool,diag=tiny_pool(builder=fixed)
    assert diag['exploration_limit']==2
    assert diag['expansion_groups']==2
    assert any(set(a.anchors)=={1,2,3} and a.level=='full' for a in pool.actions)
    assert len(pool.materialized_events)==4
    assert all(validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']) for w in pool.certificates)
