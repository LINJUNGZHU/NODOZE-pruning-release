import numpy as np
from tc_pruning.evidence_objective import Action,CandidateSnapshot,select,complete_group


def snapshot(actions,weights=None,n=5):
    return CandidateSnapshot(tuple(actions),np.ones(n,float),np.array([1.,1.] if weights is None else weights,float),n)


def test_union_cost_and_and_or_group_support():
    a=Action(1,0,(0,1,2),1.,'w1')
    b=Action(2,1,(0,2,3),1.,'w2')
    c=Action(1,0,(0,1,4),1.,'w3')
    pool=snapshot([a,b,c])
    assert not complete_group(pool,0,{0,1})
    assert not complete_group(pool,0,{0,4})
    assert complete_group(pool,0,{0,1,4})
    result=select(pool,{0},4,'edge_score')
    assert result.status=='ok' and len(result.selected_events)<=4
    assert len(result.selected_events)==len(set(result.selected_events))


def test_anchor_credit_excludes_connection_edges_and_zero_cost_action_applies_once():
    actions=[Action(1,0,(0,1),2.,'a'),Action(2,1,(0,1,2),3.,'b')]
    pool=snapshot(actions,n=3)
    result=select(pool,{0,1,2},3,'anchor_score')
    assert result.status=='ok' and result.selected_anchors==(1,2)
    assert result.budget_used==3 and result.objective_value==5.
    assert result.selected_witnesses==('a','b')


def test_complete_support_is_group_once_and_infeasible_has_null():
    pool=snapshot([Action(1,0,(0,1),2.,'a'),Action(2,0,(0,2),1.,'b')],weights=[2.,0.],n=3)
    out=select(pool,{0},3,'witness_plus_detail',eta=0)
    assert out.objective_value==1. and out.budget_used<=3
    assert select(pool,{0,1,2},2,'witness_plus_detail').status=='infeasible_mandatory_budget'
    assert select(pool,{0,1,2},2,'witness_plus_detail').objective_value is None
