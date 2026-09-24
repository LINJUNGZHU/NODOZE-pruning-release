import numpy as np
from tc_pruning.witness_portfolio import witness_portfolio


def test_witness_portfolio_charges_connectors_and_never_returns_disconnected_anchor():
    # event1 high priority needs connector event3; event2 belongs to another relation.
    score=np.array([1,.9,.8,.1]);rel=np.array([0,0,1,2]);poi=np.array([1,0,0,0],bool)
    back=np.array([-1,-1,0,0]);parent=np.array([-1,3,-1,-1]);pivot=np.array([0,3,2,3])
    kept=witness_portfolio(score,rel,poi,4,np.arange(4),(back,parent,pivot),.5)
    assert kept.all()
    kept=witness_portfolio(score,rel,poi,3,np.arange(4),(back,parent,pivot),.5)
    assert kept[0] and kept.sum()<=3
    assert not kept[1] or kept[3]


def test_witness_portfolio_skips_unreachable_high_scores_and_keeps_mandatory():
    score=np.array([1,.99,.5,.1]);rel=np.array([0,1,1,2]);m=np.array([1,0,0,1],bool)
    routes=(np.array([-1,-1,0,-1]),np.full(4,-1),np.array([0,-1,2,-1]))
    kept=witness_portfolio(score,rel,m,3,np.arange(4),routes,.5)
    assert kept.tolist()==[True,False,True,True]
