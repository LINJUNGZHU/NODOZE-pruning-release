import numpy as np
import pytest
from tc_pruning.diffusion_portfolio import portfolio_budget


def test_portfolio_preserves_global_prefix_then_covers_other_relations():
    score=np.array([1,.99,.98,.97,.5,.4,.3,.2]);rel=np.array([0,0,0,0,1,1,2,2]);m=np.array([1,0,0,0,0,0,0,0],bool)
    chosen=portfolio_budget(score,rel,m,4,np.arange(8),.5)
    assert chosen.tolist()==[True,True,False,False,True,False,True,False]


def test_portfolio_mandatory_cost_and_fraction_boundaries():
    v=np.arange(6.);r=np.array([0,0,0,1,1,1]);m=np.array([1,1,1,0,0,0],bool)
    assert portfolio_budget(v,r,m,4,np.arange(6),.5).sum()==4
    assert portfolio_budget(v,r,m,4,np.arange(6),.5)[m].all()
    with pytest.raises(ValueError):portfolio_budget(v,r,m,2,np.arange(6),.5)
    with pytest.raises(ValueError):portfolio_budget(v,r,m,4,np.arange(6),1.1)
