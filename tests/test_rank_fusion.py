import numpy as np
import pytest
from tc_pruning.rank_fusion import reciprocal_rank_fusion as fuse


def test_ties_scale_and_zero_abstention():
    a=np.array([.8,.8,.2,0]); mask=np.ones(4,dtype=bool)
    r=fuse([a],mask)
    assert r[0]==r[1]==1/61.5 and r[3]==0
    assert np.array_equal(r,fuse([a*100],mask))
    assert np.array_equal(2*r,fuse([a,a],mask))


def test_permutation_and_eligibility():
    a=np.array([5.,3.,3.,1.]); mask=np.array([False,True,True,True])
    order=np.array([3,1,0,2]); r=fuse([a],mask)
    assert r[0]==0 and r[1]==1/61.5
    assert np.array_equal(r[order],fuse([a[order]],mask[order]))
    with pytest.raises(ValueError): fuse([[-1]], [True])
