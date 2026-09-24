import numpy as np
import pytest
from tc_pruning.candidate_views import rank_views


def test_primary_rrf_and_round_robin_are_deterministic():
    primary=np.array([4.,3.,2.,1.]); rarity=np.array([1.,2.,3.,4.]); temporal=np.array([1.,4.,3.,2.]); ties=np.array([11,12,13,14],np.uint64)
    assert rank_views(primary,rarity,temporal,ties,'primary').tolist()==[0,1,2,3]
    rrf=rank_views(primary,rarity,temporal,ties,'rrf',60)
    assert sorted(rrf.tolist())==list(range(4))
    assert np.array_equal(rrf,rank_views(primary,rarity,temporal,ties,'rrf',60))
    rr=rank_views(primary,rarity,temporal,ties,'round_robin')
    assert rr.tolist()[:3]==[0,3,1]


def test_rank_views_rejects_invalid_scores_and_ties():
    v=np.array([1.,2.]); t=np.array([1,1],np.uint64)
    with pytest.raises(ValueError,match='unique'):
        rank_views(v,v,v,t,'primary')
    with pytest.raises(ValueError,match='nonnegative'):
        rank_views(v,np.array([-1.,2.]),v,np.array([1,2]),'rrf')
