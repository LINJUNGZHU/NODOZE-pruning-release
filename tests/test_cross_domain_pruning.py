import numpy as np
import pytest
from tc_pruning import cross_domain_pruning as cp


def fixture():
    d=dict(src=np.array([0,0,0,0]),dst=np.array([1,2,2,3]),relation=np.zeros(4,int),
           semantic=np.arange(4),poi=np.array([1,0,0,0],bool),tie=np.arange(4,dtype=np.uint64),
           timestamp=np.arange(4),process_nodes=np.array([1,0,0,0],bool))
    routes=(np.array([-1,0,0,0]),np.full(4,-1),np.arange(4))
    return d,routes


def test_saturation_selects_new_family_instead_of_duplicate_evidence():
    d,r=fixture()
    kept=cp.select_coverage(d,np.array([1,.9,.9,.3]),np.arange(4),r,3)
    assert kept.tolist()==[True,True,False,True]


def test_coverage_charges_connector_cost_and_keeps_mandatory():
    d,r=fixture();r=(np.array([-1,-1,-1,0]),np.array([-1,3,3,-1]),np.array([0,3,3,3]))
    mandatory=np.array([0,0,0,1],bool)
    kept=cp.select_coverage(d,np.array([1,.9,.9,.3]),np.array([0,1,1,2]),r,3,mandatory=mandatory)
    assert kept.tolist()==[True,False,False,True]


def test_poi_parallel_episode_is_completed_only_if_affordable():
    d,r=fixture();d['poi']=np.array([0,1,0,0],bool)
    d['src']=np.array([0,0,0,0]);d['dst']=np.array([1,2,2,3])
    r=(np.array([1,-1,1,1]),np.full(4,-1),np.arange(4))
    kept=cp.select_coverage(d,np.array([.2,1,.9,.3]),np.array([0,1,1,2]),r,2)
    assert kept.tolist()==[False,True,True,False]


def test_top_budget_never_overflows_or_drops_mandatory():
    got=cp.top_budget(np.array([.9,.8,.1]),np.array([0,0,1],bool),2,np.arange(3))
    assert got.tolist()==[True,False,True]
    with pytest.raises(ValueError):cp.top_budget(np.ones(3),np.ones(3,bool),2,np.arange(3))


def test_pcst_conversion_maps_virtual_nodes_to_original_edges():
    pytest.importorskip('pcst_fast')
    from tc_pruning.paper_baselines import pcst_edges
    # One profitable edge; adding the zero-prize expensive branch is not useful.
    kept=pcst_edges(np.array([0,1]),np.array([1,2]),np.array([2.,0.]),np.ones(2),np.array([0]),1.)
    assert kept.tolist()==[True,False]


def test_localdegree_scores_align_with_raw_parallel_edges():
    pytest.importorskip('networkit')
    from tc_pruning.paper_baselines import local_degree_scores
    got=local_degree_scores(np.array([0,0,0,1]),np.array([1,1,2,3]),4)
    assert got.shape==(4,) and np.isfinite(got).all()
    assert got[0]==got[1]


def test_partial_connector_does_not_saturate_unfinished_episode():
    d=dict(src=np.array([0,1,1,2]),dst=np.array([1,2,2,3]),relation=np.zeros(4,int),
           semantic=np.arange(4),poi=np.array([1,0,0,0],bool),tie=np.arange(4),timestamp=np.arange(4))
    routes=(np.full(4,-1),np.array([-1,0,0,1]),np.zeros(4,int))
    kept=cp.select_coverage(d,np.array([1.,.8,.8,.95]),np.array([0,1,1,2]),routes,4)
    assert kept.all()
