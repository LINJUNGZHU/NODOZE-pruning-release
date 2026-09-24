import numpy as np
import pytest
from scipy.linalg import expm
from tc_pruning import temporal_diffusion as td
from tc_pruning.frequency_diffusion import transition


def test_temporal_affinity_is_shift_invariant_and_monotone():
    ts=np.array([100,110,200]);p=np.array([100])
    assert td.temporal_affinity(ts,p,10).tolist()==pytest.approx([1,.5,1/11])
    assert np.allclose(td.temporal_affinity(ts+1000,p+1000,10),td.temporal_affinity(ts,p,10))
    with pytest.raises(ValueError):td.temporal_affinity(ts,p,0)


def test_heat_kernel_matches_matrix_exponential_and_preserves_mass():
    a,b,p=transition(np.array([0,1]),np.array([1,2]),np.zeros(2,int),np.ones(2),4,False)
    seed=np.array([1.,0,0,0]);P=np.zeros((4,4));P[b,a]=p;P[:,3]=seed
    v,diag=td.heat_walk(a,b,p,seed,3.,1e-12)
    assert np.allclose(v,expm(3*(P-np.eye(4)))@seed,atol=1e-11)
    assert v.sum()==pytest.approx(1,abs=1e-11) and diag['converged']
    v,_=td.heat_walk(a,b,p,np.array([0.,0,0,1.]),3.,1e-12)
    assert v.tolist()==pytest.approx([0,0,0,1],abs=1e-11)


def fixture():
    return dict(src=np.array([0,1,1,2]),dst=np.array([1,2,2,3]),relation=np.zeros(4,int),
        timestamp=np.array([100,101,10000,102]),rarity=np.ones(4)*.5,poi=np.array([1,0,0,0],bool),
        process_nodes=np.ones(4,bool),semantic=np.arange(4),tie=np.arange(4))


def test_temporal_diffusion_separates_remote_events_on_same_channel():
    d=fixture();cfg=dict(restart=.15,iterations=200,tolerance=1e-10,rarity_floor=.2,escape_floor=1e-6)
    v,diag=td.temporal_score(d,cfg,scale_ns=10)
    assert v[0]==1 and v[1]>v[2]*100
    assert all(w['converged'] for w in diag['walks'])
    d['timestamp']+=1234
    assert np.allclose(v,td.temporal_score(d,cfg,scale_ns=10)[0])


def test_no_frequency_really_ignores_rarity():
    d=fixture();cfg=dict(restart=.15,iterations=200,tolerance=1e-10,rarity_floor=.2,escape_floor=1e-6)
    a=td.temporal_score(d,cfg,scale_ns=10,frequency=False)[0];d['rarity'][:]=.99
    b=td.temporal_score(d,cfg,scale_ns=10,frequency=False)[0]
    assert np.allclose(a,b)


def test_relation_round_robin_keeps_poi_and_respects_raw_budget():
    v=np.array([1,.9,.8,.7,.1,.05]);r=np.array([0,0,0,0,1,1]);m=np.array([1,0,0,0,0,0],bool)
    chosen=td.stratified_budget(v,r,m,3,np.arange(6))
    assert chosen.tolist()==[True,True,False,False,True,False]
    with pytest.raises(ValueError):td.stratified_budget(v,r,np.ones(6,bool),3,np.arange(6))
