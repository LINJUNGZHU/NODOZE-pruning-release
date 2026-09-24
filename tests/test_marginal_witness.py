import itertools
from types import SimpleNamespace
import numpy as np
import pytest
from tc_pruning.marginal_witness import make_pool, greedy_select, milp_select, utility


def fixture():
    v=np.array([1.,.95,.9,.5,.1,.8])
    r=np.array([0,0,0,1,2,1]);m=np.array([1,0,0,0,0,0],bool)
    back=np.array([-1,0,0,0,0,-1]);parent=np.array([-1,4,4,-1,-1,-1])
    pivot=np.array([0,4,4,3,4,-1])
    return v,r,m,(back,parent,pivot)


def slow(pool,budget,lam):
    keep=pool.mandatory.copy()
    while True:
        best=None
        for i,b in enumerate(pool.bundles):
            extra=b[~keep[b]]
            if not len(extra) or keep.sum()+len(extra)>budget:continue
            new=keep.copy();new[extra]=True
            density=(utility(pool,new,lam)-utility(pool,keep,lam))/len(extra)
            key=(-density,int(pool.ties[i]))
            if best is None or key<best[0]:best=(key,new)
        if best is None:return keep
        keep=best[1]


def test_union_witness_and_ineligible_and_mandatory():
    v,r,m,routes=fixture();pool=make_pool(v,r,m,4,np.arange(6),routes)
    selected,meta=greedy_select(pool,4,0)
    assert selected.tolist()==[True,True,True,False,True,False]
    assert meta['raw_events']==4
    with pytest.raises(ValueError):greedy_select(pool,0,1)


@pytest.mark.parametrize('seed',range(12))
@pytest.mark.parametrize('lam',[0.,1.,4.])
def test_incremental_greedy_matches_slow(seed,lam):
    rng=np.random.default_rng(seed);n=18;back=np.full(n,-1)
    back[1:]=[rng.integers(i) for i in range(1,n)]
    v=rng.uniform(.01,1,n);r=rng.integers(0,4,n);m=np.arange(n)==0
    pool=make_pool(v,r,m,n,np.arange(n),(back,np.full(n,-1),np.arange(n)))
    for cap in (1,4,9,18):
        result,_=greedy_select(pool,cap,lam)
        assert np.array_equal(result,slow(pool,cap,lam))


def test_milp_agrees_with_exhaustive_union_search():
    v,r,m,routes=fixture();pool=make_pool(v,r,m,4,np.arange(6),routes)
    for cap in (1,2,3,4,5):
        best=-1
        for active in itertools.product([False,True],repeat=len(pool.bundles)):
            keep=m.copy()
            for use,b in zip(active,pool.bundles):
                if use:keep[b]=True
            if keep.sum()<=cap:best=max(best,utility(pool,keep,0))
        kept,meta=milp_select(pool,cap,time_limit=5,relative_gap=0)
        assert meta['status']=='ok'
        assert utility(pool,kept,0)==pytest.approx(best)
        assert meta['objective_upper_bound']==pytest.approx(best)


def test_no_incumbent_is_not_a_fake_solution(monkeypatch):
    import tc_pruning.marginal_witness as module
    v,r,m,routes=fixture();pool=make_pool(v,r,m,4,np.arange(6),routes)
    monkeypatch.setattr(module,'milp',lambda **kw:SimpleNamespace(x=None,status=1,message='time limit',mip_gap=None,mip_dual_bound=None,mip_node_count=None))
    kept,meta=milp_select(pool,4)
    assert kept is None and meta['status']=='no_incumbent'


def test_dense_same_type_is_not_subject_to_fixed_half_quota():
    n=10;v=np.array([1]+[.9]*7+[.001]*2);r=np.array([0]*8+[1,2]);m=np.arange(n)==0
    pool=make_pool(v,r,m,6,np.arange(n),(np.array([-1]+[0]*9),np.full(n,-1),np.arange(n)))
    kept,_=greedy_select(pool,6,1)
    assert kept.sum()==6 and not kept[8:].any()
