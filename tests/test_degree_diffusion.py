import numpy as np
from tc_pruning.degree_diffusion import degree_normalized_score


def test_degree_normalized_kernel_is_duplicate_invariant():
    d=dict(src=np.array([0,0,0]),dst=np.array([1,2,3]),relation=np.zeros(3,int),poi=np.array([0,1,0],bool),process_nodes=np.ones(4,bool))
    cfg=dict(restart=.15,iterations=200,tolerance=1e-10,heat_time=3.)
    for k in ['ppr','heat']:
        a,_=degree_normalized_score(d,cfg,k)
        duplicate={key:(np.r_[val,val[0:1]] if key in ['src','dst','relation','poi'] else val) for key,val in d.items()}
        b,_=degree_normalized_score(duplicate,cfg,k)
        assert np.allclose(a,b[:3]) and b[0]==b[3]
        assert a[1]>a[0] and a[0]==a[2]


def test_degree_normalized_ppr_matches_direct_linear_solution():
    d=dict(src=np.array([0,0,1]),dst=np.array([1,2,3]),relation=np.zeros(3,int),poi=np.array([1,0,0],bool),process_nodes=np.ones(4,bool))
    cfg=dict(restart=.15,iterations=200,tolerance=1e-12)
    A=np.array([[0,1,1,0],[1,0,0,1],[1,0,0,0],[0,1,0,0]],float);degree=A.sum(axis=0);seed=np.array([.5,.5,0,0])
    p=np.linalg.solve(np.eye(4)-.85*A/degree,.15*seed)/degree
    expected=np.sqrt(p[d['src']]*p[d['dst']]);expected/=expected.max();expected[d['poi']]=1
    actual,_=degree_normalized_score(d,cfg,'ppr')
    assert np.allclose(actual,expected,atol=1e-10)
