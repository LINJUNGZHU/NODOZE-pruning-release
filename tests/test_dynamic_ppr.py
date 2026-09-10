import numpy as np
import pytest
from tc_pruning.dynamic_ppr import DynamicPPR


def exact(d, n):
    transition = np.zeros((n, n))
    for u in range(n):
        for v, w in d.row(u).items():
            transition[u, v] = w
    seed = np.array([d.seed.get(i, 0) for i in range(n)])
    return np.linalg.solve(np.eye(n)-(1-d.alpha)*transition.T, d.alpha*seed)


def test_weight_insert_delete_seed_and_dangling():
    d = DynamicPPR(); d.set_seed({0: 1})
    for u, v, w in [(0, 1, 1), (1, 2, .2), (0, 1, .3), (1, 2, 0), (0, 0, 2)]:
        d.set_edge(u, v, w)
        diag = d.solve(1e-9)
        error = np.abs(exact(d, 3)-[d.p[i] for i in range(3)]).sum()
        assert error <= diag['error_l1_bound']+1e-13
        assert diag['converged']
    d.set_seed({2: 1}); d.solve(1e-9)
    assert np.allclose(exact(d, 3), [d.p[i] for i in range(3)], atol=1e-9)


def test_repeated_channel_and_work_cap():
    d = DynamicPPR(); d.set_seed({0: 1}); d.set_edge(0, 1, 1)
    assert not d.solve(1e-12, 1)['converged']
    d.solve(1e-8); d.set_edge(0, 1, 1)
    assert d.solve(1e-8)['pushes'] == 0
    with pytest.raises(ValueError): d.set_edge(0, 1, -1)
