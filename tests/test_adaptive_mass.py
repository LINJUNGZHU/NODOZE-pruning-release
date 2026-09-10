import numpy as np
import pytest

from tc_pruning.adaptive_mass import close_witnesses, fit_score_mixture, select_mass, temporal_successors


def test_small_stratum_is_not_drowned_by_large_stratum():
    selected, thresholds = select_mass([100., 1., .01, .001], [0, 0, 1, 1], [False]*4, .1)
    assert selected.tolist() == [True, False, True, False]
    assert all(t["constraint_met"] for t in thresholds)


def test_protected_zero_score_and_no_zero_score_budget_fill():
    selected, _ = select_mass([0., 0., 10., 1.], [0]*4, [True, False, False, False], .1)
    assert selected.tolist() == [True, False, True, False]


def test_low_score_bridge_is_restored_to_poi():
    successor, reachable = temporal_successors([0, 1, 2, 9], [1, 2, 3, 0], [1, 2, 3, 4], [False, False, True, False])
    assert reachable.tolist() == [True, True, True, False]
    closed = close_witnesses([True, False, True, False], successor)
    assert closed.tolist() == [True, True, True, False]
    assert np.array_equal(close_witnesses(closed, successor), closed)


def test_same_timestamp_and_future_edges_cannot_form_witness():
    successor, reachable = temporal_successors([0, 1, 2], [1, 2, 1], [2, 2, 3], [False, True, False])
    assert reachable.tolist() == [False, True, False]
    assert successor.tolist() == [-1, -1, -1]


@pytest.mark.parametrize("score,loss", [([float("nan")], .1), ([-1], .1), ([1], 1), ([1], -.1)])
def test_reject_invalid_values(score, loss):
    with pytest.raises(ValueError):
        select_mass(score, [0], [False], loss)


def test_stricter_mass_tolerance_is_nested():
    scores = np.random.default_rng(7).random(100)
    groups = np.arange(100) % 5
    broad, _ = select_mass(scores, groups, [False]*100, .05)
    narrow, _ = select_mass(scores, groups, [False]*100, .2)
    assert np.all(broad[narrow])


def test_minimum_hop_witness_skips_long_recent_chain():
    # 0 -> 1 -> 2 -> 3 is longer than 0 -> 1 -> POI at time 5.
    src, dst, ts, poi = [0, 1, 2, 1], [1, 2, 3, 9], [1, 2, 3, 5], [False, False, True, True]
    latest, _ = temporal_successors(src, dst, ts, poi)
    shortest, _ = temporal_successors(src, dst, ts, poi, minimum_hops=True)
    assert latest[0] == 1
    assert shortest[0] == 3


def test_mixture_separates_synthetic_groups_and_abstains_on_constant():
    rng = np.random.default_rng(17)
    low, high = np.exp(rng.normal(-8, .2, 200)), np.exp(rng.normal(-1, .2, 100))
    p, fit = fit_score_mixture(np.r_[low, high, 0.])
    assert fit["status"] == "fitted"
    assert max(p[:200]) < .1 and min(p[200:300]) > .9 and p[-1] == 0
    p, fit = fit_score_mixture(np.ones(20))
    assert not p.any() and fit["status"].startswith("abstained")
