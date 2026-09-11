import numpy as np
import pytest

from tc_pruning.rasp import select_fork_bundles
from tc_pruning.rasp_diverse import event_families, marginal, select_diverse


def test_marginal_diminishes_and_preserves_quality_floor():
    assert marginal(.5, .5, 0, .05) > marginal(.5, .5, 10, .05)
    assert marginal(.5, .5, 1e9, .05) >= .025
    assert marginal(.5, .5, 10, 1) == .5


def test_repeated_interactions_cannot_monopolize_small_budget():
    score = np.array([1., .9, .9, .9, .7, .6])
    poi = np.array([True, False, False, False, False, False])
    back = np.array([-1, 0, 0, 0, 0, 0])
    parent, pivot = np.full(6, -1), np.arange(6)
    families = np.array([0, 1, 1, 1, 2, 3])
    kept, _, evidence = select_diverse(score, poi, back, parent, pivot, families, 4, np.arange(6), 0)
    assert kept.tolist() == [True, True, False, False, True, True]
    assert evidence["selected_families"] == 4


def test_quality_only_matches_original_fork_selector():
    rng = np.random.default_rng(91)
    score = rng.random(50)
    poi = np.arange(50) == 0
    back = np.r_[-1, np.zeros(49, dtype=int)]
    parent, pivot = np.full(50, -1), np.arange(50)
    tie = rng.permutation(50)
    expected, _ = select_fork_bundles(score, poi, back, parent, pivot, 15, tie)
    actual, _, _ = select_diverse(score, poi, back, parent, pivot, np.arange(50)%4, 15, tie, 1)
    assert np.array_equal(actual, expected)


def test_family_identity_is_directed_and_relation_sensitive():
    family = event_families([0, 0, 1, 0], [1, 1, 0, 1], [0, 0, 0, 1])
    assert family[0] == family[1] and len(set(family)) == 3


def test_budget_includes_connectors_and_rejects_bad_inputs():
    score, poi = np.array([1., .01, .8]), np.array([True, False, False])
    back, parent, pivot = np.array([-1, 0, 1]), np.full(3, -1), np.arange(3)
    kept, _, _ = select_diverse(score, poi, back, parent, pivot, np.arange(3), 2, np.arange(3))
    assert kept.sum() <= 2 and not kept[2]
    with pytest.raises(ValueError):
        select_diverse(score, poi, back, parent, pivot, np.arange(3), 0, np.arange(3))


def test_recording_legacy_trace_does_not_change_selection():
    import numpy as np
    from tc_pruning.rasp_diverse import select_diverse
    score=np.array([1.,.6,.6,.4]);poi=np.array([1,0,0,0],bool)
    back=np.array([-1,0,0,0]);parent=np.full(4,-1);pivot=np.arange(4);family=np.array([0,1,1,2]);ties=np.arange(4)
    plain=select_diverse(score,poi,back,parent,pivot,family,3,ties)
    audited=select_diverse(score,poi,back,parent,pivot,family,3,ties,record_audit=True)
    assert np.array_equal(plain[0],audited[0])
    assert np.array_equal(plain[1],audited[1])
    assert audited[2]['trace'][-1]['used_after']==3
