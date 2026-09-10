import numpy as np
import pytest

from tc_pruning.rasp import interaction_graph, personalized_pagerank, propagate, select_bundles, select_fork_bundles, temporal_fork_routes, temporal_routes


CONFIG = {"restart": .15, "iterations": 200, "tolerance": 1e-10, "rarity_floor": .2}


def test_interaction_duplication_does_not_amplify_diffusion():
    src, dst, rel, rarity = np.array([0, 1, 1]), np.array([1, 2, 3]), np.array([0, 0, 1]), np.array([.2, .8, .3])
    score, _ = propagate(src, dst, rel, rarity, np.array([True, False, False]), [1, 1, 0, 0], CONFIG)
    repeat = np.array([0, 1, 2]+[2]*100)
    pois = np.zeros(len(repeat), dtype=bool)
    pois[0] = True
    duplicated, _ = propagate(src[repeat], dst[repeat], rel[repeat], rarity[repeat], pois, [1, 1, 0, 0], CONFIG)
    assert np.allclose(score, duplicated[:3], atol=1e-12)
    assert len(interaction_graph(src[repeat], dst[repeat], rel[repeat], rarity[repeat])[0]) == 3


def test_pagerank_mass_conservation_including_dangling_nodes():
    p, diag, _ = personalized_pagerank(np.array([0]), np.array([1]), np.array([1.]), [1, 0, 1], iterations=200)
    assert abs(p.sum()-1) < 1e-12 and np.all(p >= 0)
    assert diag["converged"]


def test_bundle_packing_charges_connectors_and_never_exceeds_cap():
    src, dst, ts = map(np.array, ([0, 1, 2, 8], [1, 2, 3, 9], [1, 2, 3, 2]))
    poi = np.array([False, False, True, False])
    links, direction, reachable, _ = temporal_routes(src, dst, ts, poi)
    score = np.array([1., .01, 1., 10.])
    kept, _ = select_bundles(score, poi, links, direction, reachable, 3)
    assert kept.tolist() == [True, True, True, False]
    kept, _ = select_bundles(score, poi, links, direction, reachable, 2)
    assert kept.sum() <= 2 and not kept[0] and kept[2]
    with pytest.raises(ValueError):
        select_bundles(score, poi, links, direction, reachable, 0)


def test_temporal_routes_use_both_directions_but_not_equal_time():
    src, dst, ts = map(np.array, ([0, 1, 2, 4], [1, 2, 3, 1], [1, 2, 3, 2]))
    poi = np.array([False, True, False, False])
    links, direction, reachable, depth = temporal_routes(src, dst, ts, poi)
    assert reachable.tolist() == [True, True, True, False]
    assert direction[2] == 1 and direction[0] == 0
    assert depth[:3].tolist() == [1, 0, 1]


def test_scorer_requires_real_seed_and_valid_rarity():
    with pytest.raises(ValueError):
        propagate([0], [1], [0], [.2], [False], [1, 0], CONFIG)
    with pytest.raises(ValueError):
        propagate([0], [1], [0], [float("nan")], [True], [1, 0], CONFIG)


def test_common_cause_branch_not_mistaken_for_disconnected_noise():
    # The ancestor 0 both causes the alert via 1 and acts on another branch 3.
    src, dst, ts = map(np.array, ([0, 1, 0], [1, 2, 3], [1, 3, 2]))
    poi = np.array([False, True, False])
    links, _, direct, _ = temporal_routes(src, dst, ts, poi)
    assert not direct[2]
    parent, pivot, reachable, _ = temporal_fork_routes(src, dst, ts, poi, links[0])
    assert reachable.all()
    kept, _ = select_fork_bundles(np.array([.01, 1., 1.]), poi, links[0], parent, pivot, 3)
    assert kept.all()
    kept, _ = select_fork_bundles(np.array([.01, 1., 1.]), poi, links[0], parent, pivot, 2)
    assert kept.sum() <= 2 and not kept[2]


def test_fork_does_not_traverse_backward_again_after_forward_branch():
    src, dst, ts = map(np.array, ([0, 1, 0, 9], [1, 2, 3, 3], [1, 4, 2, 3]))
    poi = np.array([False, True, False, False])
    _, _, reach, _ = temporal_fork_routes(src, dst, ts, poi)
    assert reach.tolist() == [True, True, True, False]
