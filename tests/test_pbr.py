from __future__ import annotations

from tc_pruning.benchmark_contract import EdgeProjection
from tc_pruning.models import StoredEdge


def edge(number, event, src, dst, timestamp, relation="EVENT_WRITE",
         src_type="process", dst_type="file", src_semantic="", dst_semantic=""):
    return StoredEdge(number, event, src, dst, relation, timestamp, "h",
                      src_type, dst_type, src_semantic, dst_semantic)


def read_edge(number, event, resource, process, timestamp):
    return edge(number, event, resource, process, timestamp, "EVENT_READ", "file", "process")


def run(candidate, base, pois, *, ratio=10.0, fixed=10, relevance=None,
        rarity=None, k=3, demand_pairs=None):
    from tc_pruning.pbr import PBRConfig, rescue_poi_bridges

    return rescue_poi_bridges(
        candidate_edges=tuple(candidate),
        base_selected_event_ids=frozenset(base),
        poi_node_ids=frozenset(pois),
        mandatory_event_ids=frozenset(base),
        projection=EdgeProjection("RAW_EVENT", 10),
        relevance=relevance or {},
        rarity=rarity or {},
        demand_pairs=demand_pairs,
        config=PBRConfig(k_paths=k, fixed_extra_raw=fixed, rescue_ratio=ratio,
                         max_gate_path_events=4, max_path_events=6),
    )


def test_explicit_detector_demand_pairs_avoid_quadratic_all_poi_enumeration():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "one", "p1", "p2", 1),
        edge(2, "two", "p1", "p3", 2),
    )

    result = run(
        candidate, {"proxy"}, {"p1", "p2", "p3"}, fixed=1,
        demand_pairs=frozenset({("p1", "p2")}),
    )

    assert result.added_raw_event_ids == ("one",)
    assert result.rescued_demands == ("p1->p2",)
    assert result.metrics["demand_count"] == 1
    assert result.metrics["theoretical_all_pair_count"] == 6


def test_unique_strict_bridge_is_rescued_and_charged_by_unique_raw_events():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "b1", "p1", "x", 1),
        read_edge(2, "b2", "x", "p2", 2),
    )

    result = run(candidate, {"proxy"}, {"p1", "p2"}, ratio=2.0, fixed=2)

    assert result.added_raw_event_ids == ("b1", "b2")
    assert result.rescued_demands == ("p1->p2",)
    assert result.selected_bundles[0].raw_cost == 2
    assert result.selected_bundles[0].counterfactual_essentiality == 1.0
    assert result.metrics["added_raw_events"] == 2


def test_already_reachable_pair_adds_no_edge():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "b1", "p1", "x", 1),
        read_edge(2, "b2", "x", "p2", 2),
    )
    result = run(candidate, {"proxy", "b1", "b2"}, {"p1", "p2"})
    assert result.added_raw_event_ids == ()
    assert result.metrics["gated_demand_count"] == 0


def test_reverse_and_equal_timestamp_static_paths_are_not_rescued():
    reverse = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "late", "p1", "x", 2),
        read_edge(2, "early", "x", "p2", 1),
    )
    equal = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "same-a", "p1", "x", 1),
        read_edge(2, "same-b", "x", "p2", 1),
    )
    assert run(reverse, {"proxy"}, {"p1", "p2"}).added_raw_event_ids == ()
    assert run(equal, {"proxy"}, {"p1", "p2"}).added_raw_event_ids == ()


def test_low_cost_path_wins_when_multiple_strict_alternatives_exist():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "low-a", "p1", "x", 1),
        read_edge(2, "low-b", "x", "p2", 2),
        edge(3, "high-a", "p1", "y", 1),
        read_edge(4, "high-b", "y", "p2", 3),
    )
    result = run(candidate, {"proxy"}, {"p1", "p2"}, relevance={
        "low-a": 1.0, "low-b": 1.0, "high-a": 0.0, "high-b": 0.0,
    }, rarity={event: 1.0 for event in ("low-a", "low-b", "high-a", "high-b")})
    assert result.added_raw_event_ids == ("low-a", "low-b")
    assert len(result.considered_bundles) == 2


def test_counterfactual_essentiality_distinguishes_unique_from_replaceable_bridge():
    unique = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "only-a", "p1", "x", 1),
        read_edge(2, "only-b", "x", "p2", 2),
    )
    replaceable = unique + (
        edge(3, "alt-a", "p1", "y", 1),
        read_edge(4, "alt-b", "y", "p2", 2),
    )
    one = run(unique, {"proxy"}, {"p1", "p2"}, relevance={"only-a": 0.0, "only-b": 0.0})
    many = run(replaceable, {"proxy"}, {"p1", "p2"}, relevance={
        "only-a": 1.0, "only-b": 1.0, "alt-a": 1.0, "alt-b": 1.0,
    })
    assert one.considered_bundles[0].counterfactual_essentiality == 1.0
    assert max(bundle.counterfactual_essentiality for bundle in many.considered_bundles) < 1.0


def test_unique_raw_budget_is_hard_and_overlap_is_not_double_charged():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "shared", "p1", "x", 1),
        read_edge(2, "to-p2", "x", "p2", 2),
        read_edge(3, "to-p3", "x", "p3", 3),
    )
    result = run(candidate, {"proxy"}, {"p1", "p2", "p3"}, ratio=3.0, fixed=3)
    assert set(result.added_raw_event_ids) == {"shared", "to-p2", "to-p3"}
    assert result.metrics["added_raw_events"] == 3
    assert all(bundle.raw_cost == 2 for bundle in result.selected_bundles)

    blocked = run(candidate, {"proxy"}, {"p1", "p2", "p3"}, ratio=1.0, fixed=1)
    assert blocked.added_raw_event_ids == ()
    assert blocked.metrics["added_raw_events"] <= 1


def test_cleanup_never_breaks_a_rescued_demand_or_removes_mandatory_evidence():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "a", "p1", "x", 1),
        read_edge(2, "b", "x", "p2", 2),
    )
    result = run(candidate, {"proxy"}, {"p1", "p2"}, ratio=2.0, fixed=2)
    assert set(result.selected_raw_event_ids) == {"proxy", "a", "b"}
    assert "proxy" not in result.cleanup_removed_event_ids
    assert result.rescued_demands == ("p1->p2",)


def test_zero_allowance_exactly_reproduces_legacy_selection_and_hash_is_deterministic():
    candidate = (
        read_edge(0, "proxy", "seed", "p1", 0),
        edge(1, "a", "p1", "p2", 1),
    )
    first = run(candidate, {"proxy"}, {"p1", "p2"}, ratio=0.0, fixed=0)
    second = run(candidate, {"proxy"}, {"p1", "p2"}, ratio=0.0, fixed=0)
    assert first.selected_raw_event_ids == ("proxy",)
    assert first.decision_sha256 == second.decision_sha256
