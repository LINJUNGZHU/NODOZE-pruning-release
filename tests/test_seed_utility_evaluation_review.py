from __future__ import annotations

import pytest

from tc_pruning.models import StoredEdge
from tc_pruning.seed_utility_evaluation import CandidateStageIds, EdgeProjection, ProjectionMode, evaluate_coverage_funnel, performance_fields


def _edge(event: str, src: str, dst: str, time: int) -> StoredEdge:
    return StoredEdge(time, event, src, dst, "EVENT_WRITE", time, "h", "process", "file")


def test_funnel_separates_unscored_native_threshold_and_reconstruction_recovery() -> None:
    funnel = evaluate_coverage_funnel(
        known_critical_event_ids={"unscored", "below", "direct", "recovered", "miss"},
        stages=CandidateStageIds(
            raw_database={"unscored", "below", "direct", "recovered", "miss"},
            preprocessing={"unscored", "below", "direct", "recovered", "miss"},
            inference={"unscored", "below", "direct", "recovered", "miss"},
            scored={"below", "direct", "recovered", "miss"}, native_threshold={"direct", "recovered", "miss"},
            evidence={"direct"}, candidate={"direct", "recovered"}, final={"direct"},
        ),
    )

    assert funnel["candidate_ceiling_decomposition"]["unscored"] == ["unscored"]
    assert funnel["candidate_ceiling_decomposition"]["below_native_threshold"] == ["below"]
    assert funnel["direct_evidence_hits"] == ["direct"]
    assert funnel["direct_miss_recovered_by_reconstruction"] == ["recovered"]
    assert funnel["reconstruction_miss"] == ["below", "miss", "unscored"]


def test_pairwise_delta_unions_independent_candidates_and_preserves_isolated_nodes() -> None:
    from tc_pruning.seed_utility_evaluation import CandidateSnapshot, pairwise_candidate_delta

    left = CandidateSnapshot((_edge("a", "p", "x", 1), _edge("same-group", "p", "x", 2)), frozenset({"p", "x"}))
    right = CandidateSnapshot((_edge("b", "p", "attack", 11),), frozenset({"p", "attack", "isolated"}))
    delta = pairwise_candidate_delta(
        left, right, known_critical_event_ids={"a", "b"}, known_attack_node_ids={"attack", "isolated"},
        projection=EdgeProjection(ProjectionMode.RAW_EVENT, merge_window_ns=10),
    )

    assert delta["new_critical_edges"] == ["b"]
    assert delta["new_attack_nodes"] == ["attack", "isolated"]
    assert delta["projected_edge_delta"] == 1
    assert delta["raw_event_delta"] == 1


@pytest.mark.parametrize("changes", [
    {"adapter_seconds": -1.0}, {"final_seconds": -1.0}, {"candidate_edges": -1}, {"final_edges": -1}, {"peak_rss_kb": -1},
])
def test_performance_fields_reject_negative_artifact_values(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "inference_seconds": 1.0, "candidate_seconds": 2.0, "final_seconds": 3.0,
        "peak_rss_kb": 4, "candidate_edges": 5, "final_edges": 6,
    }
    values.update(changes)
    with pytest.raises(ValueError):
        performance_fields(**values)  # type: ignore[arg-type]


def test_performance_fields_provide_adapter_candidate_selector_and_total_post_alert_costs() -> None:
    fields = performance_fields(
        inference_seconds=1.0, candidate_seconds=2.0, final_seconds=3.0,
        adapter_seconds=0.5, peak_rss_kb=4, candidate_edges=5, final_edges=6,
    )
    assert fields["adapter_seconds"] == 0.5
    assert fields["candidate_seconds"] == 2.0
    assert fields["selector_seconds"] == 3.0
    assert fields["total_post_alert_seconds"] == 5.5
