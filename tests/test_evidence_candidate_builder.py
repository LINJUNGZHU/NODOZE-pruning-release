from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _evidence(
    *, granularity: EvidenceGranularity | str = EvidenceGranularity.NODE,
    evidence_id: str = "evidence", node_ids: tuple[str, ...] = ("p",),
    event_ids: tuple[str, ...] = (), role: RoleHint | str = RoleHint.UNKNOWN,
    score: float = 0.0, **changes: object,
) -> AlertEvidence:
    values: dict[str, object] = {
        "evidence_id": evidence_id, "detector_id": "unrelated-name",
        "detector_version": "test", "granularity": granularity,
        "raw_score": score, "calibrated_score": score, "native_decision": False,
        "node_ids": node_ids, "event_ids": event_ids, "role_hint": role,
    }
    if granularity is EvidenceGranularity.EDGE or granularity == "EDGE":
        values.update(src_uuid="p", dst_uuid="a")
    if granularity in {
        EvidenceGranularity.SUBGRAPH, EvidenceGranularity.PATH,
        EvidenceGranularity.STRUCTURAL_GRAPH, "SUBGRAPH", "PATH", "STRUCTURAL_GRAPH",
    }:
        values["structural_context"] = {"native_members": ["p"]}
    values.update(changes)
    return AlertEvidence(**values)


def _store(path: Path) -> ProvenanceStore:
    store = ProvenanceStore(path)
    store.ingest([
        NodeRecord("old", "file", "old", "h"),
        NodeRecord("p", "process", "p", "h"),
        NodeRecord("a", "file", "a", "h"),
        NodeRecord("out", "file", "out", "h"),
        NodeRecord("equal", "file", "equal", "h"),
        EdgeRecord("past", "old", "p", "EVENT_READ", 5, "h"),
        EdgeRecord("anchor", "p", "a", "EVENT_WRITE", 10, "h"),
        EdgeRecord("equal-time", "p", "equal", "EVENT_WRITE", 10, "h"),
        EdgeRecord("future", "p", "out", "EVENT_WRITE", 15, "h"),
    ])
    return store


def _builder(store: ProvenanceStore, **changes: object):
    from tc_pruning.evidence_candidate_builder import (
        CandidateSearchConfig, EvidenceDrivenCandidateBuilder,
    )

    values: dict[str, object] = {"candidate_cap": 20, "max_strict_depth": 2}
    values.update(changes)
    return EvidenceDrivenCandidateBuilder(
        store, CandidateSearchConfig(**values),
    )


@pytest.mark.parametrize(
    ("granularity", "node_ids", "event_ids"),
    [
        (EvidenceGranularity.EVENT, ("p", "a"), ("anchor",)),
        (EvidenceGranularity.EDGE, ("p", "a"), ("anchor",)),
        (EvidenceGranularity.NODE, ("p",), ()),
        (EvidenceGranularity.SUBGRAPH, ("p",), ("anchor",)),
        (EvidenceGranularity.PATH, ("p",), ("anchor",)),
        (EvidenceGranularity.STRUCTURAL_GRAPH, ("p",), ("anchor",)),
    ],
)
def test_every_evidence_granularity_reconstructs_from_real_members(
    tmp_path: Path, granularity: EvidenceGranularity, node_ids: tuple[str, ...], event_ids: tuple[str, ...],
) -> None:
    with _store(tmp_path / "graph.db") as store:
        result = _builder(store).build([_evidence(
            granularity=granularity, node_ids=node_ids, event_ids=event_ids,
        )])

    assert "p" in result.node_ids
    assert {"past", "future"} <= result.event_ids
    if event_ids:
        assert "anchor" in result.event_ids


@pytest.mark.parametrize("role", [RoleHint.UNKNOWN, RoleHint.OBSERVATION, RoleHint.INTERIOR])
def test_unknown_observation_and_interior_are_bidirectional_strictly_in_time(tmp_path: Path, role: RoleHint) -> None:
    with _store(tmp_path / "graph.db") as store:
        result = _builder(store).build([_evidence(role=role, timestamp_start=10, timestamp_end=10)])

    assert {"past", "future"} <= result.event_ids
    assert "equal-time" not in result.event_ids


def test_entry_only_walks_forward_and_terminal_only_walks_backward(tmp_path: Path) -> None:
    with _store(tmp_path / "graph.db") as store:
        entry = _builder(store).build([_evidence(role=RoleHint.ENTRY, timestamp_start=10, timestamp_end=10)])
        terminal = _builder(store).build([_evidence(role=RoleHint.TERMINAL, timestamp_start=10, timestamp_end=10)])

    assert "future" in entry.event_ids and "past" not in entry.event_ids
    assert "past" in terminal.event_ids and "future" not in terminal.event_ids


def test_score_only_orders_work_and_is_never_a_hard_filter(tmp_path: Path) -> None:
    with _store(tmp_path / "graph.db") as store:
        low = _builder(store).build([_evidence(score=0.0, timestamp_start=10, timestamp_end=10)])

    assert {"past", "future"} <= low.event_ids


def test_structural_evidence_reports_only_its_real_members_as_soft_seed_region(tmp_path: Path) -> None:
    with _store(tmp_path / "graph.db") as store:
        result = _builder(store).build([_evidence(
            granularity=EvidenceGranularity.STRUCTURAL_GRAPH, event_ids=("anchor",), node_ids=("p",),
        )])

    assert result.soft_seed_node_ids == {"p", "a"}
    assert "out" not in result.soft_seed_node_ids


def test_candidate_cap_is_fixed_and_deterministic(tmp_path: Path) -> None:
    with _store(tmp_path / "graph.db") as store:
        first = _builder(store, candidate_cap=2).build([_evidence(timestamp_start=10, timestamp_end=10)])
        second = _builder(store, candidate_cap=2).build([_evidence(timestamp_start=10, timestamp_end=10)])

    assert len(first.edges) == 2
    assert first.event_ids == second.event_ids
    assert first.stop_reason == "CAP_REACHED"


def test_legacy_event_seed_compatibility_uses_stored_edges_and_registry(tmp_path: Path) -> None:
    with _store(tmp_path / "graph.db") as store:
        result = _builder(store).build_legacy(event_ids=["anchor"])

    assert "anchor" in result.event_ids
    assert {"past", "future"} <= result.event_ids


def test_event_anchor_replays_unknown_relation_without_inventing_a_causal_direction(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "unknown-relation.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"),
            NodeRecord("f", "file", "f", "h"),
            EdgeRecord("native-event", "p", "f", "EVENT_OPEN", 10, "h"),
        ])
        result = _builder(store).build([_evidence(
            granularity=EvidenceGranularity.EVENT, node_ids=(), event_ids=("native-event",),
        )])

    assert result.event_ids == {"native-event"}
    assert result.anchor_node_ids == {"p", "f"}


def test_control_lineage_and_common_cause_are_explicitly_configured(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "control.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"),
            NodeRecord("child", "process", "child", "h"),
            NodeRecord("sibling", "process", "sibling", "h"),
            NodeRecord("out", "file", "out", "h"),
            EdgeRecord("fork", "parent", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("sibling-fork", "parent", "sibling", "EVENT_FORK", 6, "h"),
            EdgeRecord("future", "child", "out", "EVENT_WRITE", 15, "h"),
        ])
        disabled = _builder(store, max_control_depth=1).build([_evidence(node_ids=("child",), timestamp_start=10, timestamp_end=10)])
        enabled = _builder(store, max_control_depth=1, enable_common_cause=True).build([_evidence(node_ids=("child",), timestamp_start=10, timestamp_end=10)])

    assert "fork" in disabled.event_ids
    assert "sibling-fork" not in disabled.event_ids
    assert "sibling-fork" in enabled.event_ids
    assert "sibling" in enabled.node_ids


def test_online_builder_has_no_label_or_evaluator_import_or_input() -> None:
    source = Path("tc_pruning/evidence_candidate_builder.py").read_text()
    tree = ast.parse(source)
    forbidden = ("groundtruth", "ground_truth", "pdf_critical", "attack_window", "oracle", "evaluator", "evaluation")
    tokens = {
        value.lower()
        for node in ast.walk(tree)
        for value in (
            ([node.id] if isinstance(node, ast.Name) else [])
            + ([node.attr] if isinstance(node, ast.Attribute) else [])
            + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            + ([alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
        )
    }
    assert not {token for token in tokens if any(word in token for word in forbidden)}


def test_offline_funnel_decomposes_candidate_ceiling_and_pairwise_delta() -> None:
    from tc_pruning.seed_utility_evaluation import (
        CandidateStageIds, EdgeProjection, ProjectionMode, evaluate_coverage_funnel, pairwise_candidate_delta,
    )

    funnel = evaluate_coverage_funnel(
        known_critical_event_ids={"a", "b", "c", "d"},
        stages=CandidateStageIds(
            raw_database={"a", "b", "c"}, preprocessing={"a", "b"}, inference={"a", "b"},
            scored={"a"}, native_threshold={"a"}, evidence={"a"}, candidate={"a", "x"}, final={"a"},
        ),
    )
    assert funnel["candidate"]["known_recall"] == pytest.approx(0.25)
    assert funnel["candidate_ceiling_decomposition"] == {
        "unmapped": ["d"], "preprocess": ["c"], "inference": [], "score": ["b"],
        "evidence": [], "search": [],
    }
    assert funnel["per_known_critical_edge"]["b"] == {
        "raw_database": True, "preprocessing": True, "inference": True, "scored": False,
        "native_threshold": False, "evidence": False, "candidate": False, "final": False,
    }
    projection = EdgeProjection(ProjectionMode.RAW_EVENT, merge_window_ns=10)
    left = [type("E", (), {"event_id": "a", "src": "p", "dst": "x", "relation": "EVENT_WRITE", "timestamp_ns": 1})()]
    right = left + [type("E", (), {"event_id": "b", "src": "p", "dst": "attack", "relation": "EVENT_WRITE", "timestamp_ns": 2})()]
    delta = pairwise_candidate_delta(left, right, known_critical_event_ids={"a", "b"}, known_attack_node_ids={"attack"}, projection=projection)
    assert delta["new_critical_edges"] == ["b"]
    assert delta["new_attack_nodes"] == ["attack"]
    assert delta["projected_edge_delta"] == 1
    assert delta["raw_event_delta"] == 1


def test_common_configuration_enforcement_requires_same_candidate_projection_budget_and_selectors() -> None:
    from tc_pruning.evidence_candidate_builder import CandidateSearchConfig
    from tc_pruning.seed_utility_evaluation import DetectorRunContract, enforce_common_configuration

    from tc_pruning.seed_utility_evaluation import EdgeProjection, ProjectionMode
    projection = EdgeProjection(ProjectionMode.RAW_EVENT, merge_window_ns=10)
    common = DetectorRunContract("a", CandidateSearchConfig(candidate_cap=5), projection, 5, ("A_rasp", "C_branch_fair"))
    enforce_common_configuration([common, DetectorRunContract("b", CandidateSearchConfig(candidate_cap=5), projection, 5, ("A_rasp", "C_branch_fair"))])
    incompatible = (
        DetectorRunContract("b", CandidateSearchConfig(candidate_cap=6), projection, 5, ("A_rasp", "C_branch_fair")),
        DetectorRunContract("b", CandidateSearchConfig(candidate_cap=5), EdgeProjection(ProjectionMode.DEPIMPACT_COMPATIBLE, merge_window_ns=10), 5, ("A_rasp", "C_branch_fair")),
        DetectorRunContract("b", CandidateSearchConfig(candidate_cap=5), projection, 4, ("A_rasp", "C_branch_fair")),
        DetectorRunContract("b", CandidateSearchConfig(candidate_cap=5), projection, 5, ("C_branch_fair",)),
    )
    for other in incompatible:
        with pytest.raises(ValueError, match="common configuration"):
            enforce_common_configuration([common, other])


def test_performance_fields_keep_detector_and_post_alert_costs_separate() -> None:
    from tc_pruning.seed_utility_evaluation import performance_fields

    fields = performance_fields(
        inference_seconds=1.5, candidate_seconds=0.25, final_seconds=0.1,
        peak_rss_kb=123, candidate_edges=5, final_edges=2,
    )
    assert fields["detector_inference_seconds"] == 1.5
    assert fields["candidate_reconstruction_seconds"] == 0.25
    assert fields["peak_rss_kb"] == 123
