from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from tc_pruning.evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from tc_pruning.models import EdgeRecord, NodeRecord, StoredEdge
from tc_pruning.store import ProvenanceStore


def _node(node: str, *, evidence_id: str = "seed", detector: str = "A", start: int | None = 10, end: int | None = 10) -> AlertEvidence:
    return AlertEvidence(
        evidence_id=evidence_id, detector_id=detector, detector_version="v", granularity=EvidenceGranularity.NODE,
        raw_score=0.0, calibrated_score=0.5, native_decision=True, node_ids=(node,),
        timestamp_start=start, timestamp_end=end, role_hint=RoleHint.UNKNOWN,
    )


def _builder(store: ProvenanceStore, **changes: object) -> EvidenceDrivenCandidateBuilder:
    values: dict[str, object] = {"candidate_cap": 20, "max_strict_depth": 2}
    values.update(changes)
    return EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(**values))


def test_cadets_semantics_fail_closed_on_endpoint_type_mismatch(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "types.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"), NodeRecord("r", "file", "r", "h"),
            NodeRecord("w", "file", "w", "h"), NodeRecord("exe", "file", "exe", "h"),
            NodeRecord("child", "process", "child", "h"), NodeRecord("bad", "file", "bad", "h"),
            EdgeRecord("read", "r", "p", "EVENT_READ", 1, "h"),
            EdgeRecord("write", "p", "w", "EVENT_WRITE", 2, "h"),
            EdgeRecord("execute", "p", "exe", "EVENT_EXECUTE", 3, "h"),
            EdgeRecord("fork", "p", "child", "EVENT_FORK", 4, "h"),
            EdgeRecord("invalid-read", "p", "bad", "EVENT_READ", 5, "h"),
            EdgeRecord("invalid-fork", "bad", "p", "EVENT_FORK", 6, "h"),
        ])
        result = _builder(store, history_start_ns=0, cutoff_ns=10).build([_node("p", start=None, end=None)])

    assert {"read", "write", "execute", "fork"} <= result.event_ids
    assert not {"invalid-read", "invalid-fork"} & result.event_ids


def test_interval_bounds_use_start_for_backward_and_end_for_forward(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "interval.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"), *(NodeRecord(name, "file", name, "h") for name in ("pre", "inside", "post")),
            EdgeRecord("pre", "pre", "p", "EVENT_READ", 5, "h"),
            EdgeRecord("inside", "inside", "p", "EVENT_READ", 15, "h"),
            EdgeRecord("post", "p", "post", "EVENT_WRITE", 25, "h"),
        ])
        result = _builder(store).build([_node("p", start=10, end=20)])

    assert {"pre", "post"} <= result.event_ids
    assert "inside" not in result.event_ids


def test_each_event_member_starts_at_its_own_raw_timestamp(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "events.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"), NodeRecord("a", "file", "a", "h"), NodeRecord("b", "file", "b", "h"), NodeRecord("out", "file", "out", "h"),
            EdgeRecord("early", "p", "a", "EVENT_WRITE", 10, "h"),
            EdgeRecord("late", "p", "b", "EVENT_WRITE", 100, "h"),
            EdgeRecord("late-successor", "p", "out", "EVENT_WRITE", 110, "h"),
        ])
        evidence = AlertEvidence("events", "A", "v", EvidenceGranularity.EVENT, 1.0, 0.5, True, event_ids=("early", "late"), node_ids=("p",))
        result = _builder(store, max_strict_depth=1).build([evidence])

    assert "late-successor" in result.event_ids


def test_timeless_node_fails_closed_without_common_window(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "timeless.db") as store:
        store.ingest([NodeRecord("p", "process", "p", "h"), NodeRecord("f", "file", "f", "h"), EdgeRecord("future", "p", "f", "EVENT_WRITE", 99, "h")])
        result = _builder(store).build([_node("p", start=None, end=None)])

    assert result.event_ids == set()
    assert result.performance.unexpanded_anchor_count == 1
    assert result.performance.unexpanded_anchor_reason == "MISSING_TIME_CHECKPOINT"


def test_control_rejects_future_parent_and_strict_process_becomes_control_anchor(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "control-time.db") as store:
        store.ingest([
            NodeRecord("root", "process", "root", "h"), NodeRecord("p", "process", "p", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("out", "file", "out", "h"),
            EdgeRecord("strict-fork", "p", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("parent", "root", "p", "EVENT_FORK", 4, "h"),
            EdgeRecord("future-parent", "root", "child", "EVENT_FORK", 15, "h"),
            EdgeRecord("future", "child", "out", "EVENT_WRITE", 20, "h"),
        ])
        result = _builder(store, max_control_depth=2).build([_node("child", start=10, end=10)])

    assert {"strict-fork", "parent"} <= result.event_ids
    assert "future-parent" not in result.event_ids


def test_control_parent_starts_remaining_strict_forward_reconstruction(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "control-continue.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("out", "file", "out", "h"),
            EdgeRecord("fork", "parent", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("parent-write", "parent", "out", "EVENT_WRITE", 6, "h"),
        ])
        result = _builder(store, max_control_depth=1, max_strict_depth=2).build([_node("child", start=10, end=10)])

    assert "parent-write" in result.event_ids


def test_detector_and_evidence_identity_cannot_change_cap_sensitive_result(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "blind.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"), NodeRecord("q", "process", "q", "h"), NodeRecord("pf", "file", "pf", "h"), NodeRecord("qf", "file", "qf", "h"),
            EdgeRecord("p-edge", "p", "pf", "EVENT_WRITE", 11, "h"), EdgeRecord("q-edge", "q", "qf", "EVENT_WRITE", 11, "h"),
        ])
        first = _builder(store, candidate_cap=1).build([_node("p", evidence_id="z", detector="One"), _node("q", evidence_id="a", detector="Two")])
        second = _builder(store, candidate_cap=1).build([_node("p", evidence_id="a-different", detector="Else"), _node("q", evidence_id="z-different", detector="Other")])

    assert first.event_ids == second.event_ids == {"p-edge"}


def test_cap_holds_for_multi_anchor_control_and_common_cause_paths(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "cap.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"), NodeRecord("a", "process", "a", "h"), NodeRecord("b", "process", "b", "h"), NodeRecord("sibling", "process", "sibling", "h"),
            EdgeRecord("parent-a", "parent", "a", "EVENT_FORK", 3, "h"), EdgeRecord("parent-b", "parent", "b", "EVENT_FORK", 4, "h"), EdgeRecord("sibling", "parent", "sibling", "EVENT_FORK", 5, "h"),
        ])
        result = _builder(store, candidate_cap=2, max_control_depth=1, enable_common_cause=True).build([_node("a"), _node("b")])

    assert len(result.edges) <= 2
    assert result.stop_reason == "CAP_REACHED"


def test_online_isolation_scan_checks_argument_names() -> None:
    tree = ast.parse(Path("tc_pruning/evidence_candidate_builder.py").read_text())
    forbidden = ("groundtruth", "ground_truth", "pdf_critical", "attack_window", "oracle", "evaluator", "evaluation")
    args = {node.arg.lower() for node in ast.walk(tree) if isinstance(node, ast.arg)}
    assert not {value for value in args if any(token in value for token in forbidden)}


def test_build_legacy_equals_equivalent_canonical_event_evidence(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "legacy.db") as store:
        store.ingest([NodeRecord("p", "process", "p", "h"), NodeRecord("f", "file", "f", "h"), EdgeRecord("event", "p", "f", "EVENT_WRITE", 10, "h")])
        builder = _builder(store, history_start_ns=0, cutoff_ns=20)
        legacy = builder.build_legacy(event_ids=("event",))
        canonical = builder.build([AlertEvidence("canonical", "anything", "v", EvidenceGranularity.EVENT, None, 0.0, True, event_ids=("event",), role_hint=RoleHint.UNKNOWN)])

    assert legacy.event_ids == canonical.event_ids
