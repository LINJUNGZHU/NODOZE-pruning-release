from __future__ import annotations

import hashlib

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from tc_pruning.evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.seed_utility_evaluation import CandidateSnapshot, EdgeProjection, ProjectionMode, pairwise_candidate_delta
from tc_pruning.store import ProvenanceStore


def _node(node: str, time: int = 10, **changes: object) -> AlertEvidence:
    values: dict[str, object] = dict(evidence_id="seed", detector_id="A", detector_version="v", granularity=EvidenceGranularity.NODE, raw_score=0.0, calibrated_score=0.5, native_decision=True, node_ids=(node,), timestamp_start=time, timestamp_end=time, role_hint=RoleHint.UNKNOWN)
    values.update(changes)
    return AlertEvidence(**values)


def _build(store: ProvenanceStore, evidence: list[AlertEvidence], **changes: object):
    values: dict[str, object] = dict(candidate_cap=20, max_strict_depth=4, max_control_depth=2)
    values.update(changes)
    return EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(**values)).build(evidence)


def test_control_and_continuation_share_admission_cap(tmp_path):
    with ProvenanceStore(tmp_path / "cap-control.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("out", "file", "out", "h"),
            EdgeRecord("control", "parent", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("continuation", "parent", "out", "EVENT_WRITE", 6, "h"),
        ])
        result = _build(store, [_node("child", role_hint=RoleHint.ENTRY)], candidate_cap=1)

    assert len(result.edges) == 1
    assert "control" in result.event_ids
    assert "continuation" not in result.event_ids


def test_forward_discovered_process_uses_discovery_time_for_parent_lookup(tmp_path):
    with ProvenanceStore(tmp_path / "forward-control.db") as store:
        store.ingest([
            NodeRecord("resource", "file", "resource", "h"), NodeRecord("process", "process", "process", "h"), NodeRecord("past", "process", "past", "h"), NodeRecord("future", "process", "future", "h"),
            EdgeRecord("read", "resource", "process", "EVENT_READ", 5, "h"),
            EdgeRecord("past-parent", "past", "process", "EVENT_FORK", 1, "h"),
            EdgeRecord("equal-parent", "past", "process", "EVENT_FORK", 5, "h"),
            EdgeRecord("future-parent", "future", "process", "EVENT_FORK", 6, "h"),
        ])
        result = _build(store, [_node("resource", time=0)], history_start_ns=0, cutoff_ns=20)

    assert {"read", "past-parent"} <= result.event_ids
    assert not {"equal-parent", "future-parent"} & result.event_ids


def test_control_continuation_walks_multiple_hops_and_stops_at_remaining_depth(tmp_path):
    with ProvenanceStore(tmp_path / "continuation.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("one", "file", "one", "h"), NodeRecord("two", "process", "two", "h"), NodeRecord("three", "file", "three", "h"),
            EdgeRecord("control", "parent", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("one", "parent", "one", "EVENT_WRITE", 6, "h"),
            EdgeRecord("two", "one", "two", "EVENT_READ", 7, "h"),
            EdgeRecord("three", "two", "three", "EVENT_WRITE", 8, "h"),
        ])
        full = _build(store, [_node("child")], max_strict_depth=3)
        shallow = _build(store, [_node("child")], max_strict_depth=1)

    assert {"one", "two", "three"} <= full.event_ids
    assert "one" in shallow.event_ids and not {"two", "three"} & shallow.event_ids


def test_canonical_identity_is_total_for_mixed_optional_values(tmp_path):
    with ProvenanceStore(tmp_path / "optional.db") as store:
        store.ingest([NodeRecord("p", "process", "p", "h"), NodeRecord("f", "file", "f", "h"), EdgeRecord("edge", "p", "f", "EVENT_WRITE", 11, "h")])
        first = _node("p", evidence_id="one", detector_id="One", timestamp_start=None, timestamp_end=None)
        second = _node("p", evidence_id="two", detector_id="Two", timestamp_start=10, timestamp_end=10)
        result = _build(store, [first, second], candidate_cap=1, history_start_ns=0, cutoff_ns=20)

    assert result.event_ids == {"edge"}


def test_common_cause_is_unique_increment_and_invalid_branches_do_not_enter(tmp_path):
    with ProvenanceStore(tmp_path / "common.db") as store:
        store.ingest([
            NodeRecord("parent", "process", "parent", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("sibling", "process", "sibling", "h"), NodeRecord("bad", "file", "bad", "h"),
            EdgeRecord("branch", "parent", "child", "EVENT_FORK", 5, "h"), EdgeRecord("sibling", "parent", "sibling", "EVENT_FORK", 6, "h"),
            EdgeRecord("bad-type", "parent", "bad", "EVENT_FORK", 7, "h"), EdgeRecord("bad-time", "parent", "sibling", "EVENT_FORK", 15, "h"),
        ])
        disabled = _build(store, [_node("child")], candidate_cap=2, enable_common_cause=False)
        enabled = _build(store, [_node("child")], candidate_cap=2, enable_common_cause=True)

    assert "sibling" not in disabled.event_ids
    assert "sibling" in enabled.event_ids
    assert not {"bad-type", "bad-time"} & enabled.event_ids
    assert len(enabled.edges) <= 2


def test_offline_label_mutation_cannot_change_builder_candidate_hash(tmp_path):
    with ProvenanceStore(tmp_path / "isolation.db") as store:
        store.ingest([NodeRecord("p", "process", "p", "h"), NodeRecord("f", "file", "f", "h"), EdgeRecord("edge", "p", "f", "EVENT_WRITE", 11, "h")])
        builder = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(candidate_cap=3))
        before = builder.build([_node("p")])
        pairwise_candidate_delta(CandidateSnapshot(before.edges, before.node_ids), CandidateSnapshot((), frozenset({"label-only"})), known_critical_event_ids={"edge"}, known_attack_node_ids={"label-only"}, projection=EdgeProjection(ProjectionMode.RAW_EVENT, merge_window_ns=10))
        after = builder.build([_node("p")])

    digest = lambda result: hashlib.sha256("\x1f".join(sorted(result.event_ids | result.node_ids)).encode()).hexdigest()
    assert digest(before) == digest(after)
