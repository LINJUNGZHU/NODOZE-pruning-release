from __future__ import annotations

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _store(path):
    with ProvenanceStore(path) as store:
        store.ingest((
            NodeRecord("p", "process", "p"), NodeRecord("f", "file", "f"),
            NodeRecord("a", "file", "a"), NodeRecord("b", "file", "b"),
            EdgeRecord("anchor", "p", "f", "EVENT_WRITE", 2, "h"),
            EdgeRecord("low", "p", "a", "EVENT_WRITE", 3, "h"),
            EdgeRecord("high", "p", "b", "EVENT_WRITE", 4, "h"),
        ))


def test_priority_reorders_only_enumerated_full_graph_edges_without_creating_an_anchor(tmp_path):
    from tc_pruning.evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder, EvidencePriority

    path = tmp_path / "priority.db"
    _store(path)
    evidence = AlertEvidence("anchor", "generic", "1", EvidenceGranularity.EVENT, 1.0, 1.0, True, event_ids=("anchor",))
    with ProvenanceStore(path) as store:
        plain = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(candidate_cap=2, history_start_ns=1, cutoff_ns=5)).build((evidence,))
        preferred = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(candidate_cap=2, history_start_ns=1, cutoff_ns=5), priority=EvidencePriority({"high": 1.0})).build((evidence,))

    assert plain.event_ids == frozenset({"anchor", "low"})
    assert preferred.event_ids == frozenset({"anchor", "high"})
    assert preferred.anchor_event_ids == frozenset({"anchor"})
    assert EvidencePriority({}).score_for_event("missing") is None


def test_velox_profiles_keep_continuous_scores_and_do_not_admit_priority_only_edges():
    from tc_pruning.detectors.velox_profiles import apply_velox_profile

    rows = (
        AlertEvidence("low", "Velox", "1", "EDGE", 1.0, .2, False, event_ids=("low",), node_ids=("a", "b"), src_uuid="a", dst_uuid="b"),
        AlertEvidence("high", "Velox", "1", "EDGE", 4.0, .9, True, event_ids=("high",), node_ids=("b", "c"), src_uuid="b", dst_uuid="c"),
    )
    vxl1, p1 = apply_velox_profile(rows, "VXL-1", frozen_development_percentile_threshold=.8)
    vxl2, p2 = apply_velox_profile(rows, "VXL-2")
    vxl3, p3 = apply_velox_profile(rows, "VXL-3", frozen_development_percentile_threshold=.8)

    assert {item.raw_score for item in vxl1} == {1.0, 4.0}
    assert [item.evidence_id for item in vxl1 if item.native_decision] == ["high"]
    assert [item.evidence_id for item in vxl2 if item.native_decision] == ["high"]
    assert p2.score_for_event("low") == 1.0 and p2.score_for_event("missing") is None
    assert [item.evidence_id for item in vxl3 if item.native_decision] == ["high"]
    assert p1.score_for_event("low") is None and p3.score_for_event("low") == .2
