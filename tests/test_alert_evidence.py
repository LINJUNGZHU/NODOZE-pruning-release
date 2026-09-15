from __future__ import annotations

import csv
from pathlib import Path

import pytest

from tc_pruning.detectors.alert_evidence import (
    AlertEvidence,
    CausalAgreement,
    DevelopmentCalibrator,
    EvidenceGranularity,
    NODLINKEvidenceAdapter,
    OrthrusEvidenceProvider,
    RCAIDEvidenceAdapter,
    RoleHint,
    VeloxEvidenceAdapter,
    dump_evidence_jsonl,
    fuse_same_object_noisy_or,
    load_evidence_jsonl,
)


def test_detector_package_exposes_evidence_contract() -> None:
    from tc_pruning.detectors import AlertEvidence as ExportedEvidence

    assert ExportedEvidence is AlertEvidence


def _edge(**changes: object) -> AlertEvidence:
    values: dict[str, object] = {
        "evidence_id": "velox:event-1",
        "detector_name": "Velox",
        "detector_version": "test",
        "granularity": EvidenceGranularity.EVENT,
        "raw_score": 2.0,
        "calibrated_score": 0.5,
        "native_decision": True,
        "event_uuid": "event-1",
        "src_node_uuid": "node-a",
        "dst_node_uuid": "node-b",
        "role_hint": RoleHint.OBSERVATION,
    }
    values.update(changes)
    return AlertEvidence(**values)


def test_evidence_validation_and_canonical_jsonl_round_trip(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="event_uuid"):
        _edge(event_uuid=None)
    with pytest.raises(ValueError, match="calibrated_score"):
        _edge(calibrated_score=1.01)
    with pytest.raises(ValueError, match="finite"):
        _edge(raw_score=float("nan"))

    path = tmp_path / "evidence.jsonl"
    rows = [_edge(evidence_id="z", metadata={"z": 2, "a": 1}), _edge(evidence_id="a")]
    dump_evidence_jsonl(path, rows)
    assert path.read_text().splitlines()[0].startswith('{"calibrated_score"')
    assert [row.evidence_id for row in load_evidence_jsonl(path)] == ["a", "z"]


def test_node_adapters_preserve_only_native_node_evidence_and_never_invent_root_metadata() -> None:
    dev = [{"loss": "1.0"}, {"loss": "3.0"}]
    row = {"loss": "4.0", "node": "7", "node_uuid": "native-node", "root_cause": "fake"}

    rcaid = RCAIDEvidenceAdapter(version="test").adapt([row], dev)[0]
    nodlink = NODLINKEvidenceAdapter(version="test").adapt([row], dev)[0]

    for evidence in (rcaid, nodlink):
        assert evidence.granularity is EvidenceGranularity.NODE
        assert evidence.node_uuid == "native-node"
        assert evidence.event_uuid is None
        assert evidence.src_node_uuid is None
        assert evidence.dst_node_uuid is None
        assert "root" not in " ".join(evidence.metadata).lower()
        assert evidence.native_decision


def test_velox_uses_development_threshold_and_identity_columns_consistently(tmp_path: Path) -> None:
    source = tmp_path / "velox.csv"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "loss", "event_uuid", "src_node_uuid", "dst_node_uuid", "time", "edge_type",
        ])
        writer.writeheader()
        writer.writerows([
            {"loss": "3.0", "event_uuid": "equal", "src_node_uuid": "a", "dst_node_uuid": "b", "time": "4", "edge_type": "2"},
            {"loss": "3.1", "event_uuid": "above", "src_node_uuid": "a", "dst_node_uuid": "b", "time": "5", "edge_type": "2"},
        ])
    evidence = VeloxEvidenceAdapter(version="test").adapt(source, [{"loss": "1"}, {"loss": "3"}])
    decisions = {item.event_uuid: item.native_decision for item in evidence}
    assert decisions == {"equal": False, "above": True}
    assert all(item.relation == "EVENT_EXECUTE" for item in evidence)


def test_adapter_rejects_duplicate_native_object_identity() -> None:
    rows = [
        {"loss": "4", "event_uuid": "event", "src_node_uuid": "a", "dst_node_uuid": "b"},
        {"loss": "5", "event_uuid": "event", "src_node_uuid": "a", "dst_node_uuid": "b"},
    ]
    with pytest.raises(ValueError, match="duplicate evidence_id"):
        VeloxEvidenceAdapter(version="test").adapt(rows, [{"loss": "1"}])


def test_orthrus_keeps_distinct_native_alerts_for_one_underlying_event(tmp_path: Path) -> None:
    source = tmp_path / "alerts.json"
    source.write_text(__import__("json").dumps([
        {"alert_id": "first", "alert_score": 4, "threshold": 3, "seed_event_ids": ["event"]},
        {"alert_id": "second", "alert_score": 5, "threshold": 3, "seed_event_ids": ["event"]},
    ]))
    evidence = OrthrusEvidenceProvider().provide(source)
    assert len(evidence) == 2
    assert len({item.evidence_id for item in evidence}) == 2
    assert {item.object_key for item in evidence} == {("event", "event")}


def test_development_calibration_is_deterministic_and_ties_share_a_percentile() -> None:
    calibration = DevelopmentCalibrator.fit([3.0, 1.0, 1.0, 2.0])
    assert calibration.percentile(1.0) == pytest.approx(0.5)
    assert calibration.percentile(2.0) == pytest.approx(0.75)
    assert calibration.percentile(3.0) == pytest.approx(1.0)
    assert calibration.percentile(1.0, scope_values=[1.0, 1.0, 2.0]) == pytest.approx(2 / 3)


def test_adapter_records_development_and_query_local_percentiles() -> None:
    rows = [
        {"loss": "2", "node": "1", "node_uuid": "node-1", "query_id": "q"},
        {"loss": "4", "node": "2", "node_uuid": "node-2", "query_id": "q"},
    ]
    evidence = RCAIDEvidenceAdapter(version="test").adapt(rows, [{"loss": "1"}, {"loss": "3"}])
    by_node = {item.node_uuid: item for item in evidence}
    assert by_node["node-1"].development_percentile == pytest.approx(1 / 2)
    assert by_node["node-1"].query_local_percentile == pytest.approx(1 / 2)
    assert by_node["node-2"].query_local_percentile == pytest.approx(1.0)


def test_noisy_or_fuses_only_the_same_underlying_object_deterministically() -> None:
    first = _edge(evidence_id="z", calibrated_score=0.2)
    second = _edge(evidence_id="a", calibrated_score=0.5, detector_name="KAIROS")
    fused = fuse_same_object_noisy_or([first, second])
    assert fused.calibrated_score == pytest.approx(0.6)
    assert fused.metadata["source_evidence_ids"] == ["a", "z"]
    assert fused.event_uuid == "event-1"
    with pytest.raises(ValueError, match="same underlying object"):
        fuse_same_object_noisy_or([first, _edge(event_uuid="event-2")])


def test_agreement_is_reliability_only_and_cannot_create_provenance_facts() -> None:
    first = _edge(evidence_id="one")
    second = _edge(evidence_id="two", detector_name="KAIROS")
    agreement = CausalAgreement.from_evidence([first, second])
    assert agreement.reliability_for("one") == pytest.approx(1.0)
    assert agreement.provenance_facts() == ()
    assert not hasattr(agreement, "nodes")
    assert not hasattr(agreement, "edges")


def test_online_alert_evidence_module_does_not_import_or_read_ground_truth_inputs() -> None:
    source = Path("tc_pruning/detectors/alert_evidence.py").read_text().lower()
    assert "groundtruth" not in source
    assert "attack_window" not in source
    assert "pdf_critical" not in source
