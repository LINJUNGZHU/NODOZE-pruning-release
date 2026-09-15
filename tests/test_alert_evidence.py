from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tc_pruning.detectors.alert_evidence import (
    AlertEvidence, CausalAgreement, DevelopmentCalibrator, EvidenceGranularity,
    KairosEvidenceProvider, MappingQuality, OrthrusEvidenceProvider, RoleHint,
    dump_evidence_jsonl, fuse_same_object_noisy_or, load_evidence_jsonl,
)
from tc_pruning.detectors.kairos_adapter import KairosEvidence


def _event(**changes: object) -> AlertEvidence:
    values: dict[str, object] = {
        "evidence_id": "velox:event-1", "detector_id": "Velox", "detector_version": "test",
        "granularity": "event", "raw_score": 2.0, "calibrated_score": 0.5,
        "native_decision": True, "event_ids": ("event-1",), "node_ids": ("node-a", "node-b"),
        "src_uuid": "node-a", "dst_uuid": "node-b", "role_hint": "observation",
        "mapping_quality": "exact",
    }
    values.update(changes)
    return AlertEvidence(**values)


def test_detector_package_exposes_evidence_contract() -> None:
    from tc_pruning.detectors import AlertEvidence as ExportedEvidence
    assert ExportedEvidence is AlertEvidence


def test_contract_has_every_required_granularity_role_and_canonical_fields() -> None:
    assert {item.value for item in EvidenceGranularity} == {
        "EVENT", "EDGE", "NODE", "SUBGRAPH", "PATH", "STRUCTURAL_GRAPH",
    }
    assert {item.value for item in RoleHint} == {
        "ROOT", "ENTRY", "OBSERVATION", "INTERIOR", "EXIT", "TERMINAL", "UNKNOWN",
    }
    node = _event(granularity="node", event_ids=(), node_ids=("node-a",), src_uuid=None, dst_uuid=None)
    subgraph = _event(granularity="subgraph", structural_context={"native_members": ["x"]})
    path = _event(granularity="path", structural_context={"native_members": ["x"]})
    graph = _event(granularity="structural_graph", structural_context={"native_members": ["x"]})
    for item in (_event(), _event(granularity="edge"), node, subgraph, path, graph):
        record = item.to_record()
        for field in (
            "detector_id", "raw_score", "calibrated_score", "event_ids", "node_ids",
            "supporting_event_ids", "structural_context", "timestamp_start", "timestamp_end",
            "src_uuid", "dst_uuid", "relation", "mapping_quality", "detector_metadata",
        ):
            assert field in record
    with pytest.raises(ValueError, match="event_ids"):
        _event(event_ids=())
    with pytest.raises(ValueError, match="structural_context"):
        _event(granularity="PATH", structural_context={})


def test_json_is_strict_allowlisted_deeply_immutable_and_rejects_duplicate_dump_ids(tmp_path: Path) -> None:
    evidence = _event(detector_metadata={"nested": {"items": ["x"]}})
    with pytest.raises(TypeError):
        evidence.detector_metadata["new"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        evidence.detector_metadata["nested"]["new"] = 1  # type: ignore[index]
    record = evidence.to_record()
    record["native_decision"] = "true"
    with pytest.raises(ValueError, match="native_decision"):
        AlertEvidence.from_record(record)
    record = evidence.to_record()
    record["calibrated_score"] = None
    with pytest.raises(ValueError, match="calibrated_score"):
        AlertEvidence.from_record(record)
    record = evidence.to_record()
    record["unknown"] = 1
    with pytest.raises(ValueError, match="unknown"):
        AlertEvidence.from_record(record)
    with pytest.raises(ValueError, match="duplicate evidence_id"):
        dump_evidence_jsonl(tmp_path / "evidence.jsonl", [evidence, evidence])


def test_jsonl_round_trip_is_canonical_and_preserves_optional_percentiles(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    dump_evidence_jsonl(path, [_event(evidence_id="z", development_percentile=None, query_local_percentile=None), _event(evidence_id="a")])
    assert path.read_text().splitlines()[0].startswith('{"calibrated_score"')
    restored = load_evidence_jsonl(path)
    assert [item.evidence_id for item in restored] == ["a", "z"]
    assert restored[1].development_percentile is None


def test_development_calibration_is_tie_stable() -> None:
    calibration = DevelopmentCalibrator.fit([3.0, 1.0, 1.0, 2.0])
    assert calibration.percentile(1.0) == pytest.approx(0.5)
    assert calibration.percentile(2.0) == pytest.approx(0.75)
    assert calibration.percentile(3.0) == pytest.approx(1.0)


def test_orthrus_requires_frozen_development_rows_and_preserves_artifact_version(tmp_path: Path) -> None:
    source = tmp_path / "alerts.json"
    source.write_text(json.dumps([{
        "alert_id": "alert", "detector_version": "4.2", "alert_score": 4.0, "threshold": 3.0,
        "seed_event_ids": ["event"], "supporting_event_ids": ["pids-observation"],
        "event_time_end": 1_523_027_699_836_180_163,
    }]))
    with pytest.raises(ValueError, match="development"):
        OrthrusEvidenceProvider().provide(source)
    evidence = OrthrusEvidenceProvider().provide(source, [{"loss": 1.0}, {"loss": 3.0}])[0]
    assert evidence.detector_version == "4.2"
    assert evidence.supporting_event_ids == ()
    assert evidence.detector_metadata["native_supporting_observation_ids"] == ("pids-observation",)
    assert evidence.query_local_percentile == pytest.approx(1.0)


def test_orthrus_test_rows_cannot_change_development_percentile(tmp_path: Path) -> None:
    def row(score: float) -> dict[str, object]:
        return {
            "alert_id": str(score), "detector_version": "4", "alert_score": score, "threshold": 0,
            "seed_event_ids": [str(score)], "event_time_end": 1_523_027_699_836_180_163,
        }
    left, right = tmp_path / "left.json", tmp_path / "right.json"
    left.write_text(json.dumps([row(2.0)]))
    right.write_text(json.dumps([row(2.0), row(100.0)]))
    dev = [{"loss": 1.0}, {"loss": 3.0}]
    assert OrthrusEvidenceProvider().provide(left, dev)[0].development_percentile == pytest.approx(0.5)
    assert OrthrusEvidenceProvider().provide(right, dev)[0].development_percentile == pytest.approx(0.5)


def test_orthrus_local_percentile_is_day_scoped_not_file_scoped(tmp_path: Path) -> None:
    source = tmp_path / "alerts.json"
    source.write_text(json.dumps([
        {"alert_id": "one", "detector_version": "4", "alert_score": 2.0, "threshold": 0, "seed_event_ids": ["one"], "event_time_end": 1_523_027_699_836_180_163},
        {"alert_id": "two", "detector_version": "4", "alert_score": 100.0, "threshold": 0, "seed_event_ids": ["two"], "event_time_end": 1_523_114_099_836_180_163},
    ]))
    evidence = OrthrusEvidenceProvider().provide(source, [{"loss": 1.0}])
    assert {item.query_local_percentile for item in evidence} == {1.0}


def test_kairos_requires_development_scores_and_preserves_duplicate_native_observations() -> None:
    first = KairosEvidence("event", "src", "dst", "EVENT_READ", 10, 2.0, 0.4, True, ("queue-a",), 0.7, True, "component-a", "native-a", "window-a", "IDENTITY")
    second = KairosEvidence("event", "src", "dst", "EVENT_READ", 11, 3.0, 0.8, True, ("queue-b",), 0.8, False, None, "native-b", "window-a", "TOLERANT")
    with pytest.raises(ValueError, match="development"):
        KairosEvidenceProvider().provide([first])
    evidence = KairosEvidenceProvider().provide([first, second], [1.0, 3.0])
    assert len(evidence) == 2
    assert len({item.evidence_id for item in evidence}) == 2
    by_native = {item.detector_metadata["native_id"]: item for item in evidence}
    assert by_native["native-a"].mapping_quality is MappingQuality.EXACT
    assert by_native["native-b"].mapping_quality is MappingQuality.TOLERANT
    assert by_native["native-a"].detector_metadata["queue_ids"] == ("queue-a",)
    assert by_native["native-a"].detector_metadata["loss_percentile"] == pytest.approx(0.4)
    assert all(item.query_local_percentile is not None for item in evidence)


def test_fusion_uses_one_contribution_per_detector_and_never_fabricates_percentiles() -> None:
    a_low = _event(evidence_id="a-low", detector_id="A", calibrated_score=0.2)
    a_high = _event(evidence_id="a-high", detector_id="A", calibrated_score=0.9)
    b = _event(evidence_id="b", detector_id="B", calibrated_score=0.5)
    fused = fuse_same_object_noisy_or([a_low, b, a_high])
    assert fused.calibrated_score == pytest.approx(0.95)
    assert fused.development_percentile is None
    assert fused.query_local_percentile is None
    assert fused.detector_metadata["per_detector_contributions"]["A"]["calibrated_score"] == pytest.approx(0.9)
    assert fused.detector_metadata["per_detector_contributions"]["A"]["source_evidence_ids"] == ("a-high", "a-low")


def test_fusion_makes_endpoint_conflicts_explicit_without_creating_a_fact() -> None:
    left = _event(evidence_id="left", detector_id="A", src_uuid="a")
    right = _event(evidence_id="right", detector_id="B", src_uuid="different")
    fused = fuse_same_object_noisy_or([left, right])
    assert fused.src_uuid is None
    assert fused.detector_metadata["identity_conflicts"]["src_uuid"] == ("a", "different")


def test_mixed_kairos_edge_and_orthrus_event_fusion_downshifts_to_event_regardless_of_order(tmp_path: Path) -> None:
    kairos_native = KairosEvidence(
        "shared-event", "src", "dst", "EVENT_READ", 10, 3.0, 0.8, True,
        ("queue",), 0.7, False, None, "native", "window", "IDENTITY",
    )
    kairos = KairosEvidenceProvider().provide([kairos_native], [1.0, 3.0])[0]
    source = tmp_path / "alerts.json"
    source.write_text(json.dumps([{
        "alert_id": "alert", "detector_version": "4", "alert_score": 2.0, "threshold": 1.0,
        "seed_event_ids": ["shared-event"], "event_time_end": 1_523_027_699_836_180_163,
    }]))
    orthrus = OrthrusEvidenceProvider().provide(source, [{"loss": 1.0}, {"loss": 3.0}])[0]
    fused_forward = fuse_same_object_noisy_or([kairos, orthrus])
    fused_reverse = fuse_same_object_noisy_or([orthrus, kairos])
    for fused in (fused_forward, fused_reverse):
        assert fused.granularity is EvidenceGranularity.EVENT
        assert fused.src_uuid is None
        assert fused.dst_uuid is None
        assert fused.detector_metadata["identity_conflicts"]["src_uuid"] == (None, "src")


def test_same_object_node_fusion_keeps_node_granularity() -> None:
    left = _event(evidence_id="left", detector_id="A", granularity="NODE", event_ids=(), node_ids=("node",), src_uuid=None, dst_uuid=None)
    right = _event(evidence_id="right", detector_id="B", granularity="NODE", event_ids=(), node_ids=("node",), src_uuid=None, dst_uuid=None)
    fused = fuse_same_object_noisy_or([left, right])
    assert fused.granularity is EvidenceGranularity.NODE
    assert fused.node_ids == ("node",)


def test_structural_object_key_includes_event_and_node_members() -> None:
    first = _event(granularity="STRUCTURAL_GRAPH", structural_context={"native_members": ["x"]}, event_ids=("e",), node_ids=("n1",))
    second = _event(evidence_id="other", granularity="STRUCTURAL_GRAPH", structural_context={"native_members": ["x"]}, event_ids=("e",), node_ids=("n2",))
    assert first.object_key != second.object_key


def test_agreement_is_immutable_reliability_only_and_cannot_create_provenance_facts() -> None:
    agreement = CausalAgreement.from_evidence([_event(evidence_id="one"), _event(evidence_id="two", detector_id="KAIROS")])
    assert agreement.reliability_for("one") == pytest.approx(1.0)
    assert agreement.provenance_facts() == ()
    with pytest.raises(TypeError):
        agreement.reliability["one"] = 0.0  # type: ignore[index]
    assert not hasattr(agreement, "nodes")
    assert not hasattr(agreement, "edges")


def _forbidden_ast_occurrences(tree: ast.AST) -> set[str]:
    forbidden = ("groundtruth", "ground_truth", "pdf_critical", "attack_window", "oracle", "evaluator", "evaluation")
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None:
                values.add(node.module.lower())
            values.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value.lower())
        elif isinstance(node, ast.Name):
            values.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            values.add(node.attr.lower())
        elif isinstance(node, ast.keyword) and node.arg is not None:
            values.add(node.arg.lower())
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = node.args
            values.update(argument.arg.lower() for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs))
            if arguments.vararg is not None:
                values.add(arguments.vararg.arg.lower())
            if arguments.kwarg is not None:
                values.add(arguments.kwarg.arg.lower())
    return {value for value in values if any(token in value for token in forbidden)}


def test_isolation_ast_scan_detects_synthetic_forbidden_parameters_attributes_keywords_and_calls() -> None:
    synthetic = ast.parse("def run(ground_truth, *, attack_window=None): return oracle.evaluator(pdf_critical=ground_truth)")
    assert {"ground_truth", "attack_window", "oracle", "evaluator", "pdf_critical"} <= _forbidden_ast_occurrences(synthetic)


def test_isolation_ast_scan_detects_import_and_importfrom_module_leaks() -> None:
    synthetic = ast.parse(
        "import tc_pruning.groundtruth_labels as labels\n"
        "from tc_pruning.evaluation import load_labels"
    )
    assert {"tc_pruning.groundtruth_labels", "tc_pruning.evaluation"} <= _forbidden_ast_occurrences(synthetic)


def test_online_module_has_no_ground_truth_or_evaluator_dependency_or_input() -> None:
    tree = ast.parse(Path("tc_pruning/detectors/alert_evidence.py").read_text())
    assert _forbidden_ast_occurrences(tree) == set()
