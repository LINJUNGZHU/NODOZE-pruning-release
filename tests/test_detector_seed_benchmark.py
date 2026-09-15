from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _fixture_store(path: Path) -> None:
    with ProvenanceStore(path) as store:
        store.ingest((
            NodeRecord("p0", "process", "p0"), NodeRecord("p1", "process", "p1"),
            NodeRecord("f0", "file", "/tmp/f0"), NodeRecord("f1", "file", "/tmp/f1"),
            EdgeRecord("e0", "p0", "f0", "EVENT_WRITE", 1, "host"),
            EdgeRecord("e1", "f0", "p1", "EVENT_READ", 2, "host"),
            EdgeRecord("e2", "p1", "f1", "EVENT_WRITE", 3, "host"),
        ))


def _edge_evidence() -> tuple[AlertEvidence, ...]:
    return (AlertEvidence(
        "fixture:e1", "Velox", "fixture", EvidenceGranularity.EDGE, 0.9, 0.9, True,
        event_ids=("e1",), node_ids=("f0", "p1"), src_uuid="f0", dst_uuid="p1",
        relation="EVENT_READ", timestamp_start=2, timestamp_end=2,
        role_hint=RoleHint.OBSERVATION,
    ),)


def _config(db: Path) -> dict[str, object]:
    return {
        "schema_version": "detector-seed-benchmark-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "database": {"path": str(db), "sha256": hashlib.sha256(db.read_bytes()).hexdigest()},
        "candidate_backend": "EvidenceDrivenCandidateBuilder",
        "candidate": {"candidate_cap": 10, "max_strict_depth": 3, "max_control_depth": 0, "scan_multiplier": 2},
        "projection": {"mode": "DEPIMPACT_COMPATIBLE", "merge_window_ns": 900000000000},
        "budget": {"raw_event_cap": 3, "selection_fraction": 1.0},
        "selectors": ["A_rasp", "C_branch_fair"],
        "detectors": [{"detector_id": "Velox", "profile": "VXL-0"}],
    }


def test_online_runner_writes_complete_hashed_artifacts_and_is_deterministic(tmp_path: Path) -> None:
    from tc_pruning.detector_seed_benchmark import run_online_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    config = _config(db)
    first = run_online_benchmark(config, {"Velox": _edge_evidence()}, tmp_path / "one")
    second = run_online_benchmark(config, {"Velox": _edge_evidence()}, tmp_path / "two")

    assert first["status"] == "COMPLETED"
    for name in ("native_manifest.json", "evidence.jsonl", "mapping_audit.json", "candidate_raw_events.jsonl", "A_rasp_final.json", "C_branch_fair_final.json", "timing.json", "resolved_config.json", "artifacts.json"):
        assert (tmp_path / "one" / "Velox" / name).is_file()
    manifest = json.loads((tmp_path / "one" / "Velox" / "artifacts.json").read_text())
    assert all("sha256" in row for row in manifest["artifacts"])
    assert json.loads((tmp_path / "one" / "Velox" / "resolved_config.json").read_text())["config_sha256"]
    assert json.loads((tmp_path / "one" / "Velox" / "A_rasp_final.json").read_text())["selected_raw_event_ids"]
    assert json.loads((tmp_path / "one" / "Velox" / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"]
    for name in ("evidence.jsonl", "mapping_audit.json", "candidate_raw_events.jsonl", "A_rasp_final.json", "C_branch_fair_final.json", "resolved_config.json"):
        assert (tmp_path / "one" / "Velox" / name).read_bytes() == (tmp_path / "two" / "Velox" / name).read_bytes()


def test_online_runner_preserves_completed_artifacts_when_a_later_selector_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tc_pruning.detector_seed_benchmark as runner

    db = tmp_path / "mini.db"
    _fixture_store(db)
    config = _config(db)
    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("fixture selector failure")

    monkeypatch.setattr(runner, "_branch_fair", fail)
    result = runner.run_online_benchmark(config, {"Velox": _edge_evidence()}, tmp_path / "failed")

    assert result["status"] == "NOT_COMPLETED"
    status = json.loads((tmp_path / "failed" / "Velox" / "status.json").read_text())
    assert status["stage"] == "selector:C_branch_fair"
    assert (tmp_path / "failed" / "Velox" / "evidence.jsonl").is_file()
    assert (tmp_path / "failed" / "Velox" / "candidate_raw_events.jsonl").is_file()


@pytest.mark.parametrize("bad", [
    {"candidate_backend": "VeloxCandidateBuilder"},
    {"ground_truth_path": "forbidden.json"},
    {"detectors": [{"detector_id": "Velox", "candidate": {"candidate_cap": 2}}]},
    {"detectors": [{"detector_id": "Velox", "profile": "VXL-9"}]},
])
def test_online_config_rejects_label_paths_detector_specific_backends_and_invalid_profiles(tmp_path: Path, bad: dict[str, object]) -> None:
    from tc_pruning.detector_seed_benchmark import BenchmarkConfig

    db = tmp_path / "mini.db"
    _fixture_store(db)
    config = _config(db)
    config.update(bad)
    with pytest.raises(ValueError):
        BenchmarkConfig.from_record(config)


def test_offline_evaluation_is_the_only_known_positive_entrypoint(tmp_path: Path) -> None:
    from tc_pruning.detector_seed_benchmark import run_online_benchmark
    from tc_pruning.detector_seed_benchmark_evaluation import evaluate_offline_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    online = tmp_path / "online"
    run_online_benchmark(_config(db), {"Velox": _edge_evidence()}, online)
    evaluation = evaluate_offline_benchmark(online, known_critical_event_ids={"e1"}, known_attack_node_ids={"p1"})

    assert evaluation["status"] == "COMPLETED"
    assert json.loads((online / "Velox" / "evaluation.json").read_text())["candidate"]["known_TP"] == 1


@pytest.mark.parametrize(("adapter_name", "native"), [
    ("Velox", [{"event_uuid": "e1", "src_node_uuid": "f0", "dst_node_uuid": "p1", "loss": 2.0, "time": 2}]),
    ("R-CAID", [{"node_uuid": "p1", "loss": 2.0}]),
    ("NODLINK", [{"node_uuid": "p1", "loss": 2.0}]),
])
def test_pidsmaker_adapter_schema_paths_feed_the_same_online_runner(tmp_path: Path, adapter_name: str, native: list[dict[str, object]]) -> None:
    from tc_pruning.detectors.alert_evidence import NODLINKEvidenceAdapter, RCAIDEvidenceAdapter, VeloxEvidenceAdapter
    from tc_pruning.detector_seed_benchmark import run_online_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    adapter = {"Velox": VeloxEvidenceAdapter, "R-CAID": RCAIDEvidenceAdapter, "NODLINK": NODLINKEvidenceAdapter}[adapter_name](version="fixture")
    evidence = adapter.provide(native, [{"loss": 1.0}, {"loss": 3.0}])
    config = _config(db)
    config["detectors"] = [{"detector_id": adapter_name, **({"profile": "VXL-0"} if adapter_name == "Velox" else {})}]

    result = run_online_benchmark(config, {adapter_name: evidence}, tmp_path / adapter_name)

    assert result["status"] == "COMPLETED"
    assert (tmp_path / adapter_name / adapter_name / "evidence.jsonl").is_file()


def test_online_module_has_no_ground_truth_or_offline_evaluation_imports() -> None:
    import tc_pruning.detector_seed_benchmark as module

    tree = ast.parse(Path(module.__file__).read_text())
    forbidden = {"groundtruth", "ground_truth", "pdf_critical", "attack_window", "funnel", "oracle", "evaluator"}
    names = {node.name.lower() for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for node in node.names}
    assert not any(part in name for name in names for part in forbidden)
