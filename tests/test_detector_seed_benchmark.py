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
            EdgeRecord("e0", "p0", "f0", "EVENT_WRITE", 1522706861813350341, "host"),
            EdgeRecord("e1", "f0", "p1", "EVENT_READ", 1522706861813350342, "host"),
            EdgeRecord("e2", "p1", "f1", "EVENT_WRITE", 1522706861813350343, "host"),
        ))


def _edge_evidence() -> tuple[AlertEvidence, ...]:
    return (AlertEvidence(
        "fixture:e1", "Velox", "fixture", EvidenceGranularity.EDGE, 0.9, 0.9, True,
        event_ids=("e1",), node_ids=("f0", "p1"), src_uuid="f0", dst_uuid="p1",
        relation="EVENT_READ", timestamp_start=1522706861813350342, timestamp_end=1522706861813350342,
        role_hint=RoleHint.OBSERVATION,
    ),)


def _config(db: Path) -> dict[str, object]:
    return {
        "schema_version": "detector-seed-benchmark-v2",
        "fixture_mode": True,
        "dataset": "DARPA_TC_E3_CADETS",
        "database": {"path": str(db), "sha256": hashlib.sha256(db.read_bytes()).hexdigest()},
        "candidate_backend": "EvidenceDrivenCandidateBuilder",
        "candidate": {"candidate_cap": 10, "history_start_ns": 1522706861813350340, "cutoff_ns": 1523655358953968696, "max_strict_depth": 3, "max_control_depth": 0, "scan_multiplier": 2},
        "projection": {"mode": "DEPIMPACT_COMPATIBLE", "merge_window_ns": 900000000000},
        "budget": {"raw_event_cap": 3, "proxy_event_cap": 3},
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
    first_dir, second_dir = Path(first["runs"]["Velox"]["run_directory"]), Path(second["runs"]["Velox"]["run_directory"])
    for name in ("native_manifest.json", "evidence.jsonl", "mapping_audit.json", "candidate_raw_events.jsonl", "A_rasp_final.json", "C_branch_fair_final.json", "timing.json", "resolved_config.json", "artifacts.json"):
        assert (first_dir / name).is_file()
    manifest = json.loads((first_dir / "artifacts.json").read_text())
    assert all("sha256" in row for row in manifest["artifacts"])
    assert json.loads((first_dir / "resolved_config.json").read_text())["config_sha256"]
    assert json.loads((first_dir / "A_rasp_final.json").read_text())["selected_raw_event_ids"]
    assert json.loads((first_dir / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"]
    for name in ("evidence.jsonl", "mapping_audit.json", "candidate_raw_events.jsonl", "A_rasp_final.json", "C_branch_fair_final.json", "resolved_config.json"):
        assert (first_dir / name).read_bytes() == (second_dir / name).read_bytes()


def test_a_rasp_preserves_noncausal_alert_observation_without_claiming_causality(tmp_path: Path) -> None:
    from tc_pruning.detector_seed_benchmark import run_online_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    with ProvenanceStore(db) as store:
        store.ingest((EdgeRecord(
            "open", "p0", "f0", "EVENT_OPEN", 1522706861813350342, "host",
        ),))
    evidence = (AlertEvidence(
        "fixture:open", "Velox", "fixture", EvidenceGranularity.EDGE,
        0.9, 0.9, True, event_ids=("open",), node_ids=("p0", "f0"),
        src_uuid="p0", dst_uuid="f0", relation="EVENT_OPEN",
        timestamp_start=1522706861813350342,
        timestamp_end=1522706861813350342,
        role_hint=RoleHint.OBSERVATION,
    ),)

    result = run_online_benchmark(_config(db), {"Velox": evidence}, tmp_path / "result")

    assert result["status"] == "COMPLETED", result
    run_dir = Path(result["runs"]["Velox"]["run_directory"])
    selected = json.loads((run_dir / "A_rasp_final.json").read_text())
    assert "open" in selected["selected_raw_event_ids"]
    assert selected["selector_input"]["noncausal_observation_event_ids"] == ["open"]


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
    status = json.loads(Path(result["runs"]["Velox"]["attempt_directory"]).joinpath("status.json").read_text())
    assert status["stage"] == "selector:C_branch_fair"
    assert Path(result["runs"]["Velox"]["attempt_directory"]).joinpath("evidence.jsonl").is_file()
    assert Path(result["runs"]["Velox"]["attempt_directory"]).joinpath("candidate_raw_events.jsonl").is_file()


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
    evaluation = evaluate_offline_benchmark(online / "runs" / "Velox", known_critical_event_ids={"e1"}, known_attack_node_ids={"p1"})

    assert evaluation["status"] == "COMPLETED"
    only = next(iter(evaluation["runs"].values()))
    assert json.loads(Path(only["evaluation"]).read_text())["candidate"]["known_TP"] == 1


@pytest.mark.parametrize(("adapter_name", "native"), [
    ("Velox", [{"event_uuid": "e1", "src_node_uuid": "f0", "dst_node_uuid": "p1", "relation": "EVENT_READ", "loss": 4.0, "time": 1522706861813350342}]),
    ("R-CAID", [{"node_uuid": "p1", "loss": 4.0}]),
    ("NODLINK", [{"node_uuid": "p1", "loss": 4.0}]),
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
    run_dir = Path(result["runs"][adapter_name]["run_directory"])
    assert (run_dir / "evidence.jsonl").is_file()
    assert json.loads((run_dir / "A_rasp_final.json").read_text())["selected_raw_event_ids"]
    assert json.loads((run_dir / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"]


def test_missing_evidence_is_a_preserved_not_completed_attempt(tmp_path: Path) -> None:
    from tc_pruning.detector_seed_benchmark import run_online_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    result = run_online_benchmark(_config(db), {}, tmp_path / "missing")
    failed = result["runs"]["Velox"]
    assert result["status"] == "NOT_COMPLETED" and failed["stage"] == "input_evidence"
    assert json.loads((Path(failed["attempt_directory"]) / "status.json").read_text())["status"] == "NOT_COMPLETED"


def test_mapping_audit_marks_collision_ambiguous_and_does_not_admit_it(tmp_path: Path) -> None:
    from tc_pruning.detector_seed_benchmark import run_online_benchmark

    db = tmp_path / "mini.db"
    _fixture_store(db)
    with ProvenanceStore(db) as store:
        store.ingest((EdgeRecord("e1", "p0", "f1", "EVENT_WRITE", 1522706861813350344, "host"),))
    result = run_online_benchmark(_config(db), {"Velox": _edge_evidence()}, tmp_path / "collision")
    attempt = Path(result["runs"]["Velox"].get("attempt_directory", result["runs"]["Velox"].get("run_directory")))
    audit = json.loads((attempt / "mapping_audit.json").read_text())
    assert audit["ambiguous"] == 1


def test_online_module_has_no_ground_truth_or_offline_evaluation_imports() -> None:
    import tc_pruning.detector_seed_benchmark as module

    tree = ast.parse(Path(module.__file__).read_text())
    forbidden = {"groundtruth", "ground_truth", "pdf_critical", "attack_window", "funnel", "oracle", "evaluator"}
    names = {node.name.lower() for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for node in node.names}
    assert not any(part in name for name in names for part in forbidden)


def test_online_runner_ast_has_no_offline_module_or_label_argument_paths() -> None:
    import tc_pruning.detector_seed_benchmark as module

    tree = ast.parse(Path(module.__file__).read_text())
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module]
    arguments = [arg.arg.lower() for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) for arg in (*node.args.args, *node.args.kwonlyargs)]
    assert not any("evaluation" in name or "funnel" in name for name in imports)
    assert not any("ground" in name or "attack" in name for name in arguments)
