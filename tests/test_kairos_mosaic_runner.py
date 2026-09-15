import ast
from dataclasses import asdict
import json
from pathlib import Path
import pytest

from scripts import run_kairos_mosaic as runner
from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.models import StoredEdge
from tc_pruning.investigation.mosaic_experiment import (
    run_online_experiment,
    validate_evidence_payload,
)


def _e(name, time, loss=2.0, queue="q"):
    return KairosEvidence(
        name, f"p{name}", f"f{name}", "EVENT_WRITE", time, loss, 0.9,
        True, (queue,), 10.0, True, queue, name, "w", "EXACT",
    )


def _edge(name, time):
    return StoredEdge(
        time, name, f"p{name}", f"f{name}", "EVENT_WRITE", time, "h",
        "process", "file", f"process:p{name}", f"file:f{name}", None,
    )


def test_online_runner_emits_all_frozen_ablation_layers_deterministically():
    evidence = (_e("e1", 1), _e("e2", 2))
    edges = tuple(_edge(row.raw_event_id, row.timestamp_ns) for row in evidence)
    config = {"selection_fraction": 0.8, "projection_window_ns": 10, "unit_size": 8}
    first = run_online_experiment(evidence, edges, scenario="06", config=config)
    second = run_online_experiment(evidence, edges, scenario="06", config=config)
    assert first == second
    assert set(first["kairos_ablations"]) == {f"K{i}" for i in range(7)}
    assert set(first["retrieval_ablations"]) == {f"R{i}" for i in range(5)}
    assert set(first["selection_ablations"]) == {f"S{i}" for i in range(6)}
    assert first["schema_version"] == "kairos-mosaic-online-v1"
    assert len(first["content_sha256"]) == 64
    assert all("projected_edge_count" in row for row in first["quality_size_frontier"])
    assert sum(len(row["added_event_ids"]) for row in first["quality_size_frontier"]) == (
        first["selection_ablations"]["S4"]["raw_event_count"]
    )


def test_online_cli_has_no_truth_or_attack_imports():
    tree = ast.parse(Path("scripts/run_kairos_mosaic.py").read_text(encoding="utf-8"))
    imports = [
        alias.name.lower() for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    ]
    assert not any(
        token in name for name in imports
        for token in ("groundtruth", "ground_truth", "pdf_critical", "evaluation", "attack")
    )


def test_online_experiment_records_detector_silence_without_fabricating_candidates():
    result = run_online_experiment((), (), scenario="13", config={})
    assert result["retrieval_ablations"]["R4"]["raw_event_count"] == 0
    assert result["selection_ablations"]["S5"]["event_ids"] == []


@pytest.mark.parametrize("field", ["ground_truth", "labels", "y_true", "is_malicious", "truth_used"])
def test_online_experiment_rejects_non_schema_config_fields(field):
    with pytest.raises(ValueError, match="unexpected config field"):
        run_online_experiment((), (), scenario="13", config={field: ["secret"]})


def test_evidence_payload_uses_strict_schema_allowlist():
    payload = {
        "schema_version": "kairos-evidence-field-v1",
        "source_hashes": {"queue_source": "0" * 64},
        "audit": {
            "native_events": 0, "identity_mapped": 0, "exact_mapped": 0,
            "tolerant_mapped": 0, "ambiguous": 0, "unmapped": 0,
            "mapping_rate": 1.0,
        },
        "mapping_sha256": "1" * 64,
        "evidence": [],
    }
    validate_evidence_payload(payload)
    payload["labels"] = []
    with pytest.raises(ValueError, match="unexpected evidence payload field"):
        validate_evidence_payload(payload)


def test_track_b_rejects_incident_context(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_kairos_mosaic.py", "--db", "unused.db", "--evidence", "unused.json",
            "--scenario", "13", "--track", "B", "--incident-dir", "forbidden",
            "--output", "unused-output.json",
        ],
    )
    with pytest.raises(SystemExit, match="2"):
        runner.main()


def test_declared_database_hash_is_verified(tmp_path):
    database = tmp_path / "db"
    database.write_bytes(b"database")
    actual = __import__("hashlib").sha256(b"database").hexdigest()
    assert runner._verified_content_hash(database, actual) == actual
    with pytest.raises(ValueError, match="database content SHA-256 mismatch"):
        runner._verified_content_hash(database, "0" * 64)
