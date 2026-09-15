import ast
from dataclasses import asdict
import json
from pathlib import Path

from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.models import StoredEdge
from tc_pruning.investigation.mosaic_experiment import run_online_experiment


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

