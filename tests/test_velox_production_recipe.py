from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from tc_pruning.velox_production_recipe import select_velox_epoch


def _csv(path: Path, losses: list[float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["loss", "event_uuid"])
        writer.writeheader()
        for index, loss in enumerate(losses):
            writer.writerow({"loss": loss, "event_uuid": f"e{index}"})


def test_selects_epoch_by_development_loss_only_and_binds_test_runtime(tmp_path):
    root = tmp_path / "artifacts"
    _csv(root / "edge_losses/val/model_epoch_0/val-a.csv", [1, 5])
    _csv(root / "edge_losses/test/model_epoch_0/test-a.csv", [9])
    _csv(root / "edge_losses/val/model_epoch_2/val-a.csv", [1, 2])
    _csv(root / "edge_losses/test/model_epoch_2/test-a.csv", [8, 7])
    audit = root / "velox-inference-runtime.jsonl"
    audit.write_text("\n".join([
        json.dumps({"epoch": 0, "requested_split": "all", "splits": {"test": {"seconds": 4, "scored_edges": 1, "edges_per_second": .25}}, "peak_inference_cpu_gb": 2, "peak_inference_gpu_gb": 1}),
        json.dumps({"epoch": 2, "requested_split": "all", "splits": {"test": {"seconds": 2, "scored_edges": 2, "edges_per_second": 1}}, "peak_inference_cpu_gb": 1, "peak_inference_gpu_gb": .5}),
    ]) + "\n")

    result = select_velox_epoch(root)

    assert result["epoch"] == 2
    assert result["selection_rule"] == "minimum_mean_validation_edge_loss"
    assert result["development_mean_loss"] == 1.5
    assert result["native_threshold"] == 2
    assert result["inference_seconds"] == 2
    assert result["test_scored_edges"] == 2
    assert result["test_edges_per_second"] == 1
    assert [Path(item["path"]).name for item in result["development"]] == ["val-a.csv"]
    assert [Path(item["path"]).name for item in result["native"]] == ["test-a.csv"]
    assert result["runtime_audit"]["sha256"] == hashlib.sha256(audit.read_bytes()).hexdigest()


def test_rejects_missing_matching_test_epoch_or_runtime_audit(tmp_path):
    root = tmp_path / "artifacts"
    _csv(root / "edge_losses/val/model_epoch_0/val.csv", [1])
    try:
        select_velox_epoch(root)
    except ValueError as exc:
        assert "test" in str(exc) or "runtime" in str(exc)
    else:
        raise AssertionError("incomplete detector artifacts were accepted")
