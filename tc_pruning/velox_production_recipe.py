"""Freeze one label-free Velox epoch into the CADETS E3 production contract."""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path
import re
import subprocess

from .detector_seed_production import (
    RUN_IDS,
    current_code_manifest,
    file_pin,
    write_json,
)


def _losses(files):
    count = 0
    total = 0.0
    maximum = float("-inf")
    for path in files:
        with path.open(encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                value = float(row["loss"])
                if not math.isfinite(value):
                    raise ValueError("nonfinite Velox loss")
                count += 1
                total += value
                maximum = max(maximum, value)
    if not count:
        raise ValueError("empty Velox loss population")
    return count, total / count, maximum


def _epoch_directories(root: Path, split: str) -> dict[int, Path]:
    parent = root / "edge_losses" / split
    result = {}
    for path in parent.glob("model_epoch_*") if parent.is_dir() else ():
        match = re.fullmatch(r"model_epoch_(\d+)", path.name)
        if match and path.is_dir():
            result[int(match.group(1))] = path
    return result


def select_velox_epoch(artifact_root: str | Path) -> dict:
    """Choose solely by mean development loss and attach measured test runtime."""
    root = Path(artifact_root).resolve()
    val, test = _epoch_directories(root, "val"), _epoch_directories(root, "test")
    common = sorted(set(val) & set(test))
    if not common:
        raise ValueError("no matching Velox validation/test epoch")
    candidates = []
    for epoch in common:
        files = sorted(val[epoch].glob("*.csv"))
        if not files:
            raise ValueError("Velox validation epoch has no CSV shards")
        count, mean, maximum = _losses(files)
        candidates.append((mean, epoch, count, maximum, files))
    mean, epoch, development_count, maximum, development_files = min(candidates)
    native_files = sorted(test[epoch].glob("*.csv"))
    if not native_files:
        raise ValueError("selected Velox epoch has no test CSV shards")
    test_count, _, _ = _losses(native_files)

    audit_path = root / "velox-inference-runtime.jsonl"
    if not audit_path.is_file():
        raise ValueError("Velox runtime audit is missing")
    runtime = None
    with audit_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                row = json.loads(line)
                if row.get("epoch") == epoch and row.get("requested_split") in ("all", "test") and "test" in row.get("splits", {}):
                    runtime = row
    if runtime is None:
        raise ValueError("selected Velox epoch has no test runtime audit")
    measured = runtime["splits"]["test"]
    if int(measured["scored_edges"]) != test_count:
        raise ValueError("Velox runtime/test population count mismatch")
    return {
        "epoch": epoch,
        "selection_rule": "minimum_mean_validation_edge_loss",
        "development_mean_loss": mean,
        "development_scored_edges": development_count,
        "native_threshold": maximum,
        "test_scored_edges": test_count,
        "inference_seconds": float(measured["seconds"]),
        "test_edges_per_second": float(measured["edges_per_second"]),
        "peak_inference_cpu_gb": float(runtime["peak_inference_cpu_gb"]),
        "peak_inference_gpu_gb": float(runtime["peak_inference_gpu_gb"]),
        "development": [file_pin(path) for path in development_files],
        "native": [file_pin(path) for path in native_files],
        "runtime_audit": file_pin(audit_path),
    }


def render_velox_config(*, artifact_root: str | Path, training_status: str | Path,
                        identity_manifest: str | Path, database: str | Path,
                        runtime_root: str | Path, output: str | Path) -> dict:
    """Render exact input pins; no positive labels are accepted by this API."""
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("refusing to overwrite Velox production config")
    output.parent.mkdir(parents=True, exist_ok=True)
    identity_path = Path(identity_manifest).resolve()
    identity = json.loads(identity_path.read_text())
    status_path = Path(training_status).resolve()
    status = json.loads(status_path.read_text())
    if status.get("status") != "COMPLETED" or status.get("detector") != "velox":
        raise ValueError("Velox training is not completed")
    if status.get("identity_manifest_sha256") != identity.get("manifest_sha256"):
        raise ValueError("Velox training/identity manifest mismatch")
    selected = select_velox_epoch(artifact_root)
    runtime_root = Path(runtime_root).resolve()
    commit = subprocess.check_output(["git", "-C", runtime_root, "rev-parse", "HEAD"], text=True).strip()
    population = {
        "native": selected["native"],
        "development": selected["development"],
        "native_threshold": selected["native_threshold"],
        "threshold_method": "max_val_loss",
        "version": commit,
        "inference_seconds": selected["inference_seconds"],
    }
    derivation = {
        "status": "COMPLETED",
        "detector_id": "VELOX",
        "source_sha256": file_pin(database)["sha256"],
        "identity_manifest_sha256": identity["manifest_sha256"],
        "runtime_sha256": identity["pidsmaker_runtime_seal"]["sha256"],
        "native": population["native"],
        "development": population["development"],
        "training_status": file_pin(status_path),
        "runtime_audit": selected["runtime_audit"],
        "epoch_selection": {key: selected[key] for key in (
            "epoch", "selection_rule", "development_mean_loss", "development_scored_edges",
            "test_scored_edges", "inference_seconds", "test_edges_per_second",
            "peak_inference_cpu_gb", "peak_inference_gpu_gb")},
        "generator": file_pin(__file__),
    }
    derivation_path = output.with_name(output.stem + "-derivation.json")
    write_json(derivation_path, derivation)
    population["derivation"] = file_pin(derivation_path)
    config = {
        "schema_version": "cadets-velox-production-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "database": file_pin(database),
        "identity_manifest": file_pin(identity_path),
        "runtime_root": str(runtime_root),
        "code": current_code_manifest(),
        "runs": list(RUN_IDS),
        "populations": {"VELOX": population},
        "candidate": {"candidate_cap": 10000, "history_start_ns": 1522706861813350340,
                      "cutoff_ns": 1523655358953968696, "max_strict_depth": 8,
                      "max_control_depth": 2, "enable_common_cause": True, "scan_multiplier": 20},
        "projection": {"mode": "DEPIMPACT_COMPATIBLE", "merge_window_ns": 900000000000},
        "raw_event_cap": 8000,
        "proxy_event_cap": 8000,
        "percentile_threshold": 0.9999,
    }
    write_json(output, config)
    return config


__all__ = ["render_velox_config", "select_velox_epoch"]
