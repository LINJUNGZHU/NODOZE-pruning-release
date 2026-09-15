"""Offline-only partial-positive accounting for immutable online attempts."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .detector_seed_benchmark import _atomic, _canonical, _sha_bytes, _sha_file, _verify_native
from .seed_utility_evaluation import CandidateStageIds, evaluate_coverage_funnel, partial_positive_metrics
from .store import ProvenanceStore

def _read_ids(path: Path, field: str) -> frozenset[str]:
    if not path.is_file(): raise ValueError(f"required artifact missing: {path.name}")
    return frozenset(str(json.loads(line)[field]) for line in path.read_text().splitlines() if line.strip())

def _write(path: Path, payload: dict[str, Any]) -> None:
    unsigned = dict(payload); payload["content_sha256"] = _sha_bytes(_canonical(unsigned)); _atomic(path, _canonical(payload))

def _verify_online(directory: Path) -> dict[str, Any]:
    status = json.loads((directory / "status.json").read_text())
    if status.get("status") != "COMPLETED": raise ValueError("online run is not completed")
    manifest = json.loads((directory / "artifacts.json").read_text())
    for row in manifest["artifacts"]:
        path = directory / row["path"]
        if not path.is_file() or path.stat().st_size != row["size_bytes"] or _sha_file(path) != row["sha256"]: raise ValueError("online artifact hash mismatch")
    for data in (directory / "evidence.jsonl", directory / "identity_audit.jsonl", directory / "candidate_raw_events.jsonl"):
        sidecar = data.with_suffix(data.suffix + ".manifest.json")
        if data.is_file() and sidecar.is_file():
            expected = json.loads(sidecar.read_text()).get("data_sha256")
            if expected != _sha_file(data): raise ValueError("JSONL data sidecar hash mismatch")
    resolved = json.loads((directory / "resolved_config.json").read_text())
    if resolved.get("database_sha256") != _sha_file(Path(resolved["database_path"])): raise ValueError("database hash changed")
    if resolved.get("expected_config_sha256") and resolved["expected_config_sha256"] != resolved["config_sha256"]: raise ValueError("config digest mismatch")
    if resolved.get("expected_code_commit") and resolved["expected_code_commit"] != resolved["code_commit"]: raise ValueError("code commit mismatch")
    native = json.loads((directory / "native_manifest.json").read_text())
    if native.get("files"): _verify_native(native)
    return resolved

def _unknown_stage() -> dict[str, str]: return {"status": "UNKNOWN"}

def _root_pin(root: Path) -> str:
    manifest = root / "root_manifest.json"
    if not manifest.is_file(): raise ValueError("online root manifest missing")
    return _sha_file(manifest)

def _current_directories(root: Path) -> list[Path]:
    runs = root / "runs"
    pointers = sorted(runs.glob("*.CURRENT")) if runs.is_dir() else []
    if pointers:
        result = []
        for pointer in pointers:
            record = json.loads(pointer.read_text())
            directory = Path(record["attempt"])
            if not directory.is_dir(): raise ValueError("CURRENT points to a missing immutable attempt")
            result.append(directory)
        return result
    return sorted(path for path in root.iterdir() if path.is_dir() and path.name not in {".attempts", "runs", "offline"})

def _pinned_directories(root: Path, expected_root_sha256: str) -> list[Path]:
    manifest_path = root / "root_manifest.json"
    if _sha_file(manifest_path) != expected_root_sha256: raise ValueError("offline root pin mismatch")
    manifest = json.loads(manifest_path.read_text())
    runs = manifest.get("runs")
    if not isinstance(runs, list): raise ValueError("invalid pinned root manifest")
    names = {str(row.get("run_id")) for row in runs}
    expected = {"ORTHRUS", "KAIROS", "R-CAID", "NODLINK", "VXL-0", "VXL-1", "VXL-2", "VXL-3"}
    if names != expected or len(runs) != 8: raise ValueError("pinned production root does not contain exact eight-run set")
    directories = []
    for row in runs:
        current = root / row["current_path"]
        if not current.is_file() or _sha_file(current) != row["current_sha256"]: raise ValueError("CURRENT bytes differ from pinned root")
        target = Path(json.loads(current.read_text())["attempt"])
        if not target.is_dir(): raise ValueError("pinned CURRENT target missing")
        for file_row in row.get("files", ()):
            file = root / file_row["path"]
            if not file.is_file() or file.stat().st_size != file_row["size_bytes"] or _sha_file(file) != file_row["sha256"]: raise ValueError("pinned artifact bytes differ")
        directories.append(target)
    return directories

def evaluate_offline_benchmark(run_root: str | Path, *, known_critical_event_ids: Iterable[str], known_attack_node_ids: Iterable[str], output_directory: str | Path | None = None, expected_root_sha256: str | None = None, pin_file: str | Path | None = None) -> dict[str, Any]:
    root, output = Path(run_root), Path(output_directory) if output_directory else Path(run_root).parent / "offline"
    if pin_file is not None:
        pin = json.loads(Path(pin_file).read_text())
        expected_root_sha256 = str(pin.get("root_manifest_sha256", ""))
    if not expected_root_sha256:
        # Fixture-only backwards compatibility: production paths are always
        # sealed.  This is deliberately based on the resolved JSON boolean,
        # never a filename convention.
        fixture_resolved = next(iter(root.glob("*/resolved_config.json")), None)
        if fixture_resolved is None:
            fixture_resolved = root / "resolved_config.json"
        fixture = fixture_resolved.is_file() and bool(json.loads(fixture_resolved.read_text()).get("config", {}).get("fixture_mode") is True)
        if not fixture: raise ValueError("offline requires an independently supplied matching root pin")
    elif _root_pin(root) != expected_root_sha256:
        raise ValueError("offline root pin mismatch")
    known_edges, known_nodes, result = frozenset(known_critical_event_ids), frozenset(known_attack_node_ids), {"status": "COMPLETED", "runs": {}}
    directories = _pinned_directories(root, expected_root_sha256) if expected_root_sha256 else _current_directories(root)
    for directory in directories:
        try:
            resolved = _verify_online(directory)
            candidate = _read_ids(directory / "candidate_raw_events.jsonl", "stored_event_id")
            a_final = frozenset(json.loads((directory / "A_rasp_final.json").read_text())["selected_raw_event_ids"])
            b_final = frozenset(json.loads((directory / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"])
            stages = json.loads((directory / "stage_identities.json").read_text())
            with ProvenanceStore(resolved["database_path"]) as store: raw = frozenset(item for item in known_edges if store.get_edge_by_event_id(item))
            def available(name: str) -> frozenset[str]:
                row = stages[name]
                if row.get("status") != "AVAILABLE": return frozenset()
                if row.get("identity_index"):
                    manifest = json.loads((directory / row["identity_index"]).read_text())
                    conn = sqlite3.connect(directory / manifest["sqlite_path"])
                    try:
                        # Query only the offline supplied partial positives;
                        # do not load the complete evidence identity population.
                        return frozenset(identity for identity in known_edges if conn.execute("SELECT 1 FROM stage_identity WHERE stage=? AND kind='event' AND identity=?", (row.get("stage", name), identity)).fetchone())
                    finally: conn.close()
                return frozenset(row.get("event_ids", ()))
            stage_ids = CandidateStageIds(raw, available("preprocessing"), available("inference"), available("scored"), available("native_threshold"), available("evidence"), candidate, a_final)
            funnel = evaluate_coverage_funnel(known_critical_event_ids=known_edges, stages=stage_ids)
            unknown = [name for name in ("preprocessing", "inference", "scored") if stages[name].get("status") != "AVAILABLE"]
            for name in unknown:
                funnel[name] = _unknown_stage()
                for edge in funnel["per_known_critical_edge"].values(): edge[name] = "UNKNOWN"
            is_fixture = bool(resolved.get("config", {}).get("fixture_mode") is True)
            if unknown: funnel["candidate_ceiling_decomposition"] = {"status": "UNKNOWN_UPSTREAM_STAGE", "stages": unknown}; payload_status = "COMPLETED" if is_fixture else "PARTIAL"
            else: payload_status = "COMPLETED"
            candidate_nodes = set(json.loads((directory / "candidate_nodes.json").read_text())["node_ids"])
            payload = {"schema_version": "detector-seed-benchmark-offline-v2", "status": payload_status, "candidate": partial_positive_metrics(candidate, known_edges), "A_rasp_final": partial_positive_metrics(a_final, known_edges), "C_branch_fair_final": partial_positive_metrics(b_final, known_edges), "candidate_known_node_recall": len(candidate_nodes & known_nodes) / len(known_nodes) if known_nodes else 1.0, "funnel": funnel}
            target = output / directory.name / "evaluation.json"; target.parent.mkdir(parents=True, exist_ok=True); _write(target, payload); result["runs"][directory.name] = {"status": payload_status, "evaluation": str(target)}
            if payload_status != "COMPLETED": result["status"] = "PARTIAL"
        except Exception as exc:
            result["status"] = "NOT_COMPLETED"; result["runs"][directory.name] = {"status": "NOT_COMPLETED", "reason": str(exc)}
    return result

__all__ = ["evaluate_offline_benchmark"]
