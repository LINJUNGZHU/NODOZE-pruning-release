"""Offline-only partial-positive accounting for immutable online attempts."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Iterable

from .detector_seed_benchmark import _atomic, _canonical, _sha_bytes, _sha_file, _verify_native
from .detectors.alert_evidence import load_evidence_jsonl
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
    resolved = json.loads((directory / "resolved_config.json").read_text())
    if resolved.get("database_sha256") != _sha_file(Path(resolved["database_path"])): raise ValueError("database hash changed")
    if resolved.get("expected_config_sha256") and resolved["expected_config_sha256"] != resolved["config_sha256"]: raise ValueError("config digest mismatch")
    if resolved.get("expected_code_commit") and resolved["expected_code_commit"] != resolved["code_commit"]: raise ValueError("code commit mismatch")
    native = json.loads((directory / "native_manifest.json").read_text())
    if native.get("files"): _verify_native(native)
    return resolved

def _unknown_stage() -> dict[str, str]: return {"status": "UNKNOWN"}

def evaluate_offline_benchmark(run_root: str | Path, *, known_critical_event_ids: Iterable[str], known_attack_node_ids: Iterable[str], output_directory: str | Path | None = None) -> dict[str, Any]:
    root, output = Path(run_root), Path(output_directory) if output_directory else Path(run_root).parent / "offline"
    known_edges, known_nodes, result = frozenset(known_critical_event_ids), frozenset(known_attack_node_ids), {"status": "COMPLETED", "runs": {}}
    for directory in sorted(path for path in root.iterdir() if path.is_dir() and path.name != ".attempts"):
        try:
            resolved = _verify_online(directory); evidence = load_evidence_jsonl(directory / "evidence.jsonl")
            candidate = _read_ids(directory / "candidate_raw_events.jsonl", "stored_event_id")
            a_final = frozenset(json.loads((directory / "A_rasp_final.json").read_text())["selected_raw_event_ids"])
            b_final = frozenset(json.loads((directory / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"])
            stages = json.loads((directory / "stage_identities.json").read_text())
            with ProvenanceStore(resolved["database_path"]) as store: raw = frozenset(item for item in known_edges if store.get_edge_by_event_id(item))
            available = lambda name: frozenset(stages[name].get("event_ids", ())) if stages[name].get("status") == "AVAILABLE" else frozenset()
            stage_ids = CandidateStageIds(raw, available("preprocessing"), available("inference"), available("scored"), available("native_threshold"), available("evidence"), candidate, a_final)
            funnel = evaluate_coverage_funnel(known_critical_event_ids=known_edges, stages=stage_ids)
            unknown = [name for name in ("preprocessing", "inference", "scored") if stages[name].get("status") != "AVAILABLE"]
            for name in unknown:
                funnel[name] = _unknown_stage()
                for edge in funnel["per_known_critical_edge"].values(): edge[name] = "UNKNOWN"
            if unknown: funnel["candidate_ceiling_decomposition"] = {"status": "UNKNOWN_UPSTREAM_STAGE", "stages": unknown}
            candidate_nodes = set(json.loads((directory / "candidate_nodes.json").read_text())["node_ids"])
            payload = {"schema_version": "detector-seed-benchmark-offline-v2", "status": "COMPLETED", "candidate": partial_positive_metrics(candidate, known_edges), "A_rasp_final": partial_positive_metrics(a_final, known_edges), "C_branch_fair_final": partial_positive_metrics(b_final, known_edges), "candidate_known_node_recall": len(candidate_nodes & known_nodes) / len(known_nodes) if known_nodes else 1.0, "funnel": funnel}
            target = output / directory.name / "evaluation.json"; target.parent.mkdir(parents=True, exist_ok=True); _write(target, payload); result["runs"][directory.name] = {"status": "COMPLETED", "evaluation": str(target)}
        except Exception as exc:
            result["status"] = "NOT_COMPLETED"; result["runs"][directory.name] = {"status": "NOT_COMPLETED", "reason": str(exc)}
    return result

__all__ = ["evaluate_offline_benchmark"]
