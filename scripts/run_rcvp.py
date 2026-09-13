"""Run and independently validate frozen RASP-RCVP ablations.

The online phase consumes only a versioned candidate score ledger.  It writes
all decisions before the optional evaluator is allowed to open reference data.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import resource
import sqlite3
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
AUDIT_NAME = "rcvp-edge-audit.jsonl.gz"
ROOTS_NAME = "rcvp-roots.json"
MANIFEST_NAME = "manifest.json"
SCHEMA = "rasp-rcvp-frozen-evaluation-v1"
AUDIT_SCHEMA = "rasp-rcvp-edge-audit-v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical(value) + b"\n")
    temporary.replace(path)


def _write_deterministic_gzip(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            for row in rows:
                zipped.write(_canonical(row) + b"\n")
    temporary.replace(path)


def _json_value(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return [_json_value(item) for item in value.tolist()]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("audit values must be finite")
    return value


def _decision_summary(decisions: Mapping[str, Sequence[bool]], count: int) -> dict[str, Any]:
    summary = {}
    for name in sorted(decisions):
        mask = np.asarray(decisions[name], dtype=bool)
        if mask.shape != (count,):
            raise ValueError(f"decision {name} must contain one value per candidate")
        kept = np.flatnonzero(mask).tolist()
        summary[name] = {
            "candidate_edges": count,
            "retained_edges": len(kept),
            "actual_keep_ratio": len(kept) / count if count else None,
            "event_index_sha256": _sha256_json(kept),
        }
    return summary


def _validate_edge_ids(candidates: Sequence[Mapping[str, Any]]) -> list[int]:
    if any("edge_id" not in row for row in candidates):
        raise ValueError("every candidate must have an edge_id")
    edge_ids = [int(row["edge_id"]) for row in candidates]
    if len(set(edge_ids)) != len(edge_ids):
        raise ValueError("candidate edge IDs must be unique")
    return edge_ids


def freeze_online_artifacts(
    output: Path | str,
    candidates: Sequence[Mapping[str, Any]],
    decisions: Mapping[str, Sequence[bool]],
    edge_fields: Mapping[str, Sequence[Any]],
    roots: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    *,
    implementation_paths: Sequence[Path | str],
    timings: Mapping[str, float] | None = None,
    memory: Mapping[str, float] | None = None,
    method_diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist the immutable online result. This function accepts no labels."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    count = len(candidates)
    event_ids = [str(row["event_id"]) for row in candidates]
    if len(set(event_ids)) != count:
        raise ValueError("candidate event IDs must be unique")
    _validate_edge_ids(candidates)
    for name, values in edge_fields.items():
        if len(values) != count:
            raise ValueError(f"edge field {name} must contain one value per candidate")
    summary = _decision_summary(decisions, count)
    if method_diagnostics is None:
        method_diagnostics = {name: {"requested_keep_ratio": float(name.rsplit("@", 1)[1]),
            "raw_event_budget": max(1, int(count * float(name.rsplit("@", 1)[1]))),
            "retained_raw_events": values["retained_edges"], "budget_feasible": values["retained_edges"] <= max(1, int(count * float(name.rsplit("@", 1)[1]))),
            "budget_overflow_edges": max(0, values["retained_edges"] - max(1, int(count * float(name.rsplit("@", 1)[1]))))} for name, values in summary.items()}
    rows = []
    for index, candidate in enumerate(candidates):
        row = {
            **_json_value(dict(candidate)),
            "audit_schema_version": AUDIT_SCHEMA,
            "candidate_index": index,
            "rcvp_evidence": {name: _json_value(values[index]) for name, values in sorted(edge_fields.items())},
            "decisions": {name: bool(np.asarray(values, dtype=bool)[index]) for name, values in sorted(decisions.items())},
        }
        if "decisions" in candidate:
            row["source_decisions"] = _json_value(candidate["decisions"])
        rows.append(row)
    audit = output / AUDIT_NAME
    _write_deterministic_gzip(audit, rows)
    roots_path = output / ROOTS_NAME
    _write_json(roots_path, _json_value(list(roots)))
    candidate_identity = [[row["event_id"], row.get("edge_id"), row.get("src"), row.get("dst"), row.get("timestamp_ns"), row.get("relation")] for row in candidates]
    implementation = {str(Path(path).resolve().relative_to(ROOT)): sha256_file(path) for path in sorted(map(Path, implementation_paths), key=lambda p: str(p.resolve()))}
    manifest = {
        "schema_version": SCHEMA,
        "ground_truth_used_for_selection": False,
        "candidate_edges": count,
        "candidate_sha256": _sha256_json(candidate_identity),
        "candidate_content_sha256": _sha256_json([dict(row) for row in candidates]),
        "decision_sha256": _sha256_json(summary),
        "config": _json_value(dict(config)),
        "config_sha256": _sha256_json(config),
        "implementation_sha256": implementation,
        "edge_field_names": sorted(edge_fields),
        "decision_summary": summary,
        "artifacts": {AUDIT_NAME: sha256_file(audit), ROOTS_NAME: sha256_file(roots_path)},
        "timings_seconds": _json_value(dict(timings or {})),
        "memory_mib": _json_value(dict(memory or {})),
        "method_diagnostics": _json_value(dict(method_diagnostics or {})),
    }
    manifest["integrity_sha256"] = _sha256_json(manifest)
    _write_json(output / MANIFEST_NAME, manifest)
    return manifest


def _read_audit(path: Path) -> list[dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def validate_frozen_artifacts(output: Path | str) -> dict[str, Any]:
    """Recompute hashes, identities, decision counts and evidence schemas."""
    output = Path(output)
    manifest = json.loads((output / MANIFEST_NAME).read_text())
    if manifest.get("schema_version") != SCHEMA:
        raise ValueError("unsupported manifest schema")
    integrity = manifest.pop("integrity_sha256", None)
    if integrity != _sha256_json(manifest):
        raise ValueError("manifest integrity hash mismatch")
    manifest["integrity_sha256"] = integrity
    if manifest.get("ground_truth_used_for_selection") is not False:
        raise ValueError("online selection truth-isolation assertion missing")
    if _sha256_json(manifest.get("config")) != manifest.get("config_sha256"):
        raise ValueError("config hash mismatch")
    for filename, expected in manifest["artifacts"].items():
        if sha256_file(output / filename) != expected:
            raise ValueError(f"artifact hash mismatch: {filename}")
    for filename, expected in manifest.get("implementation_sha256", {}).items():
        source = ROOT / filename
        if not source.is_file():
            raise ValueError(f"implementation file missing: {filename}")
        if sha256_file(source) != expected:
            raise ValueError(f"implementation hash mismatch: {filename}")
    rows = _read_audit(output / AUDIT_NAME)
    _validate_edge_ids(rows)
    if len(rows) != manifest["candidate_edges"]:
        raise ValueError("candidate count mismatch")
    if [row.get("candidate_index") for row in rows] != list(range(len(rows))):
        raise ValueError("candidate ordering mismatch")
    if len({row.get("event_id") for row in rows}) != len(rows):
        raise ValueError("duplicate candidate event ID")
    fields = set(manifest["edge_field_names"])
    methods = set(manifest["decision_summary"])
    for row in rows:
        if row.get("audit_schema_version") != AUDIT_SCHEMA:
            raise ValueError("audit schema mismatch")
        if set(row.get("rcvp_evidence", {})) != fields:
            raise ValueError("edge evidence schema mismatch")
        if set(row.get("decisions", {})) != methods:
            raise ValueError("decision schema mismatch")
        if any(type(value) is not bool for value in row["decisions"].values()):
            raise ValueError("decisions must be booleans")
    decisions = {name: [bool(row["decisions"][name]) for row in rows] for name in methods}
    summary = _decision_summary(decisions, len(rows))
    if summary != manifest["decision_summary"] or _sha256_json(summary) != manifest["decision_sha256"]:
        raise ValueError("decision summary mismatch")
    diagnostics = manifest.get("method_diagnostics", {})
    if set(diagnostics) != methods:
        raise ValueError("method diagnostics schema mismatch")
    for method, reported in diagnostics.items():
        ratio = float(method.rsplit("@", 1)[1])
        budget = max(1, int(len(rows) * ratio))
        retained = summary[method]["retained_edges"]
        if reported.get("requested_keep_ratio") != ratio or reported.get("raw_event_budget") != budget or reported.get("retained_raw_events") != retained:
            raise ValueError("method diagnostic budget/count mismatch")
        if reported.get("budget_overflow_edges") is not None and reported["budget_overflow_edges"] != max(0, retained - budget):
            raise ValueError("method diagnostic overflow mismatch")
        if reported.get("budget_feasible") is True and retained > budget:
            raise ValueError("method diagnostic feasibility mismatch")
    for value in manifest.get("timings_seconds", {}).values():
        for number in (value.values() if isinstance(value, dict) else (value,)):
            if not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
                raise ValueError("invalid timing diagnostic")
    for number in manifest.get("memory_mib", {}).values():
        if not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
            raise ValueError("invalid memory diagnostic")
    identity = [[row["event_id"], row.get("edge_id"), row.get("src"), row.get("dst"), row.get("timestamp_ns"), row.get("relation")] for row in rows]
    if _sha256_json(identity) != manifest["candidate_sha256"]:
        raise ValueError("candidate identity hash mismatch")
    originals = []
    for row in rows:
        original = {key: value for key, value in row.items() if key not in {"audit_schema_version", "candidate_index", "rcvp_evidence", "decisions", "source_decisions"}}
        if "source_decisions" in row:
            original["decisions"] = row["source_decisions"]
        originals.append(original)
    if _sha256_json(originals) != manifest["candidate_content_sha256"]:
        raise ValueError("candidate content hash mismatch")
    config = manifest["config"]
    fields_by_name = {name: np.asarray([row["rcvp_evidence"][name] for row in rows]) for name in fields}
    if {"poi_forward_score", "background_forward_score", "forward_lift"} <= fields:
        eps = float(config["resolved_variants"]["E"]["epsilon"])
        for prefix in ("forward", "backward"):
            poi_values = fields_by_name[f"poi_{prefix}_score"].astype(float)
            background = fields_by_name[f"background_{prefix}_score"].astype(float)
            expected = np.zeros_like(poi_values)
            positive = poi_values > 0
            expected[positive] = np.maximum(np.log(poi_values[positive]) - np.log(np.maximum(background[positive], eps)), 0.0)
            if not np.allclose(expected, fields_by_name[f"{prefix}_lift"].astype(float), rtol=1e-9, atol=1e-10):
                raise ValueError(f"{prefix} lift recomputation mismatch")
        weights = config["resolved_variants"]["E"]["channel_weights"]
        expected = 1 - ((1 - weights["backward"] * fields_by_name["backward_normalized"].astype(float)) *
                        (1 - weights["forward"] * fields_by_name["forward_normalized"].astype(float)) *
                        (1 - weights["verification"] * fields_by_name["roundtrip_verification_score"].astype(float)))
        poi_mask = np.asarray([bool(row.get("is_declared_poi")) for row in rows])
        expected[poi_mask] = 1.0
        if not np.allclose(expected, fields_by_name["diffusion_E_verified"].astype(float), rtol=1e-9, atol=1e-10):
            raise ValueError("verified noisy-OR recomputation mismatch")
    roots = json.loads((output / ROOTS_NAME).read_text())
    for root in roots:
        witness = [int(index) for index in root.get("witness", [])]
        if not witness or any(index < 0 or index >= len(rows) for index in witness):
            raise ValueError("invalid root witness index")
        for left, right in zip(witness, witness[1:]):
            if int(rows[left]["timestamp_ns"]) >= int(rows[right]["timestamp_ns"]):
                raise ValueError("root witness is not strictly temporal")
            left_src, left_dst = _causal_row_endpoints(rows[left])
            right_src, _ = _causal_row_endpoints(rows[right])
            if left_dst != right_src:
                raise ValueError("root witness breaks directed causal continuity")
    if any(not all(row["decisions"][method] for method in methods) for row in rows if row.get("is_declared_poi")):
        raise ValueError("declared POI was not retained")
    if "source_merge_threshold_seconds" in config:
        threshold = float(config["source_merge_threshold_seconds"])
        groups = __import__("tc_pruning.depimpact", fromlist=["merge_parallel_edges"]).merge_parallel_edges(_graph(rows), threshold_seconds=threshold).groups
        by_edge_id = {int(row["edge_id"]): row for row in rows}
        for method in methods - {name for name in methods if name.startswith("A_rasp@") }:
            for members in groups.values():
                values = {by_edge_id[edge_id]["decisions"][method] for edge_id in members}
                if len(values) > 1:
                    raise ValueError("atomic group split")
    return {"valid": True, "candidate_edges": len(rows), "methods": sorted(methods), "audit_sha256": manifest["artifacts"][AUDIT_NAME]}


def _causal_row_endpoints(row: Mapping[str, Any]) -> tuple[str, str]:
    if str(row["relation"]).upper() == "EVENT_EXECUTE":
        return str(row["dst"]), str(row["src"])
    return str(row["src"]), str(row["dst"])


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    result = {"numerator": int(numerator), "denominator": int(denominator), "value": numerator / denominator if denominator else None}
    if not denominator:
        result["reason"] = "zero_denominator"
    return result


def evaluate_frozen_positive_ids(
    rows: Sequence[Mapping[str, Any]],
    positive_node_ids: set[str],
    reference_event_ids: set[str],
) -> dict[str, dict[str, Any]]:
    """Evaluate already-frozen masks; deliberately has no selection callback."""
    methods = sorted(rows[0]["decisions"]) if rows else []
    candidate_events = {str(row["event_id"]) for row in rows}
    candidate_nodes = {str(row[key]) for row in rows for key in ("src", "dst")}
    covered_events = candidate_events & reference_event_ids
    covered_nodes = candidate_nodes & positive_node_ids
    results = {}
    for method in methods:
        retained = [row for row in rows if row["decisions"][method]]
        retained_events = {str(row["event_id"]) for row in retained}
        retained_nodes = {str(row[key]) for row in retained for key in ("src", "dst")}
        retained_reference = retained_events & reference_event_ids
        results[method] = {
            "candidate_context_edge_recall": _ratio(len(covered_events), len(reference_event_ids)),
            "conditional_context_edge_retention": _ratio(len(retained_reference), len(covered_events)),
            "pruned_context_edge_recall": _ratio(len(retained_reference), len(reference_event_ids)),
            "attack_event_recall": _ratio(len(retained_reference), len(reference_event_ids)),
            "candidate_positive_node_recall": _ratio(len(covered_nodes), len(positive_node_ids)),
            "pruned_positive_node_recall": _ratio(len(retained_nodes & positive_node_ids), len(positive_node_ids)),
            "actual_keep_ratio": _ratio(len(retained), len(rows)),
            "edge_compression": None if not rows else 1 - len(retained) / len(rows),
            "node_compression": None if not candidate_nodes else 1 - len(retained_nodes) / len(candidate_nodes),
            "verified_attack_path_retention": {"value": None, "reason": "no_independently_human_reviewed_paths"},
            "strict_complete_path_retention": {"value": None, "reason": "no_independently_human_reviewed_paths"},
            "time_respecting_reachability": {"value": None, "reason": "no_admitted_reference_paths"},
            "precision": {"value": None, "reason": "no_exhaustive_negative_labels"},
            "f1": {"value": None, "reason": "no_exhaustive_negative_labels"},
        }
    return results


def _load_candidate_rows(path: Path) -> list[dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def _measured(call):
    from tc_pruning.evaluation import _PeakRSSMonitor
    tick = time.perf_counter()
    with _PeakRSSMonitor() as monitor:
        value = call()
    return value, {"wall_seconds": time.perf_counter() - tick, "peak_rss_mib": monitor.peak_bytes / 1048576, "peak_rss_delta_mib": max(0, monitor.peak_bytes - monitor.baseline_bytes) / 1048576}


def _arrays(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, int] = {}
    process = set()
    src, dst, relation_names = [], [], []
    for row in rows:
        a = nodes.setdefault(str(row["src"]), len(nodes)); b = nodes.setdefault(str(row["dst"]), len(nodes))
        if row.get("src_type") == "process": process.add(a)
        if row.get("dst_type") == "process": process.add(b)
        if str(row["relation"]).upper() == "EVENT_EXECUTE": a, b = b, a
        src.append(a); dst.append(b); relation_names.append(str(row["relation"]))
    process_nodes = np.zeros(len(nodes), dtype=bool)
    if process: process_nodes[list(process)] = True
    return {
        "src": np.asarray(src), "dst": np.asarray(dst),
        "timestamp": np.asarray([int(row["timestamp_ns"]) for row in rows], dtype=np.int64),
        "relation_names": relation_names,
        "rarity": np.asarray([float(row.get("components", {}).get("rarity", 0.0)) for row in rows]),
        "poi": np.asarray([bool(row.get("is_declared_poi")) for row in rows]),
        "process_nodes": process_nodes,
        "tie": np.asarray([int.from_bytes(hashlib.sha256(str(row["event_id"]).encode()).digest()[:8], "big") for row in rows], dtype=np.uint64),
        "node_ids": list(nodes),
    }


def _select_fork(score: np.ndarray, arrays: Mapping[str, Any], budget: int) -> np.ndarray:
    from tc_pruning.rasp import select_fork_bundles, temporal_fork_routes, temporal_routes
    backward = temporal_routes(arrays["src"], arrays["dst"], arrays["timestamp"], arrays["poi"])[0][0]
    parent, pivot, _, _ = temporal_fork_routes(arrays["src"], arrays["dst"], arrays["timestamp"], arrays["poi"], backward)
    return select_fork_bundles(score, arrays["poi"], backward, parent, pivot, budget, arrays["tie"])[0]


def _graph(rows: Sequence[Mapping[str, Any]]):
    from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
    nodes = {}
    edges = []
    for index, row in enumerate(rows):
        for side in ("src", "dst"):
            uuid = str(row[side]); kind = str(row.get(f"{side}_type", "unknown")); label = str(row.get(f"{side}_semantic", uuid))
            nodes.setdefault(uuid, NodeRecord(uuid, kind, label, str(row.get("host", ""))))
        edges.append(StoredEdge(int(row.get("edge_id", index)), str(row["event_id"]), str(row["src"]), str(row["dst"]), str(row["relation"]), int(row["timestamp_ns"]), str(row.get("host", "")), str(row.get("src_type", "unknown")), str(row.get("dst_type", "unknown")), str(row.get("src_semantic", "")), str(row.get("dst_semantic", "")), row.get("data_size")))
    return Neighborhood(nodes, edges)


def _adaptive_mask(rows: Sequence[Mapping[str, Any]], scores: np.ndarray, ratio: float, mode: str, evidence: Mapping[str, Sequence[Any]] | None = None, *, pre_fused: bool = False, weights: Mapping[str, float] | None = None, parents: Sequence[int] | None = None, ordered_sequences: Sequence[Sequence[int]] | None = None, atomic_groups: Mapping[int, Sequence[int]] | None = None, progressive_config: Mapping[str, object] | None = None, require_all_parents_valid: bool = True) -> tuple[np.ndarray, dict[str, Any]]:
    from tc_pruning.diffusion import DiffusionResult
    from tc_pruning.pruning import adaptive_prune
    graph = _graph(rows); edge_ids = [edge.edge_id for edge in graph.edges]
    seeds = {str(row[key]) for row in rows if row.get("is_declared_poi") for key in ("src", "dst")}
    protected = {edge_ids[i] for i, row in enumerate(rows) if row.get("is_declared_poi")}
    components = {edge_id: {**{name: float(value) for name, value in rows[i].get("components", {}).items() if isinstance(value, (int, float))}, **{name: float(values[i]) for name, values in (evidence or {}).items() if np.isscalar(values[i]) and isinstance(values[i], (int, float, np.number))}} for i, edge_id in enumerate(edge_ids)}
    weights = dict(weights or {"rarity": .1, "path": .1, "impact": .1, "behavior": .1})
    dependencies = None
    excluded_dependencies = 0
    if parents is not None:
        if len(parents) != len(edge_ids) or any(int(parent) >= len(edge_ids) or int(parent) == i for i, parent in enumerate(parents)):
            raise ValueError("invalid temporal witness parent array")
        dependencies = {}
        for i, parent in enumerate(parents):
            parent = int(parent)
            if parent < 0:
                continue
            here, there = rows[i], rows[parent]
            if int(here["timestamp_ns"]) == int(there["timestamp_ns"]):
                if require_all_parents_valid: raise ValueError("temporal witness dependency has equal timestamps")
                excluded_dependencies += 1; continue
            a_src, a_dst = _causal_row_endpoints(here); b_src, b_dst = _causal_row_endpoints(there)
            if a_dst != b_src and b_dst != a_src:
                if require_all_parents_valid: raise ValueError("temporal witness dependency is not causally adjacent")
                excluded_dependencies += 1; continue
            dependencies[(edge_ids[i],)] = [(edge_ids[parent],)]
    consistency = (evidence or {}).get("roundtrip_verification_score", np.zeros(len(edge_ids)))
    edge_evidence = {}
    for i, edge_id in enumerate(edge_ids):
        causal_src, causal_dst = _causal_row_endpoints(rows[i])
        edge_evidence[edge_id] = {"consistency": float(consistency[i]), "redundancy_key": f"{causal_src}>{causal_dst}:{rows[i]['relation']}"}
    kwargs = dict(graph=graph, edge_rarity={edge_id: float(rows[i].get("components", {}).get("rarity", 0.0)) for i, edge_id in enumerate(edge_ids)},
                  diffusion=DiffusionResult({}, {}, 0, True, [], {edge_id: float(scores[i]) for i, edge_id in enumerate(edge_ids)}, edge_evidence=edge_evidence), seeds=seeds,
                  keep_ratio=ratio, rarity_weight=0.0 if pre_fused else weights["rarity"],
                  path_importance={edge_id: float(rows[i].get("components", {}).get("path", 0.0)) for i, edge_id in enumerate(edge_ids)},
                  path_weight=0.0 if pre_fused else weights["path"],
                  impact_importance={edge_id: float(rows[i].get("components", {}).get("depimpact", 0.0)) for i, edge_id in enumerate(edge_ids)},
                  impact_weight=0.0 if pre_fused else weights["impact"],
                  behavior_importance={edge_id: float(rows[i].get("components", {}).get("behavior", 0.0)) for i, edge_id in enumerate(edge_ids)},
                  behavior_weight=0.0 if pre_fused else weights["behavior"],
                  selection_mode=mode, protect_seed_incident_edges=False,
                  protected_edge_ids=protected,
                  atomic_edge_groups={int(key): tuple(map(int, value)) for key, value in (atomic_groups or {}).items()},
                  edge_scores_override={edge_id: float(np.clip(scores[i], 0., 1.)) for i, edge_id in enumerate(edge_ids)} if pre_fused else None,
                  edge_score_components_override=components if pre_fused else None,
                  progressive_dependencies=dependencies if mode == "progressive" else None,
                  progressive_config=dict(progressive_config or {}) if mode == "progressive" else None,
                  ordered_connectivity_edge_sequences=tuple(tuple(s) for s in ordered_sequences) if ordered_sequences else None,
                  certificate_poi_edge_ids={edge_id for sequence in (ordered_sequences or ()) for edge_id in sequence} or None,
                  certificate_expected_poi_count=sum(len(s) for s in ordered_sequences) if ordered_sequences else None)
    result = adaptive_prune(**kwargs)
    kept_ids = {edge.edge_id for edge in result.kept_edges}
    mask = np.asarray([edge_id in kept_ids for edge_id in edge_ids])
    audit = getattr(result, "progressive_audit", {}) or {}
    audit["_result"] = {name: _json_value(getattr(result, name)) for name in ("actual_keep_ratio", "budget_feasible", "budget_overflow_edges", "path_certificate_valid", "strict_multistage_certificate_valid") if hasattr(result, name)}
    audit["_result"].update(validated_witness_dependencies=len(dependencies or {}), excluded_nonadjacent_legacy_dependencies=excluded_dependencies)
    return mask, {str(key): _json_value(value) for key, value in audit.items()}


def run_online_case(case: str, ledger: Path, output: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    """Run A–G. No reference path or label object is accepted here."""
    from tc_pruning.rasp import propagate as rasp_propagate
    from tc_pruning.rcvp import propagate as rcvp_propagate
    from tc_pruning.rcvp_config import preset
    required_methods = {"A_rasp", "A_rdp", "B", "C", "D", "E", "F", "G", "G_no_redundancy"}
    if set(config.get("methods", ())) != required_methods:
        raise ValueError(f"full matrix requires methods {sorted(required_methods)}")
    started = time.perf_counter(); rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    frozen_config = {**dict(config), "case": case, "candidate_ledger": str(ledger.resolve()), "candidate_ledger_sha256": sha256_file(ledger),
                     "method_labels": {"A_rasp": "current RASP select_fork replay", "A_rdp": "joint RDP-Guard replay of frozen legacy diffusion and ledger components with reconstructed atomic groups/certificate inputs", "F": "exact A_rdp scoring inputs plus progressive pruning", "G": "exact E scoring inputs plus progressive pruning"}}
    rows = _load_candidate_rows(ledger); _validate_edge_ids(rows); arrays = _arrays(rows); n = len(rows)
    source_manifest_path = ledger.parent / "manifest.json"
    source_manifest = json.loads(source_manifest_path.read_text()) if source_manifest_path.is_file() else {}
    event_to_edge = {str(row["event_id"]): int(row["edge_id"]) for row in rows}
    declared = source_manifest.get("context", {}).get("pruning_parameters", {}).get("ordered_poi_event_sequences", [])
    ordered_sequences = [tuple(event_to_edge[event] for event in sequence) for sequence in declared if all(event in event_to_edge for event in sequence)]
    from tc_pruning.depimpact import merge_parallel_edges
    threshold = float(source_manifest.get("context", {}).get("scoring_parameters", {}).get("merge_threshold_seconds", 10.0))
    atomic_groups = merge_parallel_edges(_graph(rows), threshold_seconds=threshold).groups
    replay_provenance = "ordered_certificate_and_atomic_groups_reconstructed_from_source_parameters" if ordered_sequences else "atomic_groups_reconstructed_ordered_certificate_unavailable"
    frozen_config["source_pruning_provenance"] = replay_provenance
    frozen_config["source_manifest_sha256"] = sha256_file(source_manifest_path) if source_manifest_path.is_file() else None
    frozen_config["source_merge_threshold_seconds"] = threshold
    relation_index: dict[str, int] = {}
    relation_ids = np.asarray([relation_index.setdefault(name, len(relation_index)) for name in arrays["relation_names"]])
    rasp_config = config.get("rasp_config")
    if isinstance(rasp_config, str):
        rasp_config = json.loads((ROOT / rasp_config).read_text())
    if rasp_config is None:
        rasp_config = json.loads((ROOT / "configs/rasp_v1.json").read_text())
    (rasp_score, _), rasp_measure = _measured(lambda: rasp_propagate(arrays["src"], arrays["dst"], relation_ids, arrays["rarity"], arrays["poi"], arrays["process_nodes"], rasp_config))
    variants = {
        "B": {**preset("relation_aware"), "temporal_tau_seconds": None, "fanout_gamma": 0.0, "backward_enabled": False, "verification_enabled": False},
        "C": {**preset("full"), "backward_enabled": False, "verification_enabled": False},
        "D": {**preset("full"), "verification_enabled": False},
        "E": preset("full"),
    }
    frozen_config["resolved_rasp_config"] = rasp_config
    frozen_config["resolved_variants"] = variants
    frozen_config["atomic_groups_sha256"] = _sha256_json({str(key): list(value) for key, value in sorted(atomic_groups.items())})
    scores: dict[str, np.ndarray] = {"A_rasp": np.asarray(rasp_score, dtype=float)}
    full_fields = {}; roots = []; full_parents = None; phase = {"propagate_A_rasp": rasp_measure}
    for name, variant in variants.items():
        (score, diagnostics), measured = _measured(lambda variant=variant: rcvp_propagate(arrays["src"], arrays["dst"], arrays["timestamp"], arrays["relation_names"], arrays["rarity"], arrays["poi"], arrays["process_nodes"], variant))
        scores[name] = np.asarray(score, dtype=float); phase[f"propagate_{name}"] = measured
        if name == "E":
            full_fields = diagnostics.get("edge_fields", {}); roots = diagnostics.get("roots", [])
            full_parents = diagnostics.get("backward_parent")
    decisions = {}; progressive_audit = {}
    pruning_weights = config.get("pruning_weights", {"rarity": .1, "path": .1, "impact": .1, "behavior": .1})
    progressive_config = config.get("progressive", {"consistency_weight": .1, "redundancy_weight": .02})
    frozen_config["resolved_progressive_configs"] = {"G": dict(progressive_config), "G_no_redundancy": {**progressive_config, "redundancy_weight": 0.0}}
    from tc_pruning.rasp import temporal_fork_routes, temporal_routes
    rasp_backward = temporal_routes(arrays["src"], arrays["dst"], arrays["timestamp"], arrays["poi"])[0][0]
    rasp_parent = temporal_fork_routes(arrays["src"], arrays["dst"], arrays["timestamp"], arrays["poi"], rasp_backward)[0]
    rasp_dependencies = np.where(rasp_parent >= 0, rasp_parent, rasp_backward)
    legacy_diffusion = np.asarray([float(row.get("components", {}).get("diffusion", 0.0)) for row in rows])
    for ratio in config.get("budgets", [.05, .1, .2, .3]):
        budget = max(1, int(n * float(ratio)))
        key = f"A_rasp@{ratio:g}"
        decisions[key], phase[f"select_{key}"] = _measured(lambda: _select_fork(scores["A_rasp"], arrays, budget))
        for name in ("B", "C", "D", "E"):
            key = f"{name}@{ratio:g}"
            (decisions[key], progressive_audit[key]), phase[f"select_{key}"] = _measured(
                lambda name=name: _adaptive_mask(rows, scores[name], float(ratio), "rdp_guard", weights=pruning_weights, ordered_sequences=ordered_sequences, atomic_groups=atomic_groups))
        for key, call in (
            (f"A_rdp@{ratio:g}", lambda: _adaptive_mask(rows, legacy_diffusion, float(ratio), "rdp_guard", weights=pruning_weights, ordered_sequences=ordered_sequences, atomic_groups=atomic_groups)),
            (f"F@{ratio:g}", lambda: _adaptive_mask(rows, legacy_diffusion, float(ratio), "progressive", weights=pruning_weights, parents=rasp_dependencies, ordered_sequences=ordered_sequences, atomic_groups=atomic_groups, progressive_config=progressive_config, require_all_parents_valid=False)),
            (f"G@{ratio:g}", lambda: _adaptive_mask(rows, scores["E"], float(ratio), "progressive", full_fields, weights=pruning_weights, parents=full_parents, ordered_sequences=ordered_sequences, atomic_groups=atomic_groups, progressive_config=progressive_config)),
            (f"G_no_redundancy@{ratio:g}", lambda: _adaptive_mask(rows, scores["E"], float(ratio), "progressive", full_fields, weights=pruning_weights, parents=full_parents, ordered_sequences=ordered_sequences, atomic_groups=atomic_groups, progressive_config={**progressive_config, "redundancy_weight": 0.0}))):
            (decisions[key], progressive_audit[key]), phase[f"select_{key}"] = _measured(call)
    full_fields = {**full_fields, "diffusion_legacy": legacy_diffusion, "rasp_recomputed_score": scores["A_rasp"],
                   "diffusion_B_relation_only": scores["B"], "diffusion_C_time_fanout": scores["C"],
                   "diffusion_D_backward": scores["D"], "diffusion_E_verified": scores["E"],
                   "source_frozen_final_score": np.asarray([float(row.get("score", 0.0)) for row in rows])}
    edge_ids = [str(row.get("edge_id", i)) for i, row in enumerate(rows)]
    for field, source in (
        ("pruning_group_id", "group_id"),
        ("progressive_removal_round", "removal_round"),
        ("removal_priority", "removal_priority"),
        ("removal_attempted", "removal_attempted"),
        ("removal_allowed", "removal_allowed"),
        ("removal_rejection_reason", "rejection_reason"),
    ):
        full_fields[field] = [
            {method: progressive_audit[method].get(edge_id, {}).get(source) for method in sorted(progressive_audit) if method.startswith(("G@", "G_no_redundancy@"))}
            for edge_id in edge_ids
        ]
    timings = {**phase, "online_total": time.perf_counter() - started}
    memory = {"baseline_rss": rss_before, "peak_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}
    method_diagnostics = {}
    for method, mask in decisions.items():
        ratio = float(method.rsplit("@", 1)[1])
        result = progressive_audit.get(method, {}).get("_result", {})
        method_diagnostics[method] = {
            "requested_keep_ratio": ratio, "raw_event_budget": max(1, int(n * ratio)),
            "retained_raw_events": int(np.asarray(mask, dtype=bool).sum()),
            "budget_feasible": result.get("budget_feasible"),
            "budget_overflow_edges": result.get("budget_overflow_edges"),
            "path_certificate_valid": result.get("path_certificate_valid"),
            "strict_multistage_certificate_valid": result.get("strict_multistage_certificate_valid"),
            "certificate_reason": None if result else "not_available_for_frozen_array_replay",
            "source_pruning_provenance": replay_provenance,
        }
    manifest = freeze_online_artifacts(output, rows, decisions, full_fields, roots, frozen_config,
        implementation_paths=[ROOT / path for path in ("scripts/run_rcvp.py", "tc_pruning/rcvp.py", "tc_pruning/rcvp_config.py", "tc_pruning/rcvp_adapter.py", "tc_pruning/rcvp_ledger.py", "tc_pruning/pruning.py", "tc_pruning/progressive_pruning.py", "tc_pruning/causal.py", "tc_pruning/rasp.py", "tc_pruning/rdp_guard.py", "tc_pruning/depimpact.py", "tc_pruning/diffusion.py", "tc_pruning/models.py", "tc_pruning/evaluation.py", "tc_pruning/config.py", "tc_pruning/score_ledger.py")], timings=timings, memory=memory,
        method_diagnostics=method_diagnostics)
    validation = validate_frozen_artifacts(output)
    _write_json(output / "validation.json", validation)
    return manifest


def _evaluate_admitted(case: str, inputs: Path, output: Path) -> dict[str, Any]:
    """Open audited UBC labels only after the online manifest exists."""
    specs = json.loads(inputs.read_text())["cases"]; spec = specs[case]
    policy = json.loads((ROOT / "configs/benchmark-admission.json").read_text())
    if policy["cases"].get(case, {}).get("positive_node_retention") is not True:
        raise ValueError("case is not admitted for positive retention")
    audit = json.loads((ROOT / "docs/uploaded-groundtruth-evaluation.json").read_text())
    item = next(row for row in audit["archive"]["files"] if row["case_key"] == case)
    archive = Path(audit["archive"]["source"]["path"])
    with zipfile.ZipFile(archive) as zipped: blob = zipped.read(item["member"])
    if hashlib.sha256(blob).hexdigest() != policy["cases"][case]["source_sha256"]: raise ValueError("label source hash mismatch")
    positive = {row[0].strip().upper() for row in csv.reader(io.StringIO(blob.decode("utf-8-sig"))) if row}
    database = Path(spec["database"]); window = item["evaluation"]["derived_events"]["protocol_window_ns"]
    reference = set(); placeholders = ",".join("?" for _ in positive)
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        for source in positive:
            for event_id, timestamp in connection.execute(f"SELECT event_id,timestamp_ns FROM edges WHERE src=? AND dst IN ({placeholders})", [source, *positive]):
                if window[0] is None or window[0] <= timestamp <= window[1]: reference.add(str(event_id).upper())
    rows = _read_audit(output / AUDIT_NAME)
    metrics = evaluate_frozen_positive_ids(rows, positive, reference)
    fixed_path = Path(spec["ledger"]).parent.parent / "fixed-reference.json"
    path_provenance = None
    if fixed_path.is_file():
        fixed = json.loads(fixed_path.read_text()); paths = [tuple(map(str, path)) for path in fixed.get("attack_paths", [])]
        by_event = {str(row["event_id"]): row for row in rows}
        covered_paths = [path for path in paths if path and all(event in by_event for event in path)]
        strict_paths = []
        for path in covered_paths:
            path_rows = [by_event[event] for event in path]
            if all(int(left["timestamp_ns"]) < int(right["timestamp_ns"]) and _causal_row_endpoints(left)[1] == _causal_row_endpoints(right)[0] for left, right in zip(path_rows, path_rows[1:])):
                strict_paths.append(path)
        for method, values in metrics.items():
            retained_paths = sum(all(by_event[event]["decisions"][method] for event in path) for path in covered_paths)
            retained_strict = sum(all(by_event[event]["decisions"][method] for event in path) for path in strict_paths)
            values["candidate_derived_path_recall"] = _ratio(len(covered_paths), len(paths))
            values["conditional_derived_path_retention"] = _ratio(retained_paths, len(covered_paths))
            values["pruned_derived_path_recall"] = _ratio(retained_paths, len(paths))
            values["strict_derived_path_eligibility"] = _ratio(len(strict_paths), len(paths))
            values["conditional_strict_derived_path_retention"] = _ratio(retained_strict, len(strict_paths))
            values["pruned_strict_derived_path_recall"] = _ratio(retained_strict, len(paths))
        path_provenance = {"path": str(fixed_path.resolve()), "sha256": sha256_file(fixed_path), "verification_status": "automatically_derived_not_human_verified", "stored_path_policy": "exact_event_sequence; may be nondecreasing", "strict_subset_policy": "directed endpoint continuity and timestamp_ns strictly increasing"}
    result = {"case": case, "label_class": "audited_positive_entities_and_rule_derived_internal_events", "metrics": metrics,
              "ground_truth_used_for_selection": False, "frozen_audit_sha256": sha256_file(output / AUDIT_NAME), "derived_path_source": path_provenance}
    _write_json(output / "offline-evaluation.json", result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--case")
    parser.add_argument("--inputs", type=Path, default=ROOT / "docs/uploaded-groundtruth-inputs.json")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/rcvp_evaluation.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.validate:
        print(json.dumps(validate_frozen_artifacts(args.validate), indent=2)); return 0
    if not args.case or not args.output: parser.error("--case and --output are required unless --validate is used")
    config = json.loads(args.config.read_text()); spec = json.loads(args.inputs.read_text())["cases"][args.case]
    run_online_case(args.case, Path(spec["ledger"]), args.output, config)
    _evaluate_admitted(args.case, args.inputs, args.output)
    print(f"COMPLETE {args.case} {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
