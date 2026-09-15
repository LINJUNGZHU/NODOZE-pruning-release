"""Online, detector-neutral CADETS E3 seed benchmark artifact runner.

This module deliberately has no partial-positive labels, attack times, or
offline funnel dependency.  Those inputs live in detector_seed_benchmark_evaluation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import time
from typing import Any, Iterable, Mapping

import numpy as np

from .detectors.alert_evidence import AlertEvidence
from .evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from .frequency import FrequencyModel
from .investigation.branch_fair_selector import BranchFairConfig, LazyGreedySelector
from .investigation.evidence_units import EvidenceUnit, ecdf_relevance
from .models import StoredEdge
from .rasp import propagate, select_bundles, temporal_routes
from .seed_utility_evaluation import EdgeProjection, ProjectionMode, performance_fields
from .store import ProvenanceStore


SCHEMA_VERSION = "detector-seed-benchmark-v1"
FROZEN_DATASET = "DARPA_TC_E3_CADETS"
FROZEN_DATABASE = "output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db"
FROZEN_DATABASE_SHA256 = "719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf"
FROZEN_HISTORY_START_NS = 1522706861813350340
FROZEN_CUTOFF_NS = 1523655358953968696
_DETECTORS = frozenset({"ORTHRUS", "KAIROS", "VELOX", "R-CAID", "NODLINK"})
_SELECTORS = ("A_rasp", "C_branch_fair")
_FORBIDDEN_KEYS = ("groundtruth", "ground_truth", "pdf_critical", "attack_timestamp", "attack_window", "funnel", "oracle", "evaluator", "label")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    body = dict(payload)
    body.setdefault("schema_version", SCHEMA_VERSION)
    unsigned = dict(body)
    unsigned.pop("content_sha256", None)
    body["content_sha256"] = _sha256_bytes(_canonical(unsigned))
    _atomic_bytes(path, _canonical(body))


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]], *, schema: str) -> None:
    ordered = tuple(sorted((dict(row) for row in rows), key=lambda row: _canonical(row)))
    data = b"".join(_canonical(row) for row in ordered)
    _atomic_bytes(path, data)
    _write_json(path.with_suffix(path.suffix + ".manifest.json"), {
        "artifact_schema": schema, "record_count": len(ordered), "content_sha256": _sha256_bytes(data),
    })


def _reject_forbidden(value: Any, location: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower().replace("-", "_")
            if any(term in lowered for term in _FORBIDDEN_KEYS):
                raise ValueError(f"online {location} may not contain label-bearing key {key!r}")
            _reject_forbidden(item, f"{location}.{key}")
    elif isinstance(value, (tuple, list)):
        for item in value:
            _reject_forbidden(item, location)


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    detector_id: str
    profile: str | None
    frozen_development_percentile_threshold: float | None = None


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    database_path: str
    database_sha256: str
    candidate: CandidateSearchConfig
    projection: EdgeProjection
    raw_event_cap: int
    selection_fraction: float
    selectors: tuple[str, ...]
    detectors: tuple[DetectorSpec, ...]
    resolved: Mapping[str, Any]
    config_sha256: str

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "BenchmarkConfig":
        if not isinstance(record, Mapping):
            raise ValueError("benchmark config must be an object")
        _reject_forbidden(record)
        if record.get("schema_version") != SCHEMA_VERSION or record.get("dataset") != FROZEN_DATASET:
            raise ValueError("benchmark is CADETS_E3-only with the declared schema")
        if record.get("candidate_backend") != "EvidenceDrivenCandidateBuilder":
            raise ValueError("only EvidenceDrivenCandidateBuilder is permitted")
        database = record.get("database")
        candidate = record.get("candidate")
        projection = record.get("projection")
        budget = record.get("budget")
        if not all(isinstance(item, Mapping) for item in (database, candidate, projection, budget)):
            raise ValueError("database, candidate, projection, and budget are required objects")
        if set(database) != {"path", "sha256"}:
            raise ValueError("database must only specify path and sha256")
        path, digest = str(database["path"]), str(database["sha256"])
        if digest != FROZEN_DATABASE_SHA256 and not Path(path).name.startswith("mini"):
            raise ValueError("database sha256 does not match frozen CADETS_E3")
        search = CandidateSearchConfig(**dict(candidate))
        if search.candidate_cap != 10_000 and not Path(path).name.startswith("mini"):
            raise ValueError("CADETS_E3 candidate cap is frozen at 10000")
        if search.history_start_ns not in (None, FROZEN_HISTORY_START_NS) or search.cutoff_ns not in (None, FROZEN_CUTOFF_NS):
            raise ValueError("candidate time window differs from frozen CADETS_E3 bounds")
        search = CandidateSearchConfig(
            candidate_cap=search.candidate_cap, history_start_ns=search.history_start_ns or FROZEN_HISTORY_START_NS,
            cutoff_ns=search.cutoff_ns or FROZEN_CUTOFF_NS, max_strict_depth=search.max_strict_depth,
            max_control_depth=search.max_control_depth, enable_common_cause=search.enable_common_cause,
            scan_multiplier=search.scan_multiplier,
        )
        projected = EdgeProjection(ProjectionMode(str(projection.get("mode"))), int(projection.get("merge_window_ns")))
        if projected.mode is not ProjectionMode.DEPIMPACT_COMPATIBLE or projected.merge_window_ns != 900000000000:
            raise ValueError("DEPIMPACT-compatible 900000000000ns projection is required")
        raw_event_cap, fraction = int(budget.get("raw_event_cap")), float(budget.get("selection_fraction"))
        if raw_event_cap <= 0 or not 0 < fraction <= 1:
            raise ValueError("selector budget must be a positive cap and fraction in (0,1]")
        selectors = tuple(record.get("selectors", ()))
        if selectors != _SELECTORS:
            raise ValueError("selectors must be exactly A_rasp and C_branch_fair")
        detector_rows = record.get("detectors")
        if not isinstance(detector_rows, list) or not detector_rows:
            raise ValueError("at least one detector is required")
        detectors: list[DetectorSpec] = []
        for row in detector_rows:
            if not isinstance(row, Mapping) or set(row) - {"detector_id", "profile", "adapter", "frozen_development_percentile_threshold"}:
                raise ValueError("detector configuration may only select adapter/profile")
            identifier = str(row.get("detector_id", ""))
            if identifier.upper() not in _DETECTORS:
                raise ValueError("unsupported detector")
            profile = row.get("profile")
            if identifier.upper() == "VELOX" and profile not in {"VXL-0", "VXL-1", "VXL-2", "VXL-3", None}:
                raise ValueError("unsupported Velox profile")
            if identifier.upper() != "VELOX" and profile is not None:
                raise ValueError("only Velox accepts a profile")
            threshold = row.get("frozen_development_percentile_threshold")
            if threshold is not None and not isinstance(threshold, (int, float)):
                raise ValueError("profile threshold must be numeric")
            if identifier.upper() == "VELOX" and profile in {"VXL-1", "VXL-3"} and threshold is None:
                raise ValueError("VXL-1 and VXL-3 require a frozen development threshold")
            detectors.append(DetectorSpec(identifier, None if profile is None else str(profile), None if threshold is None else float(threshold)))
        if len({item.detector_id.upper() for item in detectors}) != len(detectors):
            raise ValueError("duplicate detector configuration")
        resolved = json.loads(_canonical(record))
        return cls(path, digest, search, projected, raw_event_cap, fraction, selectors, tuple(detectors), resolved, _sha256_bytes(_canonical(resolved)))


def _edge_record(edge: StoredEdge) -> dict[str, Any]:
    return {"raw_event_id": edge.event_id, "edge_id": edge.edge_id, "src_uuid": edge.src, "dst_uuid": edge.dst,
            "relation": edge.relation, "timestamp_ns": edge.timestamp_ns, "host": edge.host,
            "src_type": edge.src_type, "dst_type": edge.dst_type}


def _mapping_audit(evidence: Iterable[AlertEvidence]) -> dict[str, Any]:
    rows = tuple(evidence)
    exact = sum(item.mapping_quality.value == "EXACT" for item in rows)
    qualities = {name: sum(item.mapping_quality.value == name for item in rows) for name in ("EXACT", "UNMAPPED")}
    event_items, node_items = sum(bool(item.event_ids) for item in rows), sum(bool(item.node_ids) and not item.event_ids for item in rows)
    return {"artifact_schema": "native-mapping-audit-v1", "total_inference": len(rows), "scored": sum(item.raw_score is not None for item in rows),
            "native_decisions": sum(item.native_decision for item in rows), "evidence": len(rows), "exact": exact,
            "missing": qualities["UNMAPPED"], "duplicate": 0, "ambiguous": 0,
            "mapping_rate": exact / len(rows) if rows else None, "identity_fields": {"event_evidence": event_items, "node_evidence": node_items}}


def _a_rasp(edges: tuple[StoredEdge, ...], anchors: frozenset[str], budget: int, store: ProvenanceStore) -> dict[str, Any]:
    if not edges:
        return {"selected_raw_event_ids": [], "selector_input": {"A_rasp_contrast": "MISSING_STABLE_INPUT", "rarity": "MISSING_STABLE_INPUT"}}
    node_ids = sorted({node for edge in edges for node in (edge.src, edge.dst)})
    positions = {node: index for index, node in enumerate(node_ids)}
    relations = {value: index for index, value in enumerate(sorted({edge.relation for edge in edges}))}
    src = np.asarray([positions[edge.src] for edge in edges], dtype=np.int64)
    dst = np.asarray([positions[edge.dst] for edge in edges], dtype=np.int64)
    relation = np.asarray([relations[edge.relation] for edge in edges], dtype=np.int64)
    timestamp = np.asarray([edge.timestamp_ns for edge in edges], dtype=np.int64)
    poi = np.asarray([edge.event_id in anchors for edge in edges], dtype=bool)
    if not poi.any():
        raise ValueError("mapped evidence anchors did not resolve to candidate raw events")
    frequency = FrequencyModel.from_store(store)
    rarity = np.asarray([frequency.edge_rarity(edge) for edge in edges], dtype=float)
    process = np.asarray([store.get_node(node).node_type.lower() in {"process", "subject"} if store.get_node(node) else False for node in node_ids], dtype=float)
    score, _ = propagate(src, dst, relation, rarity, poi, process, {"restart": .15, "iterations": 100, "tolerance": 1e-10, "rarity_floor": .2})
    links, direction, reachable, _ = temporal_routes(src, dst, timestamp, poi)
    selected, selected_anchor = select_bundles(score, poi, links, direction, reachable, min(budget, len(edges)))
    return {"selected_raw_event_ids": [edge.event_id for edge, keep in zip(edges, selected) if keep],
            "selected_anchor_event_ids": [edge.event_id for edge, keep in zip(edges, selected_anchor) if keep],
            "selector_input": {"A_rasp_contrast": "MISSING_STABLE_INPUT", "rarity": "frozen_database_frequency_model"}}


def _branch_fair(edges: tuple[StoredEdge, ...], anchors: frozenset[str], budget: int) -> dict[str, Any]:
    raw_scores = {edge.event_id: 1.0 if edge.event_id in anchors else 0.0 for edge in edges}
    normalized = ecdf_relevance(raw_scores)
    units = tuple(EvidenceUnit("edge:" + edge.event_id, "edge", (edge.event_id,), (edge.src, edge.dst), frozenset({edge.src}),
                               frozenset({edge.event_id}) if edge.event_id in anchors else frozenset(), None, frozenset(), raw_scores[edge.event_id], normalized[edge.event_id], 1.0)
                  for edge in edges)
    result = LazyGreedySelector(BranchFairConfig()).select(units, mandatory_event_ids=set(), budget=min(budget, len(edges)))
    return {"selected_raw_event_ids": list(result.selected_event_ids), "selected_unit_ids": list(result.selected_unit_ids),
            "selector_input": {"unitization": "candidate StoredEdge CDM endpoints", "mapped_evidence_anchors": sorted(anchors)}, "ledger": [asdict(row) for row in result.ledger]}


def _commit() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _artifact_manifest(run_dir: Path) -> None:
    paths = sorted(path for path in run_dir.iterdir() if path.is_file() and path.name != "artifacts.json")
    _write_json(run_dir / "artifacts.json", {"artifact_schema": "online-artifact-manifest-v1", "artifacts": [
        {"path": path.name, "sha256": _sha256_file(path), "size_bytes": path.stat().st_size} for path in paths
    ]})


def run_online_benchmark(config_record: Mapping[str, Any], evidence_by_detector: Mapping[str, Iterable[AlertEvidence]], output_directory: str | Path) -> dict[str, Any]:
    """Run detector-independent reconstruction; evidence must already be normalized online data."""
    config = BenchmarkConfig.from_record(config_record)
    database = Path(config.database_path)
    if not database.is_file() or _sha256_file(database) != config.database_sha256:
        raise ValueError("database hash verification failed")
    result: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "status": "COMPLETED", "runs": {}}
    root = Path(output_directory)
    with ProvenanceStore(database) as store:
        for spec in config.detectors:
            run_dir = root / spec.detector_id
            run_dir.mkdir(parents=True, exist_ok=True)
            stage = "initialization"
            try:
                rows = tuple(sorted(evidence_by_detector.get(spec.detector_id, ()), key=lambda item: item.evidence_id))
                if any(item.detector_id.upper() != spec.detector_id.upper() for item in rows):
                    raise ValueError("evidence detector_id differs from configured detector")
                priority = None
                candidate_rows = rows
                if spec.detector_id.upper() == "VELOX" and spec.profile is not None:
                    from .detectors.velox_profiles import apply_velox_profile
                    rows, priority = apply_velox_profile(rows, spec.profile, frozen_development_percentile_threshold=spec.frozen_development_percentile_threshold)
                    candidate_rows = tuple(item for item in rows if item.native_decision)
                stage = "native_manifest"
                _write_json(run_dir / "native_manifest.json", {"artifact_schema": "native-source-manifest-v1", "detector_id": spec.detector_id,
                    "profile": spec.profile, "source_preservation_contract": "native output remains at the detector-owned immutable source; this manifest hashes normalized native records", "native_record_count": len(rows),
                    "normalized_record_sha256": _sha256_bytes(b"".join(_canonical(item.to_record()) for item in rows))})
                stage = "evidence"
                _write_jsonl(run_dir / "evidence.jsonl", (item.to_record() for item in rows), schema="alert-evidence-jsonl-v2")
                _write_json(run_dir / "mapping_audit.json", _mapping_audit(rows))
                stage = "candidate"
                started, before = time.perf_counter(), resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                candidate = EvidenceDrivenCandidateBuilder(store, config.candidate, priority=priority).build(candidate_rows)
                _write_jsonl(run_dir / "candidate_raw_events.jsonl", (_edge_record(edge) for edge in candidate.edges), schema="candidate-raw-event-jsonl-v1")
                _write_json(run_dir / "candidate_nodes.json", {"artifact_schema": "candidate-node-set-v1", "node_ids": sorted(candidate.node_ids), "anchor_event_ids": sorted(candidate.anchor_event_ids), "anchor_node_ids": sorted(candidate.anchor_node_ids), "stop_reason": candidate.stop_reason})
                stage = "selector:A_rasp"
                selector_budget = min(config.raw_event_cap, max(1, int(len(candidate.edges) * config.selection_fraction)))
                a_rasp = _a_rasp(candidate.edges, candidate.anchor_event_ids, selector_budget, store)
                _write_json(run_dir / "A_rasp_final.json", {"artifact_schema": "A_rasp-final-v1", **a_rasp})
                stage = "selector:C_branch_fair"
                branch = _branch_fair(candidate.edges, candidate.anchor_event_ids, selector_budget)
                _write_json(run_dir / "C_branch_fair_final.json", {"artifact_schema": "C-branch-fair-final-v1", **branch})
                stage = "timing"
                fields = performance_fields(inference_seconds=None, adapter_seconds=0.0, candidate_seconds=time.perf_counter() - started,
                    final_seconds=None, peak_rss_kb=max(before, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), candidate_edges=len(candidate.edges), final_edges=None)
                _write_json(run_dir / "timing.json", {"artifact_schema": "online-timing-v1", **fields})
                _write_json(run_dir / "resolved_config.json", {"artifact_schema": "resolved-online-config-v1", "config": config.resolved,
                    "config_sha256": config.config_sha256, "code_commit": _commit(), "database_sha256": config.database_sha256,
                    "database_path": config.database_path, "candidate_window": {"history_start_ns": config.candidate.history_start_ns, "cutoff_ns": config.candidate.cutoff_ns}})
                _artifact_manifest(run_dir)
                result["runs"][spec.detector_id] = {"status": "COMPLETED", "run_directory": str(run_dir)}
            except Exception as exc:
                _write_json(run_dir / "status.json", {"artifact_schema": "online-run-status-v1", "status": "NOT_COMPLETED", "stage": stage, "reason": f"{type(exc).__name__}: {exc}"})
                _artifact_manifest(run_dir)
                result["status"] = "NOT_COMPLETED"
                result["runs"][spec.detector_id] = {"status": "NOT_COMPLETED", "stage": stage, "reason": str(exc), "run_directory": str(run_dir)}
    return result


__all__ = ["BenchmarkConfig", "DetectorSpec", "run_online_benchmark"]
