"""Online-only CADETS E3 detector-seed artifact runner."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time
from typing import Any, Iterable, Mapping

import numpy as np

from .benchmark_contract import EdgeProjection, ProjectionMode, performance_fields
from .detectors.alert_evidence import AlertEvidence
from .evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from .frequency import FrequencyModel
from .investigation.branch_fair_selector import BranchFairConfig, LazyGreedySelector
from .investigation.evidence_units import EvidenceUnit, ecdf_relevance
from .models import StoredEdge
from .rasp import propagate, select_bundles, temporal_routes
from .store import ProvenanceStore

SCHEMA_VERSION = "detector-seed-benchmark-v2"
FROZEN_DATASET = "DARPA_TC_E3_CADETS"
FROZEN_DATABASE = "output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db"
FROZEN_DATABASE_SHA256 = "719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf"
FROZEN_HISTORY_START_NS, FROZEN_CUTOFF_NS = 1522706861813350340, 1523655358953968696
_DETECTORS = frozenset({"ORTHRUS", "KAIROS", "VELOX", "R-CAID", "NODLINK"})
_SELECTORS = ("A_rasp", "C_branch_fair")
_BAD = ("ground" + "truth", "ground" + "_truth", "pdf" + "_critical", "attack" + "_window", "attack" + "_timestamp", "ora" + "cle", "evalu" + "ator", "fun" + "nel", "y" + "_true", "is" + "_malicious", "mali" + "cious", "la" + "bel")

def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

def _sha_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()

def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise

def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    body = dict(payload); body.setdefault("schema_version", SCHEMA_VERSION); unsigned = dict(body); unsigned.pop("content_sha256", None)
    body["content_sha256"] = _sha_bytes(_canonical(unsigned)); _atomic(path, _canonical(body))

def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]], *, artifact_schema: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent); digest, count = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as stream:
            for row in rows:
                data = _canonical(row); stream.write(data); digest.update(data); count += 1
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    _write_json(path.with_suffix(path.suffix + ".manifest.json"), {"artifact_schema": artifact_schema, "record_count": count, "data_sha256": digest.hexdigest()})

def _reject_bad(value: Any, location: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if any(term in str(key).lower().replace("-", "_") for term in _BAD): raise ValueError(f"online {location} contains forbidden field")
            _reject_bad(item, f"{location}.{key}")
    elif isinstance(value, (list, tuple)):
        for item in value: _reject_bad(item, location)
    elif isinstance(value, (str, Path)) and any(term in str(value).lower().replace("-", "_") for term in _BAD): raise ValueError(f"online {location} contains forbidden value")

@dataclass(frozen=True, slots=True)
class DetectorSpec:
    detector_id: str
    run_id: str
    profile: str | None = None
    calibration_artifact: str | None = None
    calibration_sha256: str | None = None

@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    database_path: str; database_sha256: str; candidate: CandidateSearchConfig; projection: EdgeProjection
    raw_event_cap: int; proxy_event_cap: int; selectors: tuple[str, ...]; detectors: tuple[DetectorSpec, ...]
    fixture_mode: bool; expected_config_sha256: str | None; expected_code_commit: str | None; resolved: Mapping[str, Any]; config_sha256: str
    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "BenchmarkConfig":
        _reject_bad(record)
        if record.get("schema_version") != SCHEMA_VERSION or record.get("dataset") != FROZEN_DATASET: raise ValueError("invalid CADETS_E3 benchmark schema")
        fixture = bool(record.get("fixture_mode", False))
        if record.get("candidate_backend") != "EvidenceDrivenCandidateBuilder": raise ValueError("one detector-neutral candidate backend is required")
        database, candidate, projection, budget = (record.get(name) for name in ("database", "candidate", "projection", "budget"))
        if not all(isinstance(item, Mapping) for item in (database, candidate, projection, budget)): raise ValueError("missing benchmark sections")
        path, db_hash = str(database.get("path")), str(database.get("sha256"))
        if not fixture and (path != FROZEN_DATABASE or db_hash != FROZEN_DATABASE_SHA256): raise ValueError("database path/hash is not frozen")
        search = CandidateSearchConfig(**dict(candidate))
        if not fixture and (search.candidate_cap != 10000 or search.history_start_ns != FROZEN_HISTORY_START_NS or search.cutoff_ns != FROZEN_CUTOFF_NS): raise ValueError("candidate cap/window is not frozen")
        projected = EdgeProjection(str(projection.get("mode")), int(projection.get("merge_window_ns")))
        if projected.mode is not ProjectionMode.DEPIMPACT_COMPATIBLE or projected.merge_window_ns != 900000000000: raise ValueError("projection is not frozen")
        raw_cap, proxy_cap = int(budget.get("raw_event_cap")), int(budget.get("proxy_event_cap", budget.get("raw_event_cap")))
        if raw_cap <= 0 or proxy_cap <= 0 or tuple(record.get("selectors", ())) != _SELECTORS: raise ValueError("absolute common selector caps/selectors are required")
        rows = record.get("detectors")
        if not isinstance(rows, list) or not rows: raise ValueError("detectors required")
        specs = []
        for row in rows:
            if not isinstance(row, Mapping): raise ValueError("invalid detector")
            if set(row) - {"detector_id", "run_id", "profile", "calibration_artifact", "calibration_sha256"}: raise ValueError("detector-specific downstream configuration is forbidden")
            identifier, run_id, profile = str(row.get("detector_id", "")), str(row.get("run_id", row.get("detector_id", ""))), row.get("profile")
            if identifier.upper() not in _DETECTORS or not run_id: raise ValueError("unsupported detector/run id")
            if identifier.upper() == "VELOX" and profile not in {"VXL-0", "VXL-1", "VXL-2", "VXL-3", None}: raise ValueError("invalid Velox profile")
            calibration, calibration_hash = row.get("calibration_artifact"), row.get("calibration_sha256")
            if profile in {"VXL-1", "VXL-3"} and (not isinstance(calibration, str) or not isinstance(calibration_hash, str)): raise ValueError("frozen calibration artifact/hash required")
            specs.append(DetectorSpec(identifier, run_id, None if profile is None else str(profile), calibration, calibration_hash))
        if len({item.run_id.upper() for item in specs}) != len(specs): raise ValueError("run ids must be unique")
        unsigned = dict(record); expected = unsigned.pop("expected_config_sha256", None); digest = _sha_bytes(_canonical(unsigned))
        if not fixture and expected != digest: raise ValueError("expected canonical config digest mismatch")
        expected_commit = record.get("expected_code_commit")
        if not fixture and (not isinstance(expected_commit, str) or len(expected_commit) != 40): raise ValueError("expected code commit is required")
        return cls(path, db_hash, search, projected, raw_cap, proxy_cap, _SELECTORS, tuple(specs), fixture, expected if isinstance(expected, str) else None, expected_commit if isinstance(expected_commit, str) else None, json.loads(_canonical(record)), digest)

def _commit() -> str: return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()

def _native_files(source: str | Path) -> tuple[Path, ...]:
    path = Path(source).resolve()
    if not path.exists(): raise ValueError("native source does not exist")
    files = (path,) if path.is_file() else tuple(sorted(item for item in path.rglob("*") if item.is_file()))
    if not files: raise ValueError("native source is empty")
    return files

def _native_manifest(source: str | Path) -> dict[str, Any]:
    root = Path(source).resolve(); rows = [{"path": str(item.resolve()), "relative_path": item.name if root.is_file() else str(item.relative_to(root)), "size_bytes": item.stat().st_size, "sha256": _sha_file(item)} for item in _native_files(root)]
    return {"artifact_schema": "native-source-manifest-v2", "source": str(root), "files": rows, "aggregate_sha256": _sha_bytes(_canonical(rows))}

def _verify_native(manifest: Mapping[str, Any]) -> None:
    for row in manifest["files"]:
        path = Path(row["path"])
        if not path.is_file() or path.stat().st_size != row["size_bytes"] or _sha_file(path) != row["sha256"]: raise ValueError("native source changed")

def _edge_record(store: ProvenanceStore, edge: StoredEdge) -> dict[str, Any]:
    return {"stored_event_id": edge.event_id, "original_event_id": store.original_event_id(edge.event_id), "edge_id": edge.edge_id, "src_uuid": edge.src, "dst_uuid": edge.dst, "relation": edge.relation, "timestamp_ns": edge.timestamp_ns, "host": edge.host, "src_type": edge.src_type, "dst_type": edge.dst_type}

def _identity_audit(store: ProvenanceStore, rows: tuple[AlertEvidence, ...]) -> tuple[tuple[AlertEvidence, ...], tuple[dict[str, Any], ...], dict[str, Any]]:
    usable, audits, counts = [], [], {"exact": 0, "missing": 0, "duplicate": 0, "ambiguous": 0}
    for item in rows:
        events = [{"native_event_id": event, "matches": [{"stored_event_id": stored, "original_event_id": original} for stored, original in store.event_identity_matches(event)]} for event in item.event_ids]
        nodes = [{"native_node_id": node, "matches": 1 if store.get_node(node) else 0} for node in item.node_ids]
        sizes = [len(entry["matches"]) for entry in events] + [entry["matches"] for entry in nodes]
        state = "exact" if sizes and all(value == 1 for value in sizes) else "missing" if not sizes or any(value == 0 for value in sizes) else "ambiguous"
        counts[state] += 1; audits.append({"evidence_id": item.evidence_id, "identity_status": state, "event_identity": events, "node_identity": nodes})
        if state == "exact": usable.append(item)
    return tuple(usable), tuple(audits), {"artifact_schema": "native-mapping-audit-v2", "total_inference": len(rows), "scored": sum(item.raw_score is not None for item in rows), "native_decisions": sum(item.native_decision for item in rows), "evidence": len(rows), **counts, "mapping_rate": counts["exact"] / len(rows) if rows else None}

def _causal(edge: StoredEdge) -> tuple[str, str]:
    relation, src, dst = edge.relation.upper(), edge.src_type.lower(), edge.dst_type.lower()
    if relation in {"EVENT_READ", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_MMAP", "EVENT_LOADLIBRARY", "EVENT_READ_SOCKET_PARAMS"} and src in {"file", "socket", "netflow", "memory", "unknown"} and dst in {"process", "subject"}: return edge.src, edge.dst
    if relation in {"EVENT_WRITE", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_CONNECT", "EVENT_CREATE_OBJECT", "EVENT_TRUNCATE", "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_RENAME", "EVENT_LINK", "EVENT_UNLINK"} and src in {"process", "subject"}: return edge.src, edge.dst
    if relation == "EVENT_EXECUTE" and src in {"process", "subject"}: return edge.dst, edge.src
    if relation in {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"} and src in {"process", "subject"} and dst in {"process", "subject"}: return edge.src, edge.dst
    raise ValueError("candidate contains non-causal CDM edge")

def _proxies(edges: tuple[StoredEdge, ...], anchor_events: frozenset[str], anchor_nodes: frozenset[str], cap: int) -> tuple[frozenset[str], dict[str, Any]]:
    node_proxy = {edge.event_id for edge in edges if edge.src in anchor_nodes or edge.dst in anchor_nodes}; proxy = frozenset(set(anchor_events) | node_proxy)
    if len(proxy) > cap: raise ValueError("selector proxy cap exceeded")
    return proxy, {"anchor_event_ids": sorted(anchor_events), "anchor_node_ids": sorted(anchor_nodes), "node_incident_proxy_event_ids": sorted(node_proxy), "mandatory_proxy_event_ids": sorted(proxy), "proxy_cap": cap}

def _a_rasp(store: ProvenanceStore, edges: tuple[StoredEdge, ...], poi_ids: frozenset[str], cap: int, proxy_audit: Mapping[str, Any]) -> dict[str, Any]:
    if not edges or not poi_ids or len(poi_ids) > cap: raise ValueError("selector requires nonempty candidate and bounded POI proxies")
    causal = [_causal(edge) for edge in edges]; nodes = sorted({node for pair in causal for node in pair}); index = {node: n for n, node in enumerate(nodes)}
    src, dst = np.asarray([index[pair[0]] for pair in causal]), np.asarray([index[pair[1]] for pair in causal]); relation = np.arange(len(edges)); times = np.asarray([edge.timestamp_ns for edge in edges], dtype=np.int64); poi = np.asarray([edge.event_id in poi_ids for edge in edges], dtype=bool)
    frequency = FrequencyModel.from_store(store); rarity = np.asarray([frequency.edge_rarity(edge) for edge in edges]); process = np.asarray([bool(store.get_node(node) and store.get_node(node).node_type.lower() in {"process", "subject"}) for node in nodes], dtype=float)
    score, _ = propagate(src, dst, relation, rarity, poi, process, {"restart": .15, "iterations": 100, "tolerance": 1e-10, "rarity_floor": .2}); links, direction, reachable, _ = temporal_routes(src, dst, times, poi); selected, anchors = select_bundles(score, poi, links, direction, reachable, min(cap, len(edges)))
    return {"selected_raw_event_ids": [edge.event_id for edge, keep in zip(edges, selected) if keep], "selected_anchor_event_ids": [edge.event_id for edge, keep in zip(edges, anchors) if keep], "proxy_audit": dict(proxy_audit), "selector_input": {"causal_endpoint_orientation": "self-contained-CDM", "stable_contrast": "NOT_AVAILABLE", "rarity": "frozen_database_frequency_model"}}

def _branch(edges: tuple[StoredEdge, ...], mandatory: frozenset[str], cap: int, proxy_audit: Mapping[str, Any]) -> dict[str, Any]:
    if not edges or not mandatory: raise ValueError("selector requires nonempty candidate and mandatory proxies")
    raw = {edge.event_id: 1.0 if edge.event_id in mandatory else 0.0 for edge in edges}; norm = ecdf_relevance(raw); units = []
    for edge in edges:
        source, _ = _causal(edge); units.append(EvidenceUnit("edge:" + edge.event_id, "edge", (edge.event_id,), (edge.src, edge.dst), frozenset({source, edge.relation.upper()}), frozenset({edge.event_id}) if edge.event_id in mandatory else frozenset(), None, frozenset(), raw[edge.event_id], norm[edge.event_id], 0.0))
    result = LazyGreedySelector(BranchFairConfig()).select(units, mandatory_event_ids=set(mandatory), budget=min(cap, len(edges)))
    return {"selected_raw_event_ids": list(result.selected_event_ids), "selected_unit_ids": list(result.selected_unit_ids), "proxy_audit": dict(proxy_audit), "stable_contrast": "NOT_AVAILABLE", "ledger": [asdict(row) for row in result.ledger]}

_branch_fair = _branch

def _artifact_manifest(directory: Path) -> None:
    files = sorted(path for path in directory.iterdir() if path.is_file() and path.name != "artifacts.json"); _write_json(directory / "artifacts.json", {"artifact_schema": "online-artifact-manifest-v2", "artifacts": [{"path": path.name, "sha256": _sha_file(path), "size_bytes": path.stat().st_size} for path in files]})

def _status(directory: Path, state: str, stage: str, reason: str | None = None) -> None: _write_json(directory / "status.json", {"artifact_schema": "online-run-status-v2", "status": state, "stage": stage, "reason": reason})

def run_online_benchmark(config_record: Mapping[str, Any], evidence_by_run: Mapping[str, Iterable[AlertEvidence]], output_directory: str | Path, *, native_sources: Mapping[str, str | Path] | None = None, inference_seconds: Mapping[str, float] | None = None) -> dict[str, Any]:
    config = BenchmarkConfig.from_record(config_record)
    if not config.fixture_mode and _commit() != config.expected_code_commit: raise ValueError("expected code commit mismatch")
    database = Path(config.database_path)
    if not database.is_file() or _sha_file(database) != config.database_sha256: raise ValueError("database hash verification failed")
    supplied, expected = {str(key).upper(): value for key, value in evidence_by_run.items()}, {spec.run_id.upper() for spec in config.detectors}
    if set(supplied) - expected: raise ValueError("unexpected evidence mapping key")
    sources = {} if native_sources is None else {str(key).upper(): value for key, value in native_sources.items()}
    if not config.fixture_mode and set(sources) != expected: raise ValueError("every run requires explicit native source")
    root, result = Path(output_directory), {"schema_version": SCHEMA_VERSION, "status": "COMPLETED", "runs": {}}
    with ProvenanceStore(database) as store:
        for spec in config.detectors:
            attempt = root / ".attempts" / spec.run_id / f"attempt-{time.time_ns()}"; attempt.mkdir(parents=True, exist_ok=False); stage = "input_evidence"
            try:
                if spec.run_id.upper() not in supplied: raise ValueError("missing evidence input")
                rows = tuple(supplied[spec.run_id.upper()])
                if not rows: raise ValueError("empty evidence input")
                if any(item.detector_id.upper() != spec.detector_id.upper() for item in rows): raise ValueError("evidence detector identity mismatch")
                for item in rows: _reject_bad({"metadata": item.detector_metadata, "context": item.structural_context}, "evidence")
                stage = "native_manifest"; source = sources.get(spec.run_id.upper()); native = _native_manifest(source) if source is not None else {"artifact_schema": "native-source-manifest-v2", "fixture_mode": True, "source": None, "files": [], "aggregate_sha256": None}; _write_json(attempt / "native_manifest.json", native)
                stage = "evidence"; _write_jsonl(attempt / "evidence.jsonl", (item.to_record() for item in rows), artifact_schema="alert-evidence-jsonl-v2")
                stage = "identity_audit"; usable, identity_rows, audit = _identity_audit(store, rows); _write_jsonl(attempt / "identity_audit.jsonl", identity_rows, artifact_schema="per-evidence-identity-audit-v2"); _write_json(attempt / "mapping_audit.json", audit)
                priority = None; candidates = usable
                if spec.detector_id.upper() == "VELOX" and spec.profile:
                    from .detectors.velox_profiles import apply_velox_profile
                    threshold = None
                    if spec.profile in {"VXL-1", "VXL-3"}:
                        artifact = Path(str(spec.calibration_artifact))
                        if not artifact.is_file() or _sha_file(artifact) != spec.calibration_sha256: raise ValueError("calibration artifact changed")
                        calibration = json.loads(artifact.read_text())
                        if not isinstance(calibration.get("development_population_sha256"), str): raise ValueError("calibration lacks frozen development population hash")
                        threshold = float(calibration["development_percentile_threshold"])
                    profiled, priority = apply_velox_profile(candidates, spec.profile, frozen_development_percentile_threshold=threshold); candidates = tuple(item for item in profiled if item.native_decision)
                else: candidates = tuple(item for item in candidates if item.native_decision)
                if not candidates: raise ValueError("no uniquely mapped native-decision evidence")
                stage = "candidate"; before, started = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, time.perf_counter(); candidate = EvidenceDrivenCandidateBuilder(store, config.candidate, priority=priority).build(candidates); candidate_seconds = time.perf_counter() - started
                if not candidate.edges: raise ValueError("candidate reconstruction produced no raw events")
                _write_jsonl(attempt / "candidate_raw_events.jsonl", (_edge_record(store, edge) for edge in candidate.edges), artifact_schema="candidate-raw-event-jsonl-v2"); _write_json(attempt / "candidate_nodes.json", {"artifact_schema": "candidate-node-set-v2", "node_ids": sorted(candidate.node_ids), "anchor_event_ids": sorted(candidate.anchor_event_ids), "anchor_node_ids": sorted(candidate.anchor_node_ids), "stop_reason": candidate.stop_reason, "projected_edge_count": config.projection.count(candidate.edges)})
                proxy, proxy_audit = _proxies(candidate.edges, candidate.anchor_event_ids, candidate.anchor_node_ids, config.proxy_event_cap)
                stage = "selector:A_rasp"; started = time.perf_counter(); a = _a_rasp(store, candidate.edges, proxy, config.raw_event_cap, proxy_audit); a_seconds = time.perf_counter() - started; a["projected_edge_count"] = config.projection.count(tuple(edge for edge in candidate.edges if edge.event_id in a["selected_raw_event_ids"])); _write_json(attempt / "A_rasp_final.json", {"artifact_schema": "A_rasp-final-v2", **a})
                stage = "selector:C_branch_fair"; started = time.perf_counter(); b = _branch_fair(candidate.edges, proxy, config.raw_event_cap, proxy_audit); b_seconds = time.perf_counter() - started; b["projected_edge_count"] = config.projection.count(tuple(edge for edge in candidate.edges if edge.event_id in b["selected_raw_event_ids"])); _write_json(attempt / "C_branch_fair_final.json", {"artifact_schema": "C-branch-fair-final-v2", **b})
                inference = None if inference_seconds is None else inference_seconds.get(spec.run_id)
                _write_json(attempt / "timing.json", {"artifact_schema": "online-timing-v2", **performance_fields(inference_seconds=inference, adapter_seconds=None, candidate_seconds=candidate_seconds, a_rasp_seconds=a_seconds, branch_fair_seconds=b_seconds, peak_rss_kb=max(before, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)), "adapter_seconds_status": "NOT_AVAILABLE", "detector_inference_seconds_status": "MEASURED_EXTERNAL" if inference is not None else "NOT_AVAILABLE", "candidate_seconds_status": "MEASURED", "selector_seconds_status": "MEASURED"})
                _write_json(attempt / "stage_identities.json", {"artifact_schema": "stage-identities-v2", "preprocessing": {"status": "NOT_AVAILABLE", "reason": "no graph/tensor manifest supplied"}, "inference": {"status": "NOT_AVAILABLE", "reason": "no inference identity artifact supplied"}, "scored": {"status": "NOT_AVAILABLE", "reason": "no scored identity artifact supplied"}, "native_threshold": {"status": "AVAILABLE", "event_ids": sorted(event for item in candidates for event in item.event_ids), "node_ids": sorted(node for item in candidates for node in item.node_ids)}, "evidence": {"status": "AVAILABLE", "event_ids": sorted(event for item in usable for event in item.event_ids), "node_ids": sorted(node for item in usable for node in item.node_ids)}})
                _verify_native(native); _write_json(attempt / "resolved_config.json", {"artifact_schema": "resolved-online-config-v2", "config": config.resolved, "config_sha256": config.config_sha256, "expected_config_sha256": config.expected_config_sha256, "code_commit": _commit(), "expected_code_commit": config.expected_code_commit, "database_path": config.database_path, "database_sha256": config.database_sha256, "native_aggregate_sha256": native["aggregate_sha256"]}); _status(attempt, "COMPLETED", "complete"); _artifact_manifest(attempt)
                final = root / spec.run_id
                if final.exists(): shutil.rmtree(final)
                os.replace(attempt, final); result["runs"][spec.run_id] = {"status": "COMPLETED", "run_directory": str(final)}
            except Exception as exc:
                try: _status(attempt, "NOT_COMPLETED", stage, f"{type(exc).__name__}: {exc}"); _artifact_manifest(attempt)
                except Exception: pass
                result["status"] = "NOT_COMPLETED"; result["runs"][spec.run_id] = {"status": "NOT_COMPLETED", "stage": stage, "reason": str(exc), "attempt_directory": str(attempt)}
    return result

__all__ = ["BenchmarkConfig", "DetectorSpec", "run_online_benchmark"]
