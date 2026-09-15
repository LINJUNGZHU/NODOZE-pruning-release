"""Online-only CADETS E3 detector-seed artifact runner."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import sqlite3
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
_BAD = ("ground" + "truth", "ground" + "_truth", "pdf" + "_critical", "attack" + "_window", "attack" + "_timestamp", "attack" + "_times", "ora" + "cle", "evalu" + "ator", "fun" + "nel", "y" + "_true", "is" + "_malicious", "mali" + "cious", "la" + "bel", "known" + "_critical", "critical" + "_event", "critical" + "_edge", "positive" + "_ids", "truth", "gt")

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
    # This is deliberately token based.  A substring rule would reject benign
    # CDM text such as ``source`` because it happens to contain ``our``/``or``.
    # Compound authorities are matched only as whole underscore-delimited terms.
    def forbidden(text: str) -> bool:
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        joined = "_".join(tokens)
        singles = {"gt", "truth", "label", "malicious", "oracle", "funnel", "evaluator"}
        compounds = {"groundtruth", "ground_truth", "known_critical", "critical_event", "critical_edge", "positive_ids", "attack_time", "attack_times", "attack_window", "pdf_critical", "y_true", "is_malicious"}
        # A compound authority may be embedded in a generated key/path (for
        # example my_known_critical_event_ids_copy).  Do not apply this to
        # ordinary words such as source/target: none is an authority token.
        return any(token in singles for token in tokens) or any(term in joined for term in compounds)
    if isinstance(value, Mapping):
        for key, item in value.items():
            if forbidden(str(key)): raise ValueError(f"online {location} contains forbidden field")
            _reject_bad(item, f"{location}.{key}")
    elif isinstance(value, (list, tuple)):
        for item in value: _reject_bad(item, location)
    elif isinstance(value, (str, Path)) and forbidden(str(value)): raise ValueError(f"online {location} contains forbidden value")

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
        fixture_value = record.get("fixture_mode", False)
        if not isinstance(fixture_value, bool): raise ValueError("fixture_mode must be a JSON boolean")
        fixture = fixture_value
        if record.get("candidate_backend") != "EvidenceDrivenCandidateBuilder": raise ValueError("one detector-neutral candidate backend is required")
        database, candidate, projection, budget = (record.get(name) for name in ("database", "candidate", "projection", "budget"))
        if not all(isinstance(item, Mapping) for item in (database, candidate, projection, budget)): raise ValueError("missing benchmark sections")
        path, db_hash = str(database.get("path")), str(database.get("sha256"))
        if not fixture and (path != FROZEN_DATABASE or db_hash != FROZEN_DATABASE_SHA256): raise ValueError("database path/hash is not frozen")
        search = CandidateSearchConfig(**dict(candidate))
        if not fixture and (search.candidate_cap != 10000 or search.history_start_ns != FROZEN_HISTORY_START_NS or search.cutoff_ns != FROZEN_CUTOFF_NS): raise ValueError("candidate cap/window is not frozen")
        if not fixture and (search.max_control_depth != 2 or not search.enable_common_cause): raise ValueError("production control/common-cause lineage is frozen")
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
            if identifier.upper() not in _DETECTORS or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", run_id): raise ValueError("unsupported detector/run id")
            if identifier.upper() == "VELOX" and profile not in {"VXL-0", "VXL-1", "VXL-2", "VXL-3", None}: raise ValueError("invalid Velox profile")
            if identifier.upper() != "VELOX" and profile is not None: raise ValueError("only Velox accepts profiles")
            calibration, calibration_hash = row.get("calibration_artifact"), row.get("calibration_sha256")
            if profile in {"VXL-1", "VXL-3"} and (not isinstance(calibration, str) or not isinstance(calibration_hash, str)): raise ValueError("frozen calibration artifact/hash required")
            specs.append(DetectorSpec(identifier, run_id, None if profile is None else str(profile), calibration, calibration_hash))
        if len({item.run_id.upper() for item in specs}) != len(specs): raise ValueError("run ids must be unique")
        if not fixture:
            expected_runs = {"ORTHRUS", "KAIROS", "R-CAID", "NODLINK", "VXL-0", "VXL-1", "VXL-2", "VXL-3"}
            if {item.run_id for item in specs} != expected_runs or len(specs) != 8:
                raise ValueError("production benchmark requires exactly ORTHRUS, KAIROS, R-CAID, NODLINK and VXL-0..3")
            if any(item.profile != item.run_id for item in specs if item.detector_id.upper() == "VELOX"):
                raise ValueError("Velox profile must exactly equal its VXL run id")
            if any(item.run_id != item.detector_id.upper() for item in specs if item.detector_id.upper() != "VELOX"):
                raise ValueError("non-Velox run id must equal detector id")
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
    rows = []
    for row in manifest["files"]:
        path = Path(row["path"])
        if not path.is_file() or path.stat().st_size != row["size_bytes"] or _sha_file(path) != row["sha256"]: raise ValueError("native source changed")
        rows.append({"path": row["path"], "relative_path": row["relative_path"], "size_bytes": row["size_bytes"], "sha256": row["sha256"]})
    if manifest.get("files") and manifest.get("aggregate_sha256") != _sha_bytes(_canonical(rows)): raise ValueError("native aggregate hash mismatch")

def _edge_record(store: ProvenanceStore, edge: StoredEdge) -> dict[str, Any]:
    return {"stored_event_id": edge.event_id, "original_event_id": store.original_event_id(edge.event_id), "edge_id": edge.edge_id, "src_uuid": edge.src, "dst_uuid": edge.dst, "relation": edge.relation, "timestamp_ns": edge.timestamp_ns, "host": edge.host, "src_type": edge.src_type, "dst_type": edge.dst_type}

def _identity_audit(store: ProvenanceStore, rows: tuple[AlertEvidence, ...]) -> tuple[tuple[AlertEvidence, ...], tuple[dict[str, Any], ...], dict[str, Any]]:
    usable, audits, counts, seen = [], [], {"exact": 0, "missing": 0, "duplicate": 0, "ambiguous": 0}, set()
    for item in rows:
        events = [{"native_event_id": event, "matches": [{"stored_event_id": stored, "original_event_id": original} for stored, original in store.event_identity_matches(event)]} for event in item.event_ids]
        nodes = [{"native_node_id": node, "matches": 1 if store.get_node(node) else 0} for node in item.node_ids]
        sizes = [len(entry["matches"]) for entry in events] + [entry["matches"] for entry in nodes]
        native_object = str(item.detector_metadata.get("native_id", item.evidence_id))
        duplicate = item.evidence_id in seen or native_object in seen
        seen.update((item.evidence_id, native_object))
        coherent = True
        if item.granularity.value == "EDGE" and len(events) == 1 and len(events[0]["matches"]) == 1:
            stored = events[0]["matches"][0]["stored_event_id"]; edge = store.get_edge_by_event_id(stored)
            coherent = edge is not None and edge.src == item.src_uuid and edge.dst == item.dst_uuid and edge.relation == item.relation and (item.timestamp_start is None or edge.timestamp_ns == item.timestamp_start) and (item.timestamp_end is None or edge.timestamp_ns == item.timestamp_end)
        state = "duplicate" if duplicate else "exact" if coherent and sizes and all(value == 1 for value in sizes) else "missing" if not sizes or any(value == 0 for value in sizes) or not coherent else "ambiguous"
        counts[state] += 1; audits.append({"evidence_id": item.evidence_id, "identity_status": state, "event_identity": events, "node_identity": nodes})
        if state == "exact": usable.append(item)
    return tuple(usable), tuple(audits), {"artifact_schema": "native-mapping-audit-v2", "total_inference": len(rows), "scored": sum(item.raw_score is not None for item in rows), "native_decisions": sum(item.native_decision for item in rows), "evidence": len(rows), **counts, "mapping_rate": counts["exact"] / len(rows) if rows else None}

def _stage_evidence(store: ProvenanceStore, source: Iterable[AlertEvidence], directory: Path, detector_id: str) -> tuple[Path, dict[str, Any]]:
    """One-pass, disk-bounded evidence intake.

    The only full evidence representation is SQLite.  In particular this never
    sorts an input JSONL or builds a tuple/list of detector rows; candidate
    construction later reads a deterministic <= candidate-cap SQL subset.
    """
    db = directory / "evidence_staging.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE staged (ordinal INTEGER PRIMARY KEY, evidence_id TEXT NOT NULL, body TEXT NOT NULL, identity_status TEXT NOT NULL, native_id TEXT NOT NULL, native_decision INTEGER NOT NULL, calibrated_score REAL NOT NULL, raw_score REAL)")
    conn.execute("CREATE TABLE seen_identity (value TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE stage_identity (stage TEXT NOT NULL, kind TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY(stage,kind,identity))")
    conn.execute("CREATE INDEX staged_anchor ON staged(identity_status,native_decision,calibrated_score DESC,evidence_id)")
    counts = {"exact": 0, "missing": 0, "duplicate": 0, "ambiguous": 0, "total_inference": 0, "scored": 0, "native_decisions": 0, "evidence": 0}
    evidence_path, audit_path = directory / "evidence.jsonl", directory / "identity_audit.jsonl"
    efd, etmp = tempfile.mkstemp(prefix=".evidence.", dir=directory); afd, atmp = tempfile.mkstemp(prefix=".audit.", dir=directory)
    evidence_digest, audit_digest, ordinal = hashlib.sha256(), hashlib.sha256(), 0
    try:
        with os.fdopen(efd, "wb") as evidence_out, os.fdopen(afd, "wb") as audit_out:
            for item in source:
                if not isinstance(item, AlertEvidence): raise ValueError("evidence source yielded a non-AlertEvidence value")
                if item.detector_id.upper() != detector_id.upper(): raise ValueError("evidence detector identity mismatch")
                _reject_bad({"metadata": item.detector_metadata, "context": item.structural_context}, "evidence")
                body = item.to_record(); raw = _canonical(body); evidence_out.write(raw); evidence_digest.update(raw)
                events = [{"native_event_id": event, "matches": [{"stored_event_id": stored, "original_event_id": original} for stored, original in store.event_identity_matches(event)]} for event in item.event_ids]
                nodes = [{"native_node_id": node, "matches": 1 if store.get_node(node) else 0} for node in item.node_ids]
                sizes = [len(entry["matches"]) for entry in events] + [entry["matches"] for entry in nodes]
                native_object = str(item.detector_metadata.get("native_id", item.evidence_id))
                duplicate = False
                for identity in ("evidence:" + item.evidence_id, "native:" + native_object):
                    try: conn.execute("INSERT INTO seen_identity(value) VALUES (?)", (identity,))
                    except sqlite3.IntegrityError: duplicate = True
                coherent = True
                if item.granularity.value == "EDGE" and len(events) == 1 and len(events[0]["matches"]) == 1:
                    edge = store.get_edge_by_event_id(events[0]["matches"][0]["stored_event_id"])
                    coherent = edge is not None and edge.src == item.src_uuid and edge.dst == item.dst_uuid and edge.relation == item.relation and (item.timestamp_start is None or edge.timestamp_ns == item.timestamp_start) and (item.timestamp_end is None or edge.timestamp_ns == item.timestamp_end)
                state = "duplicate" if duplicate else "exact" if coherent and sizes and all(value == 1 for value in sizes) else "missing" if not sizes or any(value == 0 for value in sizes) or not coherent else "ambiguous"
                if state == "exact":
                    conn.executemany("INSERT OR IGNORE INTO stage_identity VALUES ('evidence',?,?)", (("event", event) for event in item.event_ids))
                    conn.executemany("INSERT OR IGNORE INTO stage_identity VALUES ('evidence',?,?)", (("node", node) for node in item.node_ids))
                counts[state] += 1; counts["total_inference"] += 1; counts["evidence"] += 1; counts["scored"] += item.raw_score is not None; counts["native_decisions"] += item.native_decision
                audit = {"evidence_id": item.evidence_id, "identity_status": state, "event_identity": events, "node_identity": nodes}; encoded = _canonical(audit); audit_out.write(encoded); audit_digest.update(encoded)
                conn.execute("INSERT INTO staged VALUES (?,?,?,?,?,?,?,?)", (ordinal, item.evidence_id, raw.decode().rstrip("\n"), state, native_object, int(item.native_decision), item.calibrated_score, item.raw_score)); ordinal += 1
            evidence_out.flush(); os.fsync(evidence_out.fileno()); audit_out.flush(); os.fsync(audit_out.fileno())
        conn.commit(); os.replace(etmp, evidence_path); os.replace(atmp, audit_path)
    except BaseException:
        conn.close()
        for temporary in (etmp, atmp):
            try: os.unlink(temporary)
            except FileNotFoundError: pass
        raise
    finally:
        if conn:
            conn.close()
    _write_json(evidence_path.with_suffix(".jsonl.manifest.json"), {"artifact_schema": "alert-evidence-jsonl-v2", "record_count": ordinal, "data_sha256": evidence_digest.hexdigest()})
    _write_json(audit_path.with_suffix(".jsonl.manifest.json"), {"artifact_schema": "per-evidence-identity-audit-v2", "record_count": ordinal, "data_sha256": audit_digest.hexdigest()})
    counts["mapping_rate"] = counts["exact"] / ordinal if ordinal else None
    identity_conn = sqlite3.connect(db)
    try: event_count = int(identity_conn.execute("SELECT COUNT(*) FROM stage_identity WHERE stage='evidence' AND kind='event'").fetchone()[0])
    finally: identity_conn.close()
    _write_json(directory / "stage_identity_manifest.json", {"artifact_schema": "stage-identity-sqlite-v1", "sqlite_path": "evidence_staging.sqlite", "evidence_event_count": event_count})
    return db, {"artifact_schema": "native-mapping-audit-v2", **counts}

def _read_staged_anchors(db: Path, *, profile: str | None, threshold: float | None, cap: int, priority_path: Path | None) -> tuple[AlertEvidence, Any | None]:
    """SQL-filter anchors and build disk priority without materializing all scores."""
    conn = sqlite3.connect(db)
    try:
        if profile in {"VXL-2", "VXL-3"}:
            from .evidence_candidate_builder import SQLiteEvidencePriority
            priority = SQLiteEvidencePriority(str(priority_path))
            def priority_rows():
                for (body,) in conn.execute("SELECT body FROM staged WHERE identity_status='exact' ORDER BY ordinal"):
                    item = AlertEvidence.from_record(json.loads(body)); score = item.raw_score if profile == "VXL-2" else item.calibrated_score
                    if score is not None:
                        for event in item.event_ids: yield event, float(score)
            priority.add_many(priority_rows())
        else: priority = None
        if profile in {"VXL-1", "VXL-3"}:
            predicate, predicate_args = "identity_status='exact' AND calibrated_score>=?", (float(threshold),)
        else:
            predicate, predicate_args = "identity_status='exact' AND native_decision=1", ()
        required = int(conn.execute("SELECT COUNT(*) FROM staged WHERE " + predicate, predicate_args).fetchone()[0])
        if required > cap: raise ValueError(f"required native anchors ({required}) exceed frozen candidate_cap ({cap}); refusing to redefine detector seed set")
        query, params = "SELECT body FROM staged WHERE " + predicate + " ORDER BY calibrated_score DESC,evidence_id", predicate_args
        anchors = tuple(AlertEvidence.from_record(json.loads(body)) for (body,) in conn.execute(query, params))
        return anchors, priority
    finally:
        conn.close()

def _causal(edge: StoredEdge) -> tuple[str, str]:
    relation, src, dst = edge.relation.upper(), edge.src_type.lower(), edge.dst_type.lower()
    if relation in {"EVENT_READ", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_MMAP", "EVENT_LOADLIBRARY", "EVENT_READ_SOCKET_PARAMS"} and src in {"file", "socket", "netflow", "memory", "unknown"} and dst in {"process", "subject"}: return edge.src, edge.dst
    if relation in {"EVENT_WRITE", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_CONNECT", "EVENT_CREATE_OBJECT", "EVENT_TRUNCATE", "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_RENAME", "EVENT_LINK", "EVENT_UNLINK"} and src in {"process", "subject"}: return edge.src, edge.dst
    if relation == "EVENT_EXECUTE" and src in {"process", "subject"}: return edge.dst, edge.src
    if relation in {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"} and src in {"process", "subject"} and dst in {"process", "subject"}: return edge.src, edge.dst
    raise ValueError("candidate contains non-causal CDM edge")

def _proxies(edges: tuple[StoredEdge, ...], anchor_events: frozenset[str], anchor_nodes: frozenset[str], cap: int, priority: Any | None = None) -> tuple[frozenset[str], dict[str, Any]]:
    if len(anchor_events) > cap: raise ValueError("selector cap cannot retain event anchors")
    # event anchors are mandatory once; node observations only nominate bounded
    # incident observation edges, ranked by detector-neutral search priority.
    incident = sorted((edge for edge in edges if edge.event_id not in anchor_events and (edge.src in anchor_nodes or edge.dst in anchor_nodes)), key=lambda edge: (-(priority.score_for_event(edge.event_id) if priority and priority.score_for_event(edge.event_id) is not None else float("-inf")), edge.timestamp_ns, edge.event_id))
    node_proxy = tuple(edge.event_id for edge in incident[:max(0, cap - len(anchor_events))])
    proxy = frozenset(set(anchor_events) | set(node_proxy))
    return proxy, {"anchor_event_ids": sorted(anchor_events), "anchor_node_ids": sorted(anchor_nodes), "node_incident_proxy_event_ids": list(node_proxy), "mandatory_proxy_event_ids": sorted(proxy), "proxy_cap": cap, "selection": "dedup-anchor,priority,time,event-id"}

def _a_rasp(store: ProvenanceStore, edges: tuple[StoredEdge, ...], poi_ids: frozenset[str], cap: int, proxy_audit: Mapping[str, Any]) -> dict[str, Any]:
    if not edges or not poi_ids or len(poi_ids) > cap: raise ValueError("selector requires nonempty candidate and bounded POI proxies")
    causal = [_causal(edge) for edge in edges]; nodes = sorted({node for pair in causal for node in pair}); index = {node: n for n, node in enumerate(nodes)}
    src, dst = np.asarray([index[pair[0]] for pair in causal]), np.asarray([index[pair[1]] for pair in causal]); relation_ids = {name: number for number, name in enumerate(sorted({edge.relation.upper() for edge in edges}))}; relation = np.asarray([relation_ids[edge.relation.upper()] for edge in edges]); times = np.asarray([edge.timestamp_ns for edge in edges], dtype=np.int64); poi = np.asarray([edge.event_id in poi_ids for edge in edges], dtype=bool)
    frequency = FrequencyModel.from_store(store); rarity = np.asarray([frequency.edge_rarity(edge) for edge in edges]); process = np.asarray([bool(store.get_node(node) and store.get_node(node).node_type.lower() in {"process", "subject"}) for node in nodes], dtype=float)
    score, _ = propagate(src, dst, relation, rarity, poi, process, {"restart": .15, "iterations": 100, "tolerance": 1e-10, "rarity_floor": .2}); links, direction, reachable, _ = temporal_routes(src, dst, times, poi); selected, anchors = select_bundles(score, poi, links, direction, reachable, min(cap, len(edges)))
    return {"selected_raw_event_ids": [edge.event_id for edge, keep in zip(edges, selected) if keep], "selected_anchor_event_ids": [edge.event_id for edge, keep in zip(edges, anchors) if keep], "proxy_audit": dict(proxy_audit), "selector_input": {"causal_endpoint_orientation": "self-contained-CDM", "stable_contrast": "NOT_AVAILABLE", "rarity": "frozen_database_frequency_model"}}

def _branch(edges: tuple[StoredEdge, ...], mandatory: frozenset[str], cap: int, proxy_audit: Mapping[str, Any], provenance: Mapping[str, tuple[str, ...]] | None = None) -> dict[str, Any]:
    if not edges or not mandatory: raise ValueError("selector requires nonempty candidate and mandatory proxies")
    raw = {edge.event_id: 1.0 if edge.event_id in mandatory else 0.0 for edge in edges}; norm = ecdf_relevance(raw); units = []
    for edge in edges:
        branches = frozenset((provenance or {}).get(edge.event_id, ("observation:" + edge.event_id,)))
        units.append(EvidenceUnit("edge:" + edge.event_id, "edge", (edge.event_id,), (edge.src, edge.dst), branches, frozenset({edge.event_id}) if edge.event_id in mandatory else frozenset(), None, frozenset(), raw[edge.event_id], norm[edge.event_id], 0.0))
    result = LazyGreedySelector(BranchFairConfig()).select(units, mandatory_event_ids=set(mandatory), budget=min(cap, len(edges)))
    return {"selected_raw_event_ids": list(result.selected_event_ids), "selected_unit_ids": list(result.selected_unit_ids), "proxy_audit": dict(proxy_audit), "stable_contrast": "NOT_AVAILABLE", "ledger": [asdict(row) for row in result.ledger]}

_branch_fair = _branch

def _artifact_manifest(directory: Path) -> None:
    files = sorted(path for path in directory.iterdir() if path.is_file() and path.name != "artifacts.json"); _write_json(directory / "artifacts.json", {"artifact_schema": "online-artifact-manifest-v2", "artifacts": [{"path": path.name, "sha256": _sha_file(path), "size_bytes": path.stat().st_size} for path in files]})

def _status(directory: Path, state: str, stage: str, reason: str | None = None) -> None: _write_json(directory / "status.json", {"artifact_schema": "online-run-status-v2", "status": state, "stage": stage, "reason": reason})

def _link_shared(shared: Path, attempt: Path) -> None:
    """Reference immutable common evidence without copying multi-GB data."""
    for name in ("evidence.jsonl", "evidence.jsonl.manifest.json", "identity_audit.jsonl", "identity_audit.jsonl.manifest.json", "evidence_staging.sqlite", "stage_identity_manifest.json"):
        source, target = shared / name, attempt / name
        if not source.is_file(): raise ValueError("shared evidence staging is incomplete")
        os.link(source, target)

def run_online_benchmark(config_record: Mapping[str, Any], evidence_by_run: Mapping[str, Iterable[AlertEvidence]], output_directory: str | Path, *, native_sources: Mapping[str, str | Path] | None = None, inference_seconds: Mapping[str, float] | None = None) -> dict[str, Any]:
    root = Path(output_directory); outer = root / ".attempts" / "runner" / f"attempt-{time.time_ns()}"; outer.mkdir(parents=True, exist_ok=False)
    try:
        _reject_bad(config_record, "config")
        config = BenchmarkConfig.from_record(config_record)
        if not config.fixture_mode and _commit() != config.expected_code_commit: raise ValueError("expected code commit mismatch")
        database = Path(config.database_path)
        if not database.is_file() or _sha_file(database) != config.database_sha256: raise ValueError("database hash verification failed")
    except Exception as exc:
        _status(outer, "NOT_COMPLETED", "input", f"{type(exc).__name__}: {exc}")
        return {"schema_version": SCHEMA_VERSION, "status": "NOT_COMPLETED", "stage": "input", "reason": str(exc), "attempt_directory": str(outer)}
    try:
        _reject_bad(evidence_by_run, "evidence mapping")
        supplied, expected = {str(key).upper(): value for key, value in evidence_by_run.items()}, {spec.run_id.upper() for spec in config.detectors}
        if set(supplied) - expected: raise ValueError("unexpected evidence mapping key")
        sources = {} if native_sources is None else {str(key).upper(): value for key, value in native_sources.items()}
        _reject_bad(sources, "native sources")
        if not config.fixture_mode and set(sources) != expected: raise ValueError("every run requires explicit native source")
    except Exception as exc:
        _status(outer, "NOT_COMPLETED", "input", f"{type(exc).__name__}: {exc}")
        return {"schema_version": SCHEMA_VERSION, "status": "NOT_COMPLETED", "stage": "input", "reason": str(exc), "attempt_directory": str(outer)}
    result = {"schema_version": SCHEMA_VERSION, "status": "COMPLETED", "runs": {}}
    shared_velox: dict[str, tuple[Path, dict[str, Any]]] = {}
    try: store_context = ProvenanceStore(database)
    except Exception as exc:
        _status(outer, "NOT_COMPLETED", "store", f"{type(exc).__name__}: {exc}")
        return {"schema_version": SCHEMA_VERSION, "status": "NOT_COMPLETED", "stage": "store", "reason": str(exc), "attempt_directory": str(outer)}
    with store_context as store:
        for spec in config.detectors:
            attempt = root / ".attempts" / spec.run_id / f"attempt-{time.time_ns()}"; attempt.mkdir(parents=True, exist_ok=False); stage = "input_evidence"; priority = None
            try:
                if spec.run_id.upper() not in supplied: raise ValueError("missing evidence input")
                stage = "native_manifest"; source = sources.get(spec.run_id.upper()); native = _native_manifest(source) if source is not None else {"artifact_schema": "native-source-manifest-v2", "fixture_mode": True, "source": None, "files": [], "aggregate_sha256": None}; _write_json(attempt / "native_manifest.json", native)
                stage = "input_evidence"
                # VXL-0..3 are four policies over one Velox output.  The
                # content-addressed native aggregate selects a single shared,
                # immutable SQLite/JSONL intake; attempts merely hard-link it.
                shared_key = native["aggregate_sha256"] if spec.detector_id.upper() == "VELOX" else None
                if shared_key is not None and shared_key in shared_velox:
                    staging, audit = shared_velox[shared_key]; _link_shared(staging.parent, attempt)
                elif shared_key is not None:
                    shared = root / "shared" / "velox" / shared_key; shared.mkdir(parents=True, exist_ok=True)
                    staging, audit = _stage_evidence(store, supplied[spec.run_id.upper()], shared, spec.detector_id)
                    shared_velox[shared_key] = (staging, audit); _link_shared(shared, attempt)
                else:
                    staging, audit = _stage_evidence(store, supplied[spec.run_id.upper()], attempt, spec.detector_id)
                if not audit["total_inference"]: raise ValueError("empty evidence input")
                _write_json(attempt / "mapping_audit.json", audit)
                priority = None; threshold = None
                if spec.detector_id.upper() == "VELOX" and spec.profile:
                    threshold = None
                    if spec.profile in {"VXL-1", "VXL-3"}:
                        artifact = Path(str(spec.calibration_artifact))
                        if not artifact.is_file() or _sha_file(artifact) != spec.calibration_sha256: raise ValueError("calibration artifact changed")
                        calibration = json.loads(artifact.read_text())
                        if not isinstance(calibration.get("development_population_sha256"), str): raise ValueError("calibration lacks frozen development population hash")
                        threshold = float(calibration["development_percentile_threshold"])
                    profile = spec.profile
                else: profile = None
                candidates, priority = _read_staged_anchors(staging, profile=profile, threshold=threshold, cap=config.candidate.candidate_cap, priority_path=(attempt / "priority.sqlite") if profile in {"VXL-2", "VXL-3"} else None)
                if not candidates: raise ValueError("no uniquely mapped native-decision evidence")
                stage = "candidate"; before, started = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, time.perf_counter(); candidate = EvidenceDrivenCandidateBuilder(store, config.candidate, priority=priority).build(candidates); candidate_seconds = time.perf_counter() - started
                if not candidate.edges: raise ValueError("candidate reconstruction produced no raw events")
                _write_jsonl(attempt / "candidate_raw_events.jsonl", (_edge_record(store, edge) for edge in candidate.edges), artifact_schema="candidate-raw-event-jsonl-v2"); _write_json(attempt / "candidate_nodes.json", {"artifact_schema": "candidate-node-set-v2", "node_ids": sorted(candidate.node_ids), "anchor_event_ids": sorted(candidate.anchor_event_ids), "anchor_node_ids": sorted(candidate.anchor_node_ids), "stop_reason": candidate.stop_reason, "projected_edge_count": config.projection.count(candidate.edges)})
                proxy, proxy_audit = _proxies(candidate.edges, candidate.anchor_event_ids, candidate.anchor_node_ids, config.proxy_event_cap, priority)
                stage = "selector:A_rasp"; started = time.perf_counter(); a = _a_rasp(store, candidate.edges, proxy, config.raw_event_cap, proxy_audit); a_seconds = time.perf_counter() - started; a["projected_edge_count"] = config.projection.count(tuple(edge for edge in candidate.edges if edge.event_id in a["selected_raw_event_ids"])); _write_json(attempt / "A_rasp_final.json", {"artifact_schema": "A_rasp-final-v2", **a})
                stage = "selector:C_branch_fair"; started = time.perf_counter(); b = _branch_fair(candidate.edges, proxy, config.raw_event_cap, proxy_audit, candidate.branch_provenance); b_seconds = time.perf_counter() - started; b["projected_edge_count"] = config.projection.count(tuple(edge for edge in candidate.edges if edge.event_id in b["selected_raw_event_ids"])); _write_json(attempt / "C_branch_fair_final.json", {"artifact_schema": "C-branch-fair-final-v2", **b})
                inference = None if inference_seconds is None else inference_seconds.get(spec.run_id)
                _write_json(attempt / "timing.json", {"artifact_schema": "online-timing-v2", **performance_fields(inference_seconds=inference, adapter_seconds=None, candidate_seconds=candidate_seconds, a_rasp_seconds=a_seconds, branch_fair_seconds=b_seconds, peak_rss_kb=max(before, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)), "adapter_seconds_status": "NOT_AVAILABLE", "detector_inference_seconds_status": "MEASURED_EXTERNAL" if inference is not None else "NOT_AVAILABLE", "candidate_seconds_status": "MEASURED", "selector_seconds_status": "MEASURED"})
                _write_json(attempt / "stage_identities.json", {"artifact_schema": "stage-identities-v2", "preprocessing": {"status": "NOT_AVAILABLE", "reason": "no graph/tensor manifest supplied"}, "inference": {"status": "NOT_AVAILABLE", "reason": "no inference identity artifact supplied"}, "scored": {"status": "NOT_AVAILABLE", "reason": "scored identity source was not supplied"}, "native_threshold": {"status": "AVAILABLE", "event_ids": sorted(event for item in candidates for event in item.event_ids), "node_ids": sorted(node for item in candidates for node in item.node_ids)}, "evidence": {"status": "AVAILABLE", "identity_index": "stage_identity_manifest.json", "stage": "evidence", "reason": "complete exact evidence identities are held in SQLite"}})
                _verify_native(native)
                if _sha_file(database) != config.database_sha256: raise ValueError("database hash changed during run")
                _write_json(attempt / "resolved_config.json", {"artifact_schema": "resolved-online-config-v2", "config": config.resolved, "config_sha256": config.config_sha256, "expected_config_sha256": config.expected_config_sha256, "code_commit": _commit(), "expected_code_commit": config.expected_code_commit, "database_path": config.database_path, "database_sha256": config.database_sha256, "database_sha256_start": config.database_sha256, "database_sha256_end": _sha_file(database), "native_aggregate_sha256": native["aggregate_sha256"]}); _status(attempt, "COMPLETED", "complete"); _artifact_manifest(attempt)
                published = root / "runs" / spec.run_id / attempt.name
                published.parent.mkdir(parents=True, exist_ok=True); os.replace(attempt, published)
                _atomic(root / "runs" / f"{spec.run_id}.CURRENT", _canonical({"run_id": spec.run_id, "attempt": str(published.resolve())}))
                result["runs"][spec.run_id] = {"status": "COMPLETED", "run_directory": str(published)}
            except Exception as exc:
                try: _status(attempt, "NOT_COMPLETED", stage, f"{type(exc).__name__}: {exc}"); _artifact_manifest(attempt)
                except Exception: pass
                result["status"] = "NOT_COMPLETED"; result["runs"][spec.run_id] = {"status": "NOT_COMPLETED", "stage": stage, "reason": str(exc), "attempt_directory": str(attempt)}
            finally:
                if hasattr(priority, "close"):
                    priority.close()
    if result["status"] == "COMPLETED":
        pointers = sorted((root / "runs").glob("*.CURRENT"))
        root_rows = []
        # The sealed root describes every immutable attempt byte, rather than
        # merely the mutable CURRENT pointers.  External native bytes remain
        # bound by their per-file hashes in native_manifest.json.
        for pointer in pointers:
            record = json.loads(pointer.read_text()); attempt_dir = Path(record["attempt"])
            files = [{"path": str(path.relative_to(root)), "sha256": _sha_file(path), "size_bytes": path.stat().st_size} for path in sorted(attempt_dir.rglob("*")) if path.is_file()]
            root_rows.append({"run_id": record["run_id"], "current_path": str(pointer.relative_to(root)), "current_sha256": _sha_file(pointer), "files": files})
        _write_json(root / "root_manifest.json", {"artifact_schema": "benchmark-root-manifest-v1", "runs": root_rows})
        seal = _sha_file(root / "root_manifest.json")
        _write_json(root / "root_seal.json", {"artifact_schema": "benchmark-root-seal-v1", "root_manifest_sha256": seal})
        result["root_manifest_sha256"] = seal
    _status(outer, "COMPLETED" if result["status"] == "COMPLETED" else "NOT_COMPLETED", "complete" if result["status"] == "COMPLETED" else "run", None if result["status"] == "COMPLETED" else "one or more runs failed")
    return result

__all__ = ["BenchmarkConfig", "DetectorSpec", "run_online_benchmark"]
