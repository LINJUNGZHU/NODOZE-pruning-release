"""Sealed, disk-backed execution for the four Velox CADETS E3 profiles.

Native shards are read once. Calibration uses indexed cumulative rank tables;
all four Velox policies refer to one immutable population. This module has no
offline evaluation dependency. It intentionally does not call the old runner.
"""
from __future__ import annotations

from contextlib import contextmanager
import csv
from dataclasses import asdict, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import sqlite3
import subprocess
import tempfile
import time
from typing import Mapping

from .benchmark_contract import EdgeProjection, performance_fields
from .detectors.alert_evidence import AlertEvidence
from .evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from .store import ProvenanceStore
# Pure, existing selector adapters; no old-runner admission/status is invoked.
from .detector_seed_benchmark import _a_rasp, _branch, _proxies

RUN_IDS = ("VXL-0", "VXL-1", "VXL-2", "VXL-3")
POPULATIONS = ("VELOX",)
FROZEN_SHA = "719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf"
REPO = Path(__file__).resolve().parents[1]
CODE_FILES = (
    "tc_pruning/__init__.py", "tc_pruning/benchmark_contract.py",
    "tc_pruning/detector_seed_production.py", "tc_pruning/detector_seed_benchmark.py",
    "tc_pruning/detectors/__init__.py", "tc_pruning/detectors/alert_evidence.py",
    "tc_pruning/evidence_candidate_builder.py", "tc_pruning/store.py", "tc_pruning/models.py",
    "tc_pruning/frequency.py", "tc_pruning/frequency_cache.py", "tc_pruning/rasp.py",
    "tc_pruning/investigation/__init__.py", "tc_pruning/investigation/branch_fair_selector.py",
    "tc_pruning/investigation/evidence_units.py", "scripts/run_detector_seed_production.py",
    "tc_pruning/detector_seed_production_evaluation.py", "scripts/evaluate_detector_seed_production.py",
    "tc_pruning/seed_utility_evaluation.py",
    "tc_pruning/velox_production_recipe.py", "scripts/prepare_velox_seed_production.py",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest_json(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reject_authorities(value):
    """Reject authority names in keys AND values, including collapsed spellings."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            reject_authorities(str(key))
            reject_authorities(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            reject_authorities(item)
    elif isinstance(value, (str, Path)):
        split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value))
        tokens = re.findall(r"[a-z0-9]+", split.lower())
        compact = "".join(tokens)
        forbidden = ("groundtruth", "knowncritical", "criticalevent", "criticaledge", "pdfcritical",
                     "attacktime", "attackwindow", "attackdate", "ytrue", "oracle", "funnel",
                     "label", "malicious", "positiveids", "evaluator")
        if "gt" in tokens or "truth" in tokens or any(term in compact for term in forbidden):
            raise ValueError("online authority is forbidden")


def file_pin(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": file_sha(path), "size_bytes": path.stat().st_size}


def verify_file(item):
    path = Path(item["path"])
    if not path.is_file() or file_sha(path) != item["sha256"]:
        raise ValueError("sealed file hash mismatch: " + str(path))
    if "size_bytes" in item and path.stat().st_size != item["size_bytes"]:
        raise ValueError("sealed file size mismatch: " + str(path))
    return path


def current_code_manifest():
    return {"files": {name: file_pin(REPO / name) for name in CODE_FILES}}


def write_json(path, value):
    """Atomic file write within an already-created private attempt."""
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _number(value):
    if isinstance(value, bool):
        raise ValueError("boolean score")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite score")
    return result


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"-?\d+", str(value)):
        raise ValueError("timestamp must be an exact integer")
    return int(value)


def _boolean(value):
    if type(value) is bool:
        return value
    if value in ("True", "true", "1", 1):
        return True
    if value in ("False", "false", "0", 0):
        return False
    raise ValueError("invalid native decision")


def _array(value):
    result = json.loads(value) if isinstance(value, str) else value
    if not isinstance(result, (list, tuple)) or any(not isinstance(x, str) or not x for x in result):
        raise ValueError("invalid identity array")
    return list(result)


def _bounded_csv_rows(stream):
    reader = csv.DictReader(stream)
    while True:
        previous_limit = csv.field_size_limit()
        csv.field_size_limit(4 * 1024 * 1024)
        try:
            row = next(reader)
        except StopIteration:
            return
        finally:
            csv.field_size_limit(previous_limit)
        yield row


def iter_shards(files):
    """CSV/JSONL only; bound parser fields and never hold a shard in memory."""
    for item in files:
        reject_authorities(item)
        path = verify_file(item)
        with path.open(encoding="utf-8", newline="") as stream:
            if path.suffix.lower() == ".csv":
                reader = _bounded_csv_rows(stream)
            elif path.suffix.lower() == ".jsonl":
                def lines():
                    while True:
                        line = stream.readline(4 * 1024 * 1024 + 1)
                        if not line:
                            break
                        if len(line) > 4 * 1024 * 1024:
                            raise ValueError("native record exceeds 4 MiB bound")
                        if line.strip():
                            yield json.loads(line)
                reader = lines()
            else:
                raise ValueError("only immutable CSV/JSONL native shards are admitted")
            for row in reader:
                if not isinstance(row, dict):
                    raise ValueError("native row must be an object")
                reject_authorities(row)
                if "scope" not in row and item.get("scope"):
                    row = dict(row, scope=item["scope"])
                yield row


class ReadOnlyStore(ProvenanceStore):
    """Use existing graph accessors without schema writes or unbounded node cache."""
    def __init__(self, path):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row
        self._node_record_cache = {}
        self.conn.execute("PRAGMA query_only=ON")

    def get_node(self, uuid):
        if len(self._node_record_cache) >= 20000:
            self._node_record_cache.clear()
        return super().get_node(uuid)


def open_store(path):
    return ReadOnlyStore(path)


def close_store(store):
    store.close()


def _resolve_event(store, native, *, stored=None):
    if stored is not None:
        found = store.conn.execute("SELECT event_id,original_event_id,src,dst,relation,timestamp_ns FROM edges WHERE event_id=?", (stored,)).fetchone()
        matches = [] if found is None else [found]
    else:
        # A bare native id can be either stored or original. Ambiguity is never
        # resolved by first-row selection or endpoint/timestamp guessing.
        matches = store.conn.execute("SELECT event_id,original_event_id,src,dst,relation,timestamp_ns FROM edges WHERE event_id=? OR original_event_id=? LIMIT 2", (native, native)).fetchall()
    if len(matches) != 1:
        return None, "ambiguous" if matches else "missing"
    return matches[0], "exact"


def _score_scope(row):
    score = _number(row.get("loss", row.get("raw_loss", row.get("alert_score", row.get("anomaly_score")))))
    stamp = row.get("time", row.get("timestamp_ns", row.get("event_time_start")))
    stamp = None if stamp is None else _integer(stamp)
    scope = str(row.get("scope") or row.get("window") or (stamp // 86400000000000 if stamp is not None else ""))
    if not scope:
        raise ValueError("native query/day scope is required")
    return score, stamp, scope


def _native_records(detector, row, spec, store, ordinal):
    score, stamp, scope = _score_scope(row)
    threshold = _number(row.get("threshold", spec["native_threshold"]))
    decision = row.get("native_decision", row.get("anomalous_native", row.get("native_prediction")))
    decision = score > threshold if decision is None else _boolean(decision)
    if detector == "VELOX":
        configured = _number(spec["native_threshold"])
        if threshold != configured:
            raise ValueError("Velox row threshold differs from frozen development maximum")
        if decision != (score > configured):
            raise ValueError("Velox native decision is inconsistent with max_val_loss threshold")
    metadata = {"native_threshold": threshold, "scope": scope, "native_row": ordinal}
    if detector in ("R-CAID", "NODLINK"):
        node = row.get("node_uuid")
        if not isinstance(node, str) or not node or node.isdigit():
            raise ValueError("exact node UUID identity is required")
        if not store.conn.execute("SELECT 1 FROM nodes WHERE uuid=?", (node,)).fetchone():
            raise ValueError("node identity absent from frozen database")
        item = AlertEvidence(f"{detector}:{ordinal}", detector, spec["version"], "NODE", score, 0, decision,
                             node_ids=(node,), timestamp_start=stamp, timestamp_end=stamp,
                             mapping_quality="EXACT", detector_metadata=metadata)
        yield item, {"state": "exact", "native_node_id": node, "node_id": node}, scope
        return
    if detector == "ORTHRUS":
        ids = _array(row.get("seed_event_ids"))
    else:
        ids = [row.get("event_uuid") if detector == "VELOX" else row.get("raw_event_id")]
    if not ids or any(not isinstance(x, str) or not x for x in ids):
        raise ValueError("native event identity is missing")
    for index, native in enumerate(ids):
        strict = detector == "VELOX"
        if strict:
            required = ("event_uuid", "stored_event_id", "original_event_id", "identity_origin", "identity_collision",
                        "src_node_uuid", "dst_node_uuid", "raw_relation", "model_operation", "time", "supporting_event_ids")
            if any(row.get(key) in (None, "") for key in required) or native.startswith("legacy-row-"):
                raise ValueError("incomplete exact native identity")
            original = row["original_event_id"]
            origin = ("DERIVED_NO_RAW_EVENT" if original.startswith("LINEAGE:") else
                      "RAW_TC_EVENT" if re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", original) else "OTHER_STORED_ID")
            support = _array(row["supporting_event_ids"])
            if row["stored_event_id"] != native or row["identity_origin"] != origin or _boolean(row["identity_collision"]) != (native != original):
                raise ValueError("native identity origin/collision mismatch")
            if not support or support[0] != native or len(set(support)) != len(support):
                raise ValueError("native supporting identity mismatch")
            operation = "EVENT_CLONE" if row["raw_relation"] == "EVENT_FORK" else row["raw_relation"]
            if row["model_operation"] != operation:
                raise ValueError("native raw/model relation mismatch")
        found, state = _resolve_event(store, native, stored=row.get("stored_event_id") if strict else None)
        audit = {"native_event_id": native, "state": state}
        if found is None:
            if strict:
                raise ValueError("native identity is " + state)
            yield None, audit, scope
            continue
        stored, original, src, dst, relation, timestamp = found
        audit.update(stored_event_id=stored, original_event_id=original)
        if strict:
            if (original, src, dst, relation, timestamp) != (row["original_event_id"], row["src_node_uuid"], row["dst_node_uuid"], row["raw_relation"], stamp):
                raise ValueError("native identity endpoint/relation/timestamp mismatch")
            for member in support:
                if not store.conn.execute("SELECT 1 FROM edges WHERE event_id=?", (member,)).fetchone():
                    raise ValueError("supporting event identity absent")
            metadata.update(identity_origin=origin, original_event_id=original, identity_collision=native != original)
        quality = "EXACT"
        if detector == "KAIROS":
            if (src, dst, relation, timestamp) != (row.get("src"), row.get("dst"), row.get("relation"), stamp):
                yield None, dict(audit, state="incoherent"), scope
                continue
            tier = str(row.get("mapping_tier", "PARTIAL")).upper()
            quality = "EXACT" if tier in ("EXACT", "IDENTITY") else "TOLERANT" if tier == "TOLERANT" else "PARTIAL"
            metadata.update(mapping_tier=tier, frozen_legacy=True)
        item = AlertEvidence(f"{detector}:{ordinal}:{index}", detector, spec["version"], "EDGE", score, 0, decision,
                             event_ids=(stored,), node_ids=(src, dst), src_uuid=src, dst_uuid=dst, relation=relation,
                             timestamp_start=timestamp, timestamp_end=timestamp, mapping_quality=quality,
                             supporting_event_ids=tuple(support) if strict else (), detector_metadata=metadata)
        yield item, dict(audit, mapping_quality=quality), scope


def _snapshot_inputs(spec, directory):
    snapshots = {}
    for kind in ("native", "development"):
        target = directory / kind
        target.mkdir()
        entries = []
        for number, item in enumerate(spec[kind]):
            source = verify_file(item)
            dest = target / f"{number:06d}{source.suffix.lower()}"
            shutil.copyfile(source, dest)
            if file_sha(dest) != item["sha256"]:
                raise ValueError("input changed during snapshot")
            entries.append(dict(item, path=str(dest), source_path=str(source.resolve())))
        snapshots[kind] = entries
    return snapshots


def stage_population(detector, spec, store, directory):
    """Materialize one population, with indexed rank and priority tables on disk."""
    reject_authorities(spec)
    if detector != "VELOX" or not spec.get("native") or not spec.get("development"):
        raise ValueError("one nonempty Velox native/development population is required")
    if spec.get("threshold_method") != "max_val_loss":
        raise ValueError("Velox native threshold method must be max_val_loss")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    snapshots = _snapshot_inputs(spec, directory)
    conn = sqlite3.connect(directory / "stage.sqlite")
    counts = {"total": 0, "native_rows": 0, "exact": 0, "missing": 0, "ambiguous": 0, "incoherent": 0,
              "supporting_event_rows": 0}
    try:
        conn.executescript("""
            PRAGMA journal_mode=DELETE; PRAGMA temp_store=FILE; PRAGMA cache_size=-8192;
            CREATE TABLE development(score REAL NOT NULL);
            CREATE TABLE native_scores(scope TEXT,score REAL);
            CREATE INDEX native_scope_score ON native_scores(scope,score);
            CREATE TABLE staged(id INTEGER PRIMARY KEY, body TEXT NOT NULL, scope TEXT NOT NULL,
                score REAL NOT NULL, native INTEGER NOT NULL, kind TEXT NOT NULL, object_id TEXT NOT NULL,
                anchor_key TEXT NOT NULL, calibrated REAL, local REAL);
            CREATE INDEX staged_scope_score ON staged(scope,score);
            CREATE INDEX staged_score ON staged(score);
            CREATE TABLE stage_identity(stage TEXT,kind TEXT,identity TEXT,PRIMARY KEY(stage,kind,identity));
            CREATE TABLE seen_supporting_event(identity TEXT PRIMARY KEY);
        """)
        conn.executemany("INSERT INTO development VALUES (?)", ((_number(row.get("loss", row.get("score", row.get("raw_loss")))),) for row in iter_shards(snapshots["development"])))
        if conn.execute("SELECT COUNT(*) FROM development").fetchone()[0] == 0:
            raise ValueError("empty development population")
        development_max = conn.execute("SELECT MAX(score) FROM development").fetchone()[0]
        if _number(spec["native_threshold"]) != development_max:
            raise ValueError("Velox native threshold must equal max development loss")
        conn.executescript("""
            CREATE INDEX development_score ON development(score);
            CREATE TABLE development_rank(score REAL PRIMARY KEY, percentile REAL NOT NULL);
            INSERT INTO development_rank SELECT score,
                1.0 * SUM(COUNT(*)) OVER(ORDER BY score ROWS UNBOUNDED PRECEDING) / SUM(COUNT(*)) OVER()
                FROM development GROUP BY score;
        """)
        with (directory / "mapping.jsonl").open("wb") as audit_stream:
            for number, row in enumerate(iter_shards(snapshots["native"]), 1):
                counts["native_rows"] += 1
                score, _, scope = _score_scope(row)
                conn.execute("INSERT INTO native_scores VALUES (?,?)", (scope, score))
                for item, audit, scope in _native_records(detector, row, spec, store, number):
                    counts["total"] += 1
                    counts[audit["state"]] += 1
                    audit_stream.write(canonical(dict(audit, native_row=number)) + b"\n")
                    if item is None:
                        continue
                    kind = "event" if item.event_ids else "node"
                    identity = item.event_ids[0] if item.event_ids else item.node_ids[0]
                    anchor_key = EvidenceDrivenCandidateBuilder._identity(item)
                    support = item.supporting_event_ids or item.event_ids
                    try:
                        conn.executemany("INSERT INTO seen_supporting_event VALUES (?)", ((member,) for member in support))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError("duplicate Velox scored/supporting event identity") from exc
                    conn.execute("INSERT INTO staged(body,scope,score,native,kind,object_id,anchor_key) VALUES (?,?,?,?,?,?,?)",
                                 (canonical(item.to_record()).decode(), scope, item.raw_score, int(item.native_decision), kind, identity, anchor_key))
                    stages = ("preprocessing", "inference", "scored", "evidence") + (("native_threshold",) if item.native_decision else ())
                    counts["supporting_event_rows"] += len(support)
                    for member in support:
                        for stage in stages:
                            conn.execute("INSERT OR IGNORE INTO stage_identity VALUES (?,?,?)", (stage, "event", member))
                    for node in item.node_ids:
                        for stage in stages:
                            conn.execute("INSERT OR IGNORE INTO stage_identity VALUES (?,?,?)", (stage, "node", node))
                    if number % 10000 == 0:
                        conn.commit()
            audit_stream.flush()
            os.fsync(audit_stream.fileno())
        if not counts["total"] or not counts["exact"]:
            raise ValueError("empty or entirely unmapped native population")
        conn.executescript("""
            CREATE TABLE local_rank(scope TEXT,score REAL,percentile REAL,PRIMARY KEY(scope,score));
            INSERT INTO local_rank SELECT scope,score,
                1.0 * SUM(COUNT(*)) OVER(PARTITION BY scope ORDER BY score ROWS UNBOUNDED PRECEDING)
                    / SUM(COUNT(*)) OVER(PARTITION BY scope)
                FROM native_scores GROUP BY scope,score;
            UPDATE staged SET calibrated=COALESCE((SELECT percentile FROM development_rank
                WHERE development_rank.score <= staged.score ORDER BY score DESC LIMIT 1),0),
                local=(SELECT percentile FROM local_rank WHERE local_rank.scope=staged.scope AND local_rank.score=staged.score);
            CREATE INDEX staged_anchor ON staged(native,calibrated DESC,anchor_key);
            CREATE TABLE priorities(kind TEXT,identity TEXT,raw REAL,calibrated REAL,PRIMARY KEY(kind,identity));
            INSERT INTO priorities SELECT kind,object_id,MAX(score),MAX(calibrated) FROM staged GROUP BY kind,object_id;
        """)
        digest, evidence_count = hashlib.sha256(), 0
        with (directory / "evidence.jsonl").open("wb") as output:
            for body, calibrated, local in conn.execute("SELECT body,calibrated,local FROM staged ORDER BY id"):
                item = replace(AlertEvidence.from_record(json.loads(body)), calibrated_score=calibrated,
                               development_percentile=calibrated, query_local_percentile=local)
                line = canonical(item.to_record()) + b"\n"
                output.write(line)
                digest.update(line)
                evidence_count += 1
            output.flush()
            os.fsync(output.fileno())
        conn.commit()
    finally:
        conn.close()
    for kind in ("native", "development"):
        for item in spec[kind]:
            verify_file(item)
    summary = {"detector_id": detector, "counts": counts, "evidence_count": evidence_count,
               "evidence_sha256": digest.hexdigest(), "mapping_sha256": file_sha(directory / "mapping.jsonl"),
               "stage_sha256": file_sha(directory / "stage.sqlite"), "source": spec,
               "calibration": "development ECDF <=; query/day ECDF <=; disk indexed cumulative ranks",
               "adapter_seconds": time.perf_counter() - started,
               "stage_availability": {"preprocessing": "NOT_AVAILABLE", "inference": "AVAILABLE_SCORED_OUTPUT_ONLY"}}
    write_json(directory / "population.json", summary)
    return summary


class PopulationPriority:
    def __init__(self, path, raw):
        self.conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
        self.column = "raw" if raw else "calibrated"

    def _score(self, kind, identity):
        row = self.conn.execute(f"SELECT {self.column} FROM priorities WHERE kind=? AND identity=?", (kind, identity)).fetchone()
        return None if row is None else row[0]

    def score_for_event(self, event_id):
        return self._score("event", event_id)

    def score_for_node(self, node_id):
        return self._score("node", node_id)

    def close(self):
        self.conn.close()


def close_priority(priority):
    priority.close()


@contextmanager
def population_inputs(directory, run_id, cap, percentile):
    directory = Path(directory)
    summary = json.loads((directory / "population.json").read_text())
    conn = sqlite3.connect((directory / "stage.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
    priority = None
    try:
        predicate = "calibrated>=?" if run_id in ("VXL-1", "VXL-3") else "native=1"
        params = (percentile,) if "?" in predicate else ()
        distinct = conn.execute("SELECT COUNT(DISTINCT anchor_key) FROM staged WHERE " + predicate, params).fetchone()[0]
        if distinct > cap:
            raise ValueError("required anchor identities exceed fixed cap")
        # Dedup equivalent causal anchors only. Retain different node time/role
        # branches; never load a population-sized evidence collection.
        anchors = []
        sql = "SELECT body,calibrated,local FROM (SELECT *,ROW_NUMBER() OVER(PARTITION BY anchor_key ORDER BY calibrated DESC,score DESC,id) AS choice FROM staged WHERE " + predicate + ") WHERE choice=1 ORDER BY calibrated DESC,anchor_key"
        for body, calibrated, local in conn.execute(sql, params):
            anchors.append(replace(AlertEvidence.from_record(json.loads(body)), calibrated_score=calibrated,
                                   development_percentile=calibrated, query_local_percentile=local))
        if run_id in ("VXL-2", "VXL-3"):
            priority = PopulationPriority(directory / "stage.sqlite", raw=run_id == "VXL-2")
        yield tuple(anchors), priority, summary["evidence_sha256"]
    finally:
        try:
            if priority is not None:
                try:
                    close_priority(priority)
                except BaseException:
                    priority.conn.close()
                    raise
        finally:
            conn.close()


def validate_config(config, *, allow_test=False):
    reject_authorities(config)
    if config.get("schema_version") != "cadets-velox-production-v1" or config.get("dataset") != "DARPA_TC_E3_CADETS":
        raise ValueError("CADETS E3 Velox production contract required")
    if tuple(config.get("runs", ())) != RUN_IDS or set(config.get("populations", {})) != set(POPULATIONS):
        raise ValueError("exactly VXL-0..3 and one Velox population are required")
    allowed = {"schema_version", "dataset", "database", "identity_manifest", "runtime_root", "code", "runs", "populations",
               "candidate", "projection", "raw_event_cap", "proxy_event_cap", "percentile_threshold"}
    if set(config) - allowed:
        raise ValueError("unknown production config fields")
    search = CandidateSearchConfig(**config["candidate"])
    if search.max_control_depth != 2 or not search.enable_common_cause:
        raise ValueError("common control depth 2 and common cause are required")
    if not allow_test and (config["database"]["sha256"] != FROZEN_SHA or search != CandidateSearchConfig(10000,1522706861813350340,1523655358953968696,8,2,True,20)):
        raise ValueError("frozen database/candidate contract mismatch")
    if config["projection"] != {"mode": "DEPIMPACT_COMPATIBLE", "merge_window_ns": 900000000000}:
        raise ValueError("frozen projection mismatch")
    if any(type(config[name]) is not int or config[name] <= 0 for name in ("raw_event_cap", "proxy_event_cap")):
        raise ValueError("positive integer selector caps required")
    if not allow_test and (config["raw_event_cap"] != 8000 or config["proxy_event_cap"] != 8000):
        raise ValueError("frozen selector caps mismatch")
    if not 0 < _number(config["percentile_threshold"]) <= 1:
        raise ValueError("invalid global development percentile")
    verify_file(config["database"])
    manifest = json.loads(verify_file(config["identity_manifest"]).read_text())
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if digest_json(unsigned) != manifest.get("manifest_sha256") or manifest.get("status") != "COMPLETED" or not manifest.get("reconciliation", {}).get("exact"):
        raise ValueError("completed exact identity manifest required")
    if manifest.get("source_sha256") != config["database"]["sha256"] or not manifest.get("model_views_sha256") or "model_eligible_identity_origin_counts" not in manifest:
        raise ValueError("identity source/model-view seal mismatch")
    if not allow_test and (manifest.get("test_only") or manifest.get("production_admissible") is not True):
        raise ValueError("identity manifest is not production-admissible")
    runtime = manifest.get("pidsmaker_runtime_seal", {})
    if not runtime.get("files") or digest_json({k: v for k, v in runtime.items() if k != "sha256"}) != runtime.get("sha256"):
        raise ValueError("identity runtime seal missing or corrupt")
    for name, sha in runtime["files"].items():
        reject_authorities(name)
        verify_file({"path": str(Path(config["runtime_root"]) / name), "sha256": sha})
    if not allow_test and subprocess.check_output(["git", "-C", config["runtime_root"], "rev-parse", "HEAD"], text=True).strip() != runtime.get("commit"):
        raise ValueError("identity runtime commit differs from seal")
    if config["code"] != current_code_manifest():
        raise ValueError("reviewed code byte manifest mismatch")
    for detector, spec in config["populations"].items():
        if set(spec) - {"native", "development", "native_threshold", "threshold_method", "version", "inference_seconds", "derivation"}:
            raise ValueError("detector-specific reconstruction settings forbidden")
        if not isinstance(spec.get("version"), str) or not spec["version"]:
            raise ValueError("detector version required")
        _number(spec["native_threshold"])
        if spec.get("threshold_method") != "max_val_loss":
            raise ValueError("Velox threshold method must be max_val_loss")
        if spec.get("inference_seconds") is not None and _number(spec["inference_seconds"]) < 0:
            raise ValueError("invalid inference duration")
        for kind in ("native", "development"):
            if not spec.get(kind):
                raise ValueError("missing " + kind + " shards")
            for item in spec[kind]:
                path = verify_file(item)
                if path.suffix.lower() not in (".csv", ".jsonl"):
                    raise ValueError("only CSV/JSONL populations are allowed")
        if {item["sha256"] for item in spec["native"]} & {item["sha256"] for item in spec["development"]}:
            raise ValueError("development/native population overlap")
        if not spec.get("derivation"):
            raise ValueError("native exporter derivation seal required")
        derivation = json.loads(verify_file(spec["derivation"]).read_text())
        reject_authorities(derivation)
        expected = {"status": "COMPLETED", "detector_id": detector, "source_sha256": config["database"]["sha256"],
                    "native": spec["native"], "development": spec["development"]}
        expected.update(identity_manifest_sha256=manifest["manifest_sha256"], runtime_sha256=runtime["sha256"])
        if any(derivation.get(key) != value for key, value in expected.items()):
            raise ValueError("native/development/runtime derivation mismatch")
        for key in ("training_status", "runtime_audit", "generator"):
            if not isinstance(derivation.get(key), Mapping):
                raise ValueError("Velox derivation is missing " + key)
            verify_file(derivation[key])
        training_status = json.loads(Path(derivation["training_status"]["path"]).read_text())
        if (training_status.get("status"), training_status.get("detector"), training_status.get("identity_manifest_sha256")) != (
                "COMPLETED", "velox", manifest["manifest_sha256"]):
            raise ValueError("Velox training status does not match the sealed identity")
        selection = derivation.get("epoch_selection", {})
        if selection.get("selection_rule") != "minimum_mean_validation_edge_loss" or _number(selection.get("inference_seconds")) != _number(spec.get("inference_seconds")):
            raise ValueError("Velox development-only epoch selection/runtime mismatch")
    return manifest


def make_attempt(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=".seed-attempt-", dir=output.parent))


def _fsync_tree(directory):
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    for path in sorted((p for p in directory.rglob("*") if p.is_dir()), reverse=True) + [directory]:
        _fsync_directory(path)


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def seal_attempt(directory, payload):
    files = {str(path.relative_to(directory)): {"sha256": file_sha(path), "size_bytes": path.stat().st_size}
             for path in sorted(directory.rglob("*")) if path.is_file() and path.name != "manifest.json"}
    manifest = dict(payload, files=files)
    write_json(directory / "manifest.json", manifest)
    _fsync_tree(directory)
    return file_sha(directory / "manifest.json")


def publish_attempt(attempt, output):
    if output.exists():
        raise ValueError("refusing to replace existing result directory")
    os.rename(attempt, output)


def freeze_artifacts(directory):
    for path in directory.rglob("*"):
        if path.is_file():
            path.chmod(0o444)


def _failure_receipt(attempt, reason, stage):
    """Independent emergency writer, also usable when normal sealing failed."""
    if attempt is None or not attempt.is_dir():
        attempt = Path(tempfile.mkdtemp(prefix="seed-failed-"))
    payload = {"status": "NOT_COMPLETED", "stage": stage, "reason": reason,
               "attempt_directory": str(attempt)}
    retained = {str(path.relative_to(attempt)): {"sha256": file_sha(path), "size_bytes": path.stat().st_size}
                for path in sorted(attempt.rglob("*")) if path.is_file() and path.name not in ("status.json", "failure-pin.json")}
    for name, body in (("status.json", payload), ("failure-pin.json", {"status": "NOT_COMPLETED", "status_sha256": hashlib.sha256(canonical(payload) + b"\n").hexdigest(), "retained_files": retained})):
        if (attempt / name).exists():
            (attempt / name).chmod(0o600)
        with (attempt / name).open("wb") as stream:
            stream.write(canonical(body) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    return payload


def run_production(config, output, external_pin, *, allow_test=False):
    """One outer terminal status owns admission, staging, selectors and sealing."""
    attempt, store, published = None, None, False
    stage = "admission"
    try:
        output, external_pin = Path(output).resolve(), Path(external_pin).resolve()
        reject_authorities([output, external_pin, config])
        if output == external_pin or output in external_pin.parents or external_pin.exists() or output.exists():
            raise ValueError("fresh output and independent external pin paths are required")
        attempt = make_attempt(output)
        write_json(attempt / "status.json", {"status": "RUNNING", "stage": stage})
        config_source = None
        if isinstance(config, (str, Path)):
            stage = "config_read"
            config_source = file_pin(config)
            config = json.loads(Path(config).read_text())
        stage = "admission"
        identity = validate_config(config, allow_test=allow_test)
        input_bytes = sum(Path(item["path"]).stat().st_size for spec in config["populations"].values() for kind in ("native", "development") for item in spec[kind])
        if shutil.disk_usage(attempt).free < input_bytes * 12 + 32 * 1024 * 1024:
            raise ValueError("insufficient disk for one shared population and indexed staging")
        write_json(attempt / "config.json", config)
        for name, item in config["code"]["files"].items():
            target = attempt / "code" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item["path"], target)
        write_json(attempt / "identity.json", identity)
        (attempt / "populations").mkdir()
        (attempt / "runs").mkdir()
        stage = "store_open"
        store = open_store(config["database"]["path"])
        populations, runs = {}, {}
        for detector in POPULATIONS:
            stage = "population:" + detector
            populations[detector] = stage_population(detector, config["populations"][detector], store, attempt / "populations" / detector)
        search = CandidateSearchConfig(**config["candidate"])
        projection = EdgeProjection(**config["projection"])
        for run_id in RUN_IDS:
            detector = "VELOX"
            directory = attempt / "runs" / run_id
            directory.mkdir()
            stage = "candidate:" + run_id
            with population_inputs(attempt / "populations" / detector, run_id, search.candidate_cap, config["percentile_threshold"]) as (anchors, priority, evidence_sha):
                if not anchors:
                    candidate_seconds = a_seconds = b_seconds = 0.0
                    candidate_edges = ()
                    write_json(directory / "candidate.json", {"event_ids": [], "node_ids": [], "edges": [],
                               "branch_provenance": {}, "raw_events": 0, "projected_edges": 0,
                               "stop_reason": "NO_ELIGIBLE_VELOX_ANCHORS"})
                    proxy_audit = {"anchor_event_ids": [], "anchor_node_ids": [],
                                   "node_incident_proxy_event_ids": [], "mandatory_proxy_event_ids": [],
                                   "proxy_cap": min(config["raw_event_cap"], config["proxy_event_cap"]),
                                   "selection": "not-run:no-eligible-velox-anchors"}
                    a = {"selected_raw_event_ids": [], "selected_anchor_event_ids": [],
                         "proxy_audit": proxy_audit,
                         "selector_input": {"status": "NOT_RUN", "reason": "NO_ELIGIBLE_VELOX_ANCHORS"}}
                    b = {"selected_raw_event_ids": [], "selected_unit_ids": [],
                         "proxy_audit": proxy_audit, "stable_contrast": "NOT_AVAILABLE", "ledger": [],
                         "selector_status": "NOT_RUN", "selector_reason": "NO_ELIGIBLE_VELOX_ANCHORS"}
                else:
                    started = time.perf_counter()
                    candidate = EvidenceDrivenCandidateBuilder(store, search, priority=priority).build(anchors)
                    candidate_seconds = time.perf_counter() - started
                    if not candidate.edges:
                        raise ValueError("nonempty Velox anchors produced an empty candidate")
                    candidate_edges = candidate.edges
                    write_json(directory / "candidate.json", {"event_ids": sorted(candidate.event_ids), "node_ids": sorted(candidate.node_ids),
                               "edges": [asdict(edge) for edge in candidate.edges], "branch_provenance": candidate.branch_provenance,
                               "raw_events": len(candidate.edges), "projected_edges": projection.count(candidate.edges), "stop_reason": candidate.stop_reason})
                    mandatory, proxy_audit = _proxies(candidate.edges, candidate.anchor_event_ids, candidate.anchor_node_ids, min(config["raw_event_cap"], config["proxy_event_cap"]), priority)
                    stage = "A_rasp:" + run_id
                    started = time.perf_counter()
                    a = _a_rasp(store, candidate.edges, mandatory, config["raw_event_cap"], proxy_audit)
                    a_seconds = time.perf_counter() - started
                    stage = "C_branch_fair:" + run_id
                    started = time.perf_counter()
                    b = _branch(candidate.edges, mandatory, config["raw_event_cap"], proxy_audit, candidate.branch_provenance)
                    b_seconds = time.perf_counter() - started
                for name, result in (("A_rasp", a), ("C_branch_fair", b)):
                    selected = set(result["selected_raw_event_ids"])
                    result.update(run_id=run_id, detector_id=detector, raw_events=len(selected),
                                  projected_edges=projection.count(edge for edge in candidate_edges if edge.event_id in selected))
                    write_json(directory / (name + ".json"), result)
                timing = performance_fields(inference_seconds=config["populations"][detector].get("inference_seconds"),
                    adapter_seconds=populations[detector]["adapter_seconds"], candidate_seconds=candidate_seconds,
                    a_rasp_seconds=a_seconds, branch_fair_seconds=b_seconds,
                    peak_rss_kb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                write_json(directory / "timing.json", dict(timing, adapter_shared_by=4 if detector == "VELOX" else 1))
            runs[run_id] = {"run_id": run_id, "detector_id": detector, "directory": "runs/" + run_id,
                            "population": "populations/" + detector, "evidence_sha256": evidence_sha, "status": "COMPLETED"}
            write_json(directory / "run.json", runs[run_id])
        stage = "store_close"
        try:
            close_store(store)
        except BaseException:
            store.conn.close()
            raise
        store = None
        stage = "revalidation"
        validate_config(config, allow_test=allow_test)
        if config_source:
            verify_file(config_source)
        write_json(attempt / "status.json", {"status": "COMPLETED", "runs": runs})
        stage = "seal"
        digest = seal_attempt(attempt, {"status": "COMPLETED", "runs": runs,
            "config_sha256": digest_json(config), "database_start": config["database"], "database_end": file_pin(config["database"]["path"]),
            "config_source": config_source, "test_only": allow_test, "population_derivation": {name: populations[name]["evidence_sha256"] for name in POPULATIONS}})
        external_pin.parent.mkdir(parents=True, exist_ok=True)
        pin_payload = {"status": "COMPLETED", "root": str(output), "manifest_sha256": digest, "runs": list(RUN_IDS)}
        # Prepare the pin before publication; failure cannot expose completed results.
        pin_temporary = attempt / ".external-pin-prepared"
        write_json(pin_temporary, pin_payload)
        stage = "publish"
        publish_attempt(attempt, output)
        published = True
        attempt = output
        os.replace(output / ".external-pin-prepared", external_pin)
        stage = "freeze"
        freeze_artifacts(output)
        _fsync_directory(output.parent)
        _fsync_directory(external_pin.parent)
        return {"status": "COMPLETED", "run_directory": str(output), "pin": str(external_pin), "runs": runs}
    except BaseException as exc:
        if store is not None:
            try:
                store.conn.close()
            except BaseException:
                pass
        if published and attempt == output:
            # Only this attempt's just-published tree is moved back to a failure
            # path; no prior result can be overwritten by this code.
            failed = output.with_name(output.name + ".failed-" + str(time.time_ns()))
            os.rename(output, failed)
            attempt = failed
            if external_pin.is_file():
                write_json(external_pin, {"status": "NOT_COMPLETED", "root": str(failed), "reason": str(exc)})
        return _failure_receipt(attempt, str(exc), stage)
