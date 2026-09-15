"""Typed detector-native alert evidence without label-bearing dependencies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from bisect import bisect_right
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
import os
from pathlib import Path
import sqlite3
import tempfile
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


ALERT_EVIDENCE_SCHEMA_VERSION = "2.0"
ORTHRUS_ALERTS_PATH = Path("output/query-adaptive-feasibility-20260914/orthrus/alerts.json")
_ONLINE_FORBIDDEN = ("ground" + "truth", "ground" + "_truth", "pdf" + "_critical", "attack" + "_window", "attack" + "_timestamp", "ora" + "cle", "evalu" + "ator", "fun" + "nel", "y" + "_true", "is" + "_malicious", "mali" + "cious", "la" + "bel")


class EvidenceGranularity(str, Enum):
    EVENT = "EVENT"
    EDGE = "EDGE"
    NODE = "NODE"
    SUBGRAPH = "SUBGRAPH"
    PATH = "PATH"
    STRUCTURAL_GRAPH = "STRUCTURAL_GRAPH"


class RoleHint(str, Enum):
    ROOT = "ROOT"
    ENTRY = "ENTRY"
    OBSERVATION = "OBSERVATION"
    INTERIOR = "INTERIOR"
    EXIT = "EXIT"
    TERMINAL = "TERMINAL"
    UNKNOWN = "UNKNOWN"


class MappingQuality(str, Enum):
    EXACT = "EXACT"
    TOLERANT = "TOLERANT"
    PARTIAL = "PARTIAL"
    UNMAPPED = "UNMAPPED"
    NATIVE = "NATIVE"


def _enum(value: Any, enum_type: type[Enum], field_name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an enum string")
    try:
        return enum_type(value.strip().upper())
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}") from exc


def _identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _score(value: Any, field_name: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{field_name} must be a finite JSON number")
    return float(value)


def _percentile(value: Any, field_name: str, *, optional: bool = True) -> float | None:
    parsed = _score(value, field_name, optional=optional)
    if parsed is not None and not 0.0 <= parsed <= 1.0:
        raise ValueError(f"{field_name} must be in [0, 1]")
    return parsed


def _identifiers(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{field_name} must be a JSON array")
    return tuple(sorted({_identifier(item, field_name) for item in value}))


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        if any(any(token in key.lower().replace("-", "_") for token in _ONLINE_FORBIDDEN) for key in value):
            raise ValueError("label-bearing detector metadata is forbidden online")
        return MappingProxyType({key: _freeze_json(value[key]) for key in sorted(value)})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, str) and any(token in value.lower().replace("-", "_") for token in _ONLINE_FORBIDDEN):
        raise ValueError("label-bearing detector metadata is forbidden online")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("detector metadata must be strict JSON")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    evidence_id: str
    detector_id: str
    detector_version: str
    granularity: EvidenceGranularity | str
    raw_score: float | None
    calibrated_score: float
    native_decision: bool
    event_ids: tuple[str, ...] = ()
    node_ids: tuple[str, ...] = ()
    supporting_event_ids: tuple[str, ...] = ()
    structural_context: Mapping[str, Any] = field(default_factory=dict)
    timestamp_start: int | None = None
    timestamp_end: int | None = None
    src_uuid: str | None = None
    dst_uuid: str | None = None
    relation: str | None = None
    role_hint: RoleHint | str = RoleHint.UNKNOWN
    mapping_quality: MappingQuality | str = MappingQuality.NATIVE
    detector_metadata: Mapping[str, Any] = field(default_factory=dict)
    development_percentile: float | None = None
    query_local_percentile: float | None = None
    schema_version: str = ALERT_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ALERT_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        object.__setattr__(self, "evidence_id", _identifier(self.evidence_id, "evidence_id"))
        object.__setattr__(self, "detector_id", _identifier(self.detector_id, "detector_id"))
        object.__setattr__(self, "detector_version", _identifier(self.detector_version, "detector_version"))
        object.__setattr__(self, "granularity", _enum(self.granularity, EvidenceGranularity, "granularity"))
        object.__setattr__(self, "role_hint", _enum(self.role_hint, RoleHint, "role_hint"))
        object.__setattr__(self, "mapping_quality", _enum(self.mapping_quality, MappingQuality, "mapping_quality"))
        object.__setattr__(self, "raw_score", _score(self.raw_score, "raw_score", optional=True))
        object.__setattr__(self, "calibrated_score", _percentile(self.calibrated_score, "calibrated_score", optional=False))
        object.__setattr__(self, "development_percentile", _percentile(self.development_percentile, "development_percentile"))
        object.__setattr__(self, "query_local_percentile", _percentile(self.query_local_percentile, "query_local_percentile"))
        if not isinstance(self.native_decision, bool):
            raise ValueError("native_decision must be a JSON boolean")
        for field_name in ("timestamp_start", "timestamp_end"):
            value = getattr(self, field_name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError(f"{field_name} must be an integer")
        if self.timestamp_start is not None and self.timestamp_end is not None and self.timestamp_start > self.timestamp_end:
            raise ValueError("timestamp_start cannot exceed timestamp_end")
        object.__setattr__(self, "event_ids", _identifiers(self.event_ids, "event_ids"))
        object.__setattr__(self, "node_ids", _identifiers(self.node_ids, "node_ids"))
        object.__setattr__(self, "supporting_event_ids", _identifiers(self.supporting_event_ids, "supporting_event_ids"))
        for field_name in ("src_uuid", "dst_uuid", "relation"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _identifier(value, field_name))
        context = _freeze_json(self.structural_context)
        if not isinstance(context, Mapping):
            raise ValueError("structural_context must be a JSON object")
        object.__setattr__(self, "structural_context", context)
        metadata = _freeze_json(self.detector_metadata)
        if not isinstance(metadata, Mapping):
            raise ValueError("detector_metadata must be a JSON object")
        object.__setattr__(self, "detector_metadata", metadata)
        if self.granularity is EvidenceGranularity.EVENT and not self.event_ids:
            raise ValueError("EVENT evidence requires event_ids")
        if self.granularity is EvidenceGranularity.EDGE and (not self.event_ids or self.src_uuid is None or self.dst_uuid is None):
            raise ValueError("EDGE evidence requires event_ids, src_uuid, and dst_uuid")
        if self.granularity is EvidenceGranularity.NODE and not self.node_ids:
            raise ValueError("NODE evidence requires node_ids")
        if self.granularity in {EvidenceGranularity.SUBGRAPH, EvidenceGranularity.PATH, EvidenceGranularity.STRUCTURAL_GRAPH}:
            if not self.structural_context:
                raise ValueError(f"{self.granularity.value} evidence requires structural_context")
            if not (self.event_ids or self.node_ids):
                raise ValueError(f"{self.granularity.value} evidence requires native members")

    @property
    def detector_name(self) -> str:
        return self.detector_id

    @property
    def metadata(self) -> Mapping[str, Any]:
        return self.detector_metadata

    @property
    def event_uuid(self) -> str | None:
        return self.event_ids[0] if len(self.event_ids) == 1 else None

    @property
    def node_uuid(self) -> str | None:
        return self.node_ids[0] if len(self.node_ids) == 1 else None

    @property
    def src_node_uuid(self) -> str | None:
        return self.src_uuid

    @property
    def dst_node_uuid(self) -> str | None:
        return self.dst_uuid

    @property
    def time_ns(self) -> int | None:
        return self.timestamp_end if self.timestamp_start == self.timestamp_end else None

    @property
    def object_key(self) -> tuple[str, ...]:
        if self.granularity in {EvidenceGranularity.EVENT, EvidenceGranularity.EDGE}:
            return ("EVENT", *self.event_ids)
        if self.granularity is EvidenceGranularity.NODE:
            return ("NODE", *self.node_ids)
        return (
            self.granularity.value, "EVENTS", *self.event_ids, "NODES", *self.node_ids,
            "CONTEXT", json.dumps(_thaw_json(self.structural_context), sort_keys=True, separators=(",", ":")),
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "evidence_id": self.evidence_id,
            "detector_id": self.detector_id, "detector_version": self.detector_version,
            "granularity": self.granularity.value, "raw_score": self.raw_score,
            "calibrated_score": self.calibrated_score, "native_decision": self.native_decision,
            "event_ids": list(self.event_ids), "node_ids": list(self.node_ids),
            "supporting_event_ids": list(self.supporting_event_ids),
            "structural_context": _thaw_json(self.structural_context),
            "timestamp_start": self.timestamp_start, "timestamp_end": self.timestamp_end,
            "src_uuid": self.src_uuid, "dst_uuid": self.dst_uuid, "relation": self.relation,
            "role_hint": self.role_hint.value, "mapping_quality": self.mapping_quality.value,
            "detector_metadata": _thaw_json(self.detector_metadata),
            "development_percentile": self.development_percentile,
            "query_local_percentile": self.query_local_percentile,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "AlertEvidence":
        if not isinstance(record, Mapping) or not all(isinstance(key, str) for key in record):
            raise ValueError("AlertEvidence record must be a JSON object")
        keys = set(record)
        if keys - _CANONICAL_FIELDS:
            raise ValueError("unknown AlertEvidence fields: " + ", ".join(sorted(keys - _CANONICAL_FIELDS)))
        if _CANONICAL_FIELDS - keys:
            raise ValueError("missing AlertEvidence fields: " + ", ".join(sorted(_CANONICAL_FIELDS - keys)))
        return cls(**dict(record))


_CANONICAL_FIELDS = frozenset(AlertEvidence.__dataclass_fields__)


def dump_evidence_jsonl(path: str | Path, evidence: Iterable[AlertEvidence]) -> None:
    rows = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    identifiers = [item.evidence_id for item in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate evidence_id")
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for item in rows:
            handle.write(json.dumps(item.to_record(), sort_keys=True, separators=(",", ":"), allow_nan=False))
            handle.write("\n")


def load_evidence_jsonl(path: str | Path) -> tuple[AlertEvidence, ...]:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")
    rows: list[AlertEvidence] = []
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                try:
                    rows.append(AlertEvidence.from_record(json.loads(line, parse_constant=reject_constant)))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid AlertEvidence JSONL line {number}") from exc
    dump_check = [item.evidence_id for item in rows]
    if len(dump_check) != len(set(dump_check)):
        raise ValueError("duplicate evidence_id")
    return tuple(sorted(rows, key=lambda item: item.evidence_id))


def iter_evidence_jsonl(path: str | Path) -> Iterable[AlertEvidence]:
    """Single-pass JSONL reader preserving source order for SQLite staging."""
    def reject_constant(_: str) -> None: raise ValueError("non-finite JSON number")
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip(): continue
            try: yield AlertEvidence.from_record(json.loads(line, parse_constant=reject_constant))
            except (TypeError, ValueError, json.JSONDecodeError) as exc: raise ValueError(f"invalid AlertEvidence JSONL line {number}") from exc


@dataclass(frozen=True, slots=True)
class DevelopmentCalibrator:
    development_scores: tuple[float, ...]

    @classmethod
    def fit(cls, scores: Iterable[float]) -> "DevelopmentCalibrator":
        values = tuple(sorted(_loss(score) for score in scores))
        if not values:
            raise ValueError("development calibration needs at least one score")
        return cls(values)

    def percentile(self, score: float) -> float:
        return bisect_right(self.development_scores, _loss(score)) / len(self.development_scores)


def _loss(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("native loss must be finite") from exc
    if not math.isfinite(parsed):
        raise ValueError("native loss must be finite")
    return parsed


def _read_rows(source: str | Path | Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", newline="") as handle:
                return [dict(row) for row in csv.DictReader(handle)]
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list) or not all(isinstance(row, Mapping) for row in payload):
            raise ValueError("native input must be an array of objects")
        return [dict(row) for row in payload]
    return [dict(row) for row in source]


def _development(rows: str | Path | Iterable[Mapping[str, Any]] | Iterable[float] | None) -> DevelopmentCalibrator:
    if rows is None:
        raise ValueError("frozen development calibration input is required")
    values = list(rows) if not isinstance(rows, (str, Path)) else _read_rows(rows)
    scores = [_loss(row["loss"]) if isinstance(row, Mapping) else _loss(row) for row in values]
    return DevelopmentCalibrator.fit(scores)


def _local_percentiles(rows: Sequence[Any], score: callable, scope: callable) -> dict[int, float | None]:
    groups: dict[str, list[tuple[int, float]]] = {}
    result: dict[int, float | None] = {}
    for index, row in enumerate(rows):
        key = scope(row)
        if key is None:
            result[index] = None
        else:
            groups.setdefault(key, []).append((index, score(row)))
    for members in groups.values():
        calibrator = DevelopmentCalibrator.fit(value for _, value in members)
        for index, value in members:
            result[index] = calibrator.percentile(value)
    return result


def _evidence_id(detector: str, *parts: str) -> str:
    return detector.lower() + ":" + hashlib.sha256("\x1f".join((detector, *parts)).encode()).hexdigest()[:20]


def _ordered_unique(rows: Iterable[AlertEvidence]) -> tuple[AlertEvidence, ...]:
    ordered = tuple(sorted(rows, key=lambda item: item.evidence_id))
    if len({item.evidence_id for item in ordered}) != len(ordered):
        raise ValueError("duplicate evidence_id from native detector output")
    return ordered


_EDGE_RELATIONS = {"1": "EVENT_CONNECT", "2": "EVENT_EXECUTE", "3": "EVENT_OPEN", "4": "EVENT_READ", "5": "EVENT_RECVFROM", "6": "EVENT_RECVMSG", "7": "EVENT_SENDMSG", "8": "EVENT_SENDTO", "9": "EVENT_WRITE", "10": "EVENT_CLONE"}


def _native_support(row: Mapping[str, Any]) -> tuple[str, ...]:
    value = row.get('supporting_event_ids')
    if value in (None, ''):
        return ()
    if isinstance(value, str):
        value = json.loads(value)
    return _identifiers(value, 'supporting_event_ids')


def _native_identity_metadata(row: Mapping[str, Any]) -> dict[str, Any]:
    result = {key: row[key] for key in ('stored_event_id', 'original_event_id', 'identity_origin')
              if row.get(key) not in (None, '')}
    collision = row.get('identity_collision')
    if collision not in (None, ''):
        if isinstance(collision, str) and collision.lower() in ('true', 'false'):
            collision = collision.lower() == 'true'
        if not isinstance(collision, bool):
            raise ValueError('identity_collision must be a boolean')
        result['identity_collision'] = collision
    if 'supporting_event_ids' in row:
        result['supporting_event_ids'] = _native_support(row)
    return result


def _native_mapping_quality(row: Mapping[str, Any], metadata: Mapping[str, Any]) -> MappingQuality:
    markers = ('stored_event_id', 'original_event_id', 'identity_origin', 'identity_collision', 'raw_relation')
    if not any(key in row for key in markers):
        return MappingQuality.NATIVE
    for key in markers + ('event_uuid', 'src_node_uuid', 'dst_node_uuid', 'time', 'supporting_event_ids'):
        if row.get(key) in (None, ''):
            raise ValueError('Incomplete exact native identity: ' + key)
    if row['stored_event_id'] != row['event_uuid']:
        raise ValueError('Stored and exported event identities disagree')
    event, original = row['event_uuid'], row['original_event_id']
    if metadata['identity_collision'] != (event != original):
        raise ValueError('Inconsistent native identity collision')
    origin = ('DERIVED_NO_RAW_EVENT' if original.startswith('LINEAGE:') else
              'RAW_TC_EVENT' if re.fullmatch(r'[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', original)
              else 'OTHER_STORED_ID')
    if row['identity_origin'] != origin:
        raise ValueError('Inconsistent native identity origin')
    support = row['supporting_event_ids']
    if isinstance(support, str):
        support = json.loads(support)
    if not isinstance(support, (tuple, list)) or not support or support[0] != event or len(set(support)) != len(support):
        raise ValueError('Invalid representative/supporting identities')
    expected_operation = 'EVENT_CLONE' if row['raw_relation'] == 'EVENT_FORK' else row['raw_relation']
    if (row.get('model_operation') or _EDGE_RELATIONS.get(str(row.get('edge_type')))) != expected_operation:
        raise ValueError('Native model operation disagrees with raw relation')
    if isinstance(row['time'], bool) or not isinstance(row['time'], (int, str)):
        raise ValueError('Native timestamp must be an exact integer')
    int(row['time'])
    return MappingQuality.EXACT


class AlertEvidenceProvider(ABC):
    @abstractmethod
    def provide(self, *args: Any, **kwargs: Any) -> tuple[AlertEvidence, ...]:
        """Translate native detector output without external labels."""

    def iter_provide(self, *args: Any, **kwargs: Any) -> Iterable[AlertEvidence]:
        """Streaming export hook. Legacy providers retain tuple compatibility."""
        yield from self.provide(*args, **kwargs)


class VeloxEvidenceAdapter(AlertEvidenceProvider):
    def __init__(self, *, version: str) -> None:
        self.version = version

    def _convert_row(self, row: Mapping[str, Any], threshold: float, rank: float, local: float | None) -> AlertEvidence:
        event, src, dst = (_identifier(row.get(key), key) for key in ("event_uuid", "src_node_uuid", "dst_node_uuid"))
        value, edge_type = _loss(row.get("loss")), row.get("edge_type")
        metadata = _native_identity_metadata(row)
        quality = _native_mapping_quality(row, metadata)
        timestamp = int(row["time"]) if row.get("time") not in (None, "") else None
        return AlertEvidence(
            _evidence_id("Velox", event), "Velox", self.version, EvidenceGranularity.EDGE, value, rank, value > threshold,
            event_ids=(event,), node_ids=(src, dst), src_uuid=src, dst_uuid=dst,
            relation=row.get("raw_relation") or row.get("relation") or _EDGE_RELATIONS.get(str(edge_type)),
            role_hint=RoleHint.OBSERVATION, supporting_event_ids=_native_support(row), mapping_quality=quality,
            detector_metadata={"native_threshold": threshold, "native_edge_type": edge_type, **metadata},
            timestamp_start=timestamp, timestamp_end=timestamp, development_percentile=rank, query_local_percentile=local)

    def adapt(self, rows: str | Path | Iterable[Mapping[str, Any]], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> tuple[AlertEvidence, ...]:
        native, calibration = _read_rows(rows), _development(development_rows)
        threshold = max(calibration.development_scores)
        local = _local_percentiles(native, lambda row: _loss(row["loss"]), lambda row: row.get("query_id") or row.get("day"))
        result = []
        for index, row in enumerate(native):
            value = _loss(row.get("loss"))
            result.append(self._convert_row(row, threshold, calibration.percentile(value), local[index]))
        return _ordered_unique(result)

    provide = adapt

    def iter_provide(self, rows: Iterable[Mapping[str, Any]], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> Iterable[AlertEvidence]:
        # Reuse the disk-backed streaming calibration implementation with an
        # EDGE-specific projection; this deliberately omits query-local ranks
        # rather than retaining an unbounded query grouping in RAM.
        fd, name = tempfile.mkstemp(prefix="velox-development-", suffix=".sqlite"); os.close(fd); conn = sqlite3.connect(name)
        try:
            conn.execute("CREATE TABLE scores(value REAL NOT NULL)")
            conn.execute("CREATE TABLE seen(event_id TEXT PRIMARY KEY,evidence_id TEXT UNIQUE NOT NULL)")
            def values() -> Iterable[Any]:
                if isinstance(development_rows, (str, Path)):
                    path = Path(development_rows)
                    if path.suffix.lower() == ".csv":
                        with path.open(encoding="utf-8", newline="") as stream: yield from csv.DictReader(stream)
                    elif path.suffix.lower() == ".jsonl":
                        with path.open(encoding="utf-8") as stream:
                            for line in stream:
                                if line.strip(): yield json.loads(line)
                    else: raise ValueError("production development input must be CSV or JSONL")
                else: yield from development_rows
            conn.executemany("INSERT INTO scores VALUES (?)", ((_loss(row["loss"]) if isinstance(row, Mapping) else _loss(row),) for row in values())); conn.commit(); total, threshold = conn.execute("SELECT COUNT(*),MAX(value) FROM scores").fetchone()
            if not total: raise ValueError("development calibration needs at least one score")
            for row in rows:
                value = _loss(row.get("loss"))
                rank = conn.execute("SELECT COUNT(*) FROM scores WHERE value<=?", (value,)).fetchone()[0] / total
                evidence = self._convert_row(row, threshold, rank, None)
                try:
                    conn.execute("INSERT INTO seen VALUES (?,?)", (evidence.event_ids[0], evidence.evidence_id))
                except sqlite3.IntegrityError as exc:
                    raise ValueError('Duplicate native event/evidence identity') from exc
                yield evidence
        finally:
            conn.close()
            try: os.unlink(name)
            except FileNotFoundError: pass


class _PIDSMakerNodeAdapter(AlertEvidenceProvider):
    detector_id: str

    def __init__(self, *, version: str) -> None:
        self.version = version

    def adapt(self, rows: str | Path | Iterable[Mapping[str, Any]], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> tuple[AlertEvidence, ...]:
        native, calibration = _read_rows(rows), _development(development_rows)
        threshold = max(calibration.development_scores)
        local = _local_percentiles(native, lambda row: _loss(row["loss"]), lambda row: row.get("query_id") or row.get("day"))
        result = []
        for index, row in enumerate(native):
            node, value = _identifier(row.get("node_uuid"), "node_uuid"), _loss(row.get("loss"))
            start = int(row['timestamp_start']) if row.get('timestamp_start') not in (None, '') else None
            end = int(row['timestamp_end']) if row.get('timestamp_end') not in (None, '') else None
            context = () if start is None and end is None else (str(start), str(end))
            result.append(AlertEvidence(
                _evidence_id(self.detector_id, node, *context), self.detector_id, self.version, EvidenceGranularity.NODE, value, calibration.percentile(value), value > threshold,
                node_ids=(node,), role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT,
                timestamp_start=start, timestamp_end=end, supporting_event_ids=_native_support(row),
                detector_metadata={"native_threshold": threshold, "native_node_id": row.get("node")},
                development_percentile=calibration.percentile(value), query_local_percentile=local[index],
            ))
        return _ordered_unique(result)

    provide = adapt

    def iter_provide(self, rows: Iterable[Any], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> Iterable[AlertEvidence]:
        """Production streaming path: calibration ranks live in disk SQLite."""
        fd, name = tempfile.mkstemp(prefix="pidsmaker-development-", suffix=".sqlite"); os.close(fd); conn = sqlite3.connect(name)
        try:
            conn.execute("CREATE TABLE scores(value REAL NOT NULL)")
            def development_iter() -> Iterable[Any]:
                if isinstance(development_rows, (str, Path)):
                    path = Path(development_rows)
                    if path.suffix.lower() == ".csv":
                        with path.open(encoding="utf-8", newline="") as stream: yield from csv.DictReader(stream)
                    elif path.suffix.lower() == ".jsonl":
                        with path.open(encoding="utf-8") as stream:
                            for line in stream:
                                if line.strip(): yield json.loads(line)
                    else: raise ValueError("production development input must be CSV or JSONL")
                else: yield from development_rows
            conn.executemany("INSERT INTO scores VALUES (?)", ((_loss(row["loss"]) if isinstance(row, Mapping) else _loss(row),) for row in development_iter())); conn.commit()
            total, threshold = conn.execute("SELECT COUNT(*),MAX(value) FROM scores").fetchone()
            if not total: raise ValueError("development calibration needs at least one score")
            for row in rows:
                node, value = _identifier(row.get("node_uuid"), "node_uuid"), _loss(row.get("loss")); rank = conn.execute("SELECT COUNT(*) FROM scores WHERE value<=?", (value,)).fetchone()[0] / total
                start = int(row['timestamp_start']) if row.get('timestamp_start') not in (None, '') else None; end = int(row['timestamp_end']) if row.get('timestamp_end') not in (None, '') else None; context = () if start is None and end is None else (str(start), str(end))
                yield AlertEvidence(_evidence_id(self.detector_id, node, *context), self.detector_id, self.version, EvidenceGranularity.NODE, value, rank, value > threshold, node_ids=(node,), role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT, timestamp_start=start, timestamp_end=end, supporting_event_ids=_native_support(row), detector_metadata={"native_threshold": threshold, "native_node_id": row.get("node")}, development_percentile=rank, query_local_percentile=None)
        finally:
            conn.close()
            try: os.unlink(name)
            except FileNotFoundError: pass


class RCAIDEvidenceAdapter(_PIDSMakerNodeAdapter):
    detector_id = "R-CAID"


class NODLINKEvidenceAdapter(_PIDSMakerNodeAdapter):
    detector_id = "NODLINK"


def _day(timestamp: Any) -> str | None:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp) / 1_000_000_000, timezone.utc).date().isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


class OrthrusEvidenceProvider(AlertEvidenceProvider):
    def provide(self, source: str | Path = ORTHRUS_ALERTS_PATH, development_rows: str | Path | Iterable[Mapping[str, Any]] | None = None) -> tuple[AlertEvidence, ...]:
        native, calibration = _read_rows(source), _development(development_rows)
        local = _local_percentiles(native, lambda row: _loss(row["alert_score"]), lambda row: _day(row.get("event_time_end") or row.get("event_time_start")))
        result = []
        for index, row in enumerate(native):
            alert_id = _identifier(row.get("alert_id"), "alert_id")
            version = _identifier(row.get("detector_version"), "detector_version")
            value, threshold = _loss(row.get("alert_score")), _loss(row.get("threshold"))
            events = _identifiers(row.get("seed_event_ids"), "seed_event_ids")
            if not events:
                raise ValueError("ORTHRUS alert requires seed_event_ids")
            start = row.get("event_time_start")
            end = row.get("event_time_end")
            for event in events:
                result.append(AlertEvidence(
                    _evidence_id("ORTHRUS", alert_id, event), "ORTHRUS", version, EvidenceGranularity.EVENT, value, calibration.percentile(value), value > threshold,
                    event_ids=(event,), timestamp_start=int(start) if start is not None else None, timestamp_end=int(end) if end is not None else None,
                    role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT if row.get("mapping_status") == "MATCHED" else MappingQuality.PARTIAL,
                    detector_metadata={"native_alert_id": alert_id, "native_threshold": threshold, "native_supporting_observation_ids": _identifiers(row.get("supporting_event_ids"), "supporting_event_ids")},
                    development_percentile=calibration.percentile(value), query_local_percentile=local[index],
                ))
        return _ordered_unique(result)


class KairosEvidenceProvider(AlertEvidenceProvider):
    def provide(self, rows: Iterable[Any], development_scores: Iterable[float] | None = None) -> tuple[AlertEvidence, ...]:
        native, calibration = tuple(rows), _development(development_scores)
        local = _local_percentiles(native, lambda row: _loss(row.raw_loss), lambda row: str(row.window) if getattr(row, "window", None) else None)
        result = []
        for index, row in enumerate(native):
            tier = str(row.mapping_tier).upper()
            quality = MappingQuality.EXACT if tier in {"IDENTITY", "EXACT"} else MappingQuality.TOLERANT if tier == "TOLERANT" else MappingQuality.PARTIAL
            value = _loss(row.raw_loss)
            result.append(AlertEvidence(
                _evidence_id("KAIROS", str(row.native_id), str(row.window), str(row.raw_event_id)), "KAIROS", "frozen", EvidenceGranularity.EDGE, value, calibration.percentile(value), bool(row.anomalous_native),
                event_ids=(str(row.raw_event_id),), node_ids=(str(row.src), str(row.dst)), src_uuid=str(row.src), dst_uuid=str(row.dst), relation=str(row.relation),
                timestamp_start=int(row.timestamp_ns), timestamp_end=int(row.timestamp_ns), role_hint=RoleHint.OBSERVATION, mapping_quality=quality,
                detector_metadata={"native_id": str(row.native_id), "window": str(row.window), "queue_ids": tuple(row.queue_ids), "queue_strength": float(row.queue_strength), "summary_membership": bool(row.summary_membership), "summary_component": row.summary_component, "loss_percentile": float(row.loss_percentile), "mapping_tier": tier},
                development_percentile=calibration.percentile(value), query_local_percentile=local[index],
            ))
        return _ordered_unique(result)


def fuse_same_object_noisy_or(evidence: Sequence[AlertEvidence]) -> AlertEvidence:
    if not evidence:
        raise ValueError("cannot fuse empty evidence")
    ordered = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    if any(item.object_key != ordered[0].object_key for item in ordered[1:]):
        raise ValueError("Noisy-OR fusion requires the same underlying object")
    by_detector: dict[str, list[AlertEvidence]] = {}
    for item in ordered:
        by_detector.setdefault(item.detector_id, []).append(item)
    contributions: dict[str, Any] = {}
    selected: list[AlertEvidence] = []
    for detector, rows in sorted(by_detector.items()):
        ranked = sorted(rows, key=lambda item: (-item.calibrated_score, item.evidence_id))
        selected.append(ranked[0])
        contributions[detector] = {"calibrated_score": ranked[0].calibrated_score, "source_evidence_ids": tuple(item.evidence_id for item in rows)}
    score = 1.0 - math.prod(1.0 - item.calibrated_score for item in selected)
    first = selected[0]
    granularities = {item.granularity for item in selected}
    edge_representable = all(
        item.granularity is EvidenceGranularity.EDGE and item.src_uuid is not None and item.dst_uuid is not None
        for item in selected
    ) and len({(item.src_uuid, item.dst_uuid) for item in selected}) == 1
    if edge_representable:
        granularity = EvidenceGranularity.EDGE
    elif granularities <= {EvidenceGranularity.EVENT, EvidenceGranularity.EDGE}:
        granularity = EvidenceGranularity.EVENT
    elif len(granularities) == 1:
        granularity = first.granularity
    else:
        raise ValueError("Noisy-OR fusion has incompatible granularities")
    common_node_ids = tuple(sorted(set.intersection(*(set(item.node_ids) for item in selected))))
    fields = ("src_uuid", "dst_uuid", "relation", "timestamp_start", "timestamp_end")
    conflicts = {name: tuple(sorted({getattr(item, name) for item in selected}, key=lambda value: "" if value is None else str(value))) for name in fields if len({getattr(item, name) for item in selected}) > 1}
    same_role = len({item.role_hint for item in selected}) == 1
    return AlertEvidence(
        "fusion:" + hashlib.sha256("\x1f".join(item.evidence_id for item in ordered).encode()).hexdigest()[:20],
        "Noisy-OR[" + ",".join(sorted(by_detector)) + "]", ALERT_EVIDENCE_SCHEMA_VERSION, granularity, None, score,
        any(item.native_decision for item in selected), event_ids=first.event_ids, node_ids=common_node_ids,
        supporting_event_ids=tuple(event for item in selected for event in item.supporting_event_ids), structural_context=first.structural_context,
        src_uuid=None if "src_uuid" in conflicts else first.src_uuid, dst_uuid=None if "dst_uuid" in conflicts else first.dst_uuid,
        relation=None if "relation" in conflicts else first.relation, timestamp_start=None if "timestamp_start" in conflicts else first.timestamp_start,
        timestamp_end=None if "timestamp_end" in conflicts else first.timestamp_end, role_hint=first.role_hint if same_role else RoleHint.UNKNOWN,
        mapping_quality=min((item.mapping_quality for item in selected), key=lambda item: [MappingQuality.UNMAPPED, MappingQuality.PARTIAL, MappingQuality.TOLERANT, MappingQuality.NATIVE, MappingQuality.EXACT].index(item)),
        detector_metadata={"fusion": "noisy_or", "per_detector_contributions": contributions, "identity_conflicts": conflicts},
        development_percentile=None, query_local_percentile=None,
    )


@dataclass(frozen=True, slots=True)
class CausalAgreement:
    reliability: Mapping[str, float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "reliability", _freeze_json(self.reliability))

    @classmethod
    def from_evidence(cls, evidence: Iterable[AlertEvidence]) -> "CausalAgreement":
        rows = tuple(evidence)
        by_object: dict[tuple[str, ...], set[str]] = {}
        for item in rows:
            by_object.setdefault(item.object_key, set()).add(item.detector_id)
        return cls({item.evidence_id: min(1.0, len(by_object[item.object_key]) / 2.0) for item in rows})

    def reliability_for(self, evidence_id: str) -> float:
        return float(self.reliability.get(evidence_id, 0.0))

    def provenance_facts(self) -> tuple[()]:
        return ()


__all__ = [
    "ALERT_EVIDENCE_SCHEMA_VERSION", "ORTHRUS_ALERTS_PATH", "AlertEvidence", "AlertEvidenceProvider", "CausalAgreement",
    "DevelopmentCalibrator", "EvidenceGranularity", "KairosEvidenceProvider", "MappingQuality", "NODLINKEvidenceAdapter",
    "OrthrusEvidenceProvider", "RCAIDEvidenceAdapter", "RoleHint", "VeloxEvidenceAdapter", "dump_evidence_jsonl",
    "fuse_same_object_noisy_or", "load_evidence_jsonl", "iter_evidence_jsonl",
]
