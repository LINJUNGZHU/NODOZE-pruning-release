"""Versioned, ground-truth-free detector alert evidence primitives."""

from __future__ import annotations

from abc import ABC, abstractmethod
import csv
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ALERT_EVIDENCE_SCHEMA_VERSION = "1.0"
ORTHRUS_ALERTS_PATH = Path("output/query-adaptive-feasibility-20260914/orthrus/alerts.json")


class EvidenceGranularity(str, Enum):
    EVENT = "EVENT"
    NODE = "NODE"
    STRUCTURAL = "STRUCTURAL"


class RoleHint(str, Enum):
    UNKNOWN = "UNKNOWN"
    OBSERVATION = "OBSERVATION"
    SOURCE = "SOURCE"
    TERMINAL = "TERMINAL"


class MappingQuality(str, Enum):
    EXACT = "EXACT"
    NATIVE = "NATIVE"
    PARTIAL = "PARTIAL"
    UNMAPPED = "UNMAPPED"


def _optional_string(value: object | None) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    return str(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("metadata must be JSON-safe")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValueError("metadata must be JSON-safe")


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    """An immutable detector observation with only detector-native identity."""

    evidence_id: str
    detector_name: str
    detector_version: str
    granularity: EvidenceGranularity
    raw_score: float
    calibrated_score: float
    native_decision: bool
    development_percentile: float | None = None
    query_local_percentile: float | None = None
    event_uuid: str | None = None
    node_uuid: str | None = None
    src_node_uuid: str | None = None
    dst_node_uuid: str | None = None
    relation: str | None = None
    time_ns: int | None = None
    role_hint: RoleHint = RoleHint.UNKNOWN
    supporting_event_uuids: tuple[str, ...] = ()
    structural_node_uuids: tuple[str, ...] = ()
    structural_event_uuids: tuple[str, ...] = ()
    mapping_quality: MappingQuality = MappingQuality.NATIVE
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = ALERT_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ALERT_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported AlertEvidence schema_version")
        if not self.evidence_id or not self.detector_name or not self.detector_version:
            raise ValueError("evidence identity and detector identity are required")
        if not math.isfinite(float(self.raw_score)):
            raise ValueError("raw_score must be finite")
        if not math.isfinite(float(self.calibrated_score)) or not 0.0 <= float(self.calibrated_score) <= 1.0:
            raise ValueError("calibrated_score must be finite and in [0, 1]")
        development_percentile = self.calibrated_score if self.development_percentile is None else self.development_percentile
        if not math.isfinite(float(development_percentile)) or not 0.0 <= float(development_percentile) <= 1.0:
            raise ValueError("development_percentile must be finite and in [0, 1]")
        if self.query_local_percentile is not None and (
            not math.isfinite(float(self.query_local_percentile)) or not 0.0 <= float(self.query_local_percentile) <= 1.0
        ):
            raise ValueError("query_local_percentile must be finite and in [0, 1]")
        if self.time_ns is not None and not isinstance(self.time_ns, int):
            raise ValueError("time_ns must be an integer")
        event_uuid = _optional_string(self.event_uuid)
        node_uuid = _optional_string(self.node_uuid)
        src_uuid = _optional_string(self.src_node_uuid)
        dst_uuid = _optional_string(self.dst_node_uuid)
        if self.granularity is EvidenceGranularity.EVENT and event_uuid is None:
            raise ValueError("EVENT evidence requires event_uuid")
        if self.granularity is EvidenceGranularity.NODE and node_uuid is None:
            raise ValueError("NODE evidence requires node_uuid")
        if self.granularity is EvidenceGranularity.STRUCTURAL and not (
            self.structural_node_uuids or self.structural_event_uuids
        ):
            raise ValueError("STRUCTURAL evidence requires native members")
        if self.granularity is EvidenceGranularity.NODE and any((event_uuid, src_uuid, dst_uuid)):
            raise ValueError("NODE evidence cannot carry edge identity")
        object.__setattr__(self, "event_uuid", event_uuid)
        object.__setattr__(self, "node_uuid", node_uuid)
        object.__setattr__(self, "src_node_uuid", src_uuid)
        object.__setattr__(self, "dst_node_uuid", dst_uuid)
        object.__setattr__(self, "relation", _optional_string(self.relation))
        object.__setattr__(self, "development_percentile", float(development_percentile))
        object.__setattr__(self, "query_local_percentile", None if self.query_local_percentile is None else float(self.query_local_percentile))
        object.__setattr__(self, "supporting_event_uuids", tuple(sorted(set(self.supporting_event_uuids))))
        object.__setattr__(self, "structural_node_uuids", tuple(sorted(set(self.structural_node_uuids))))
        object.__setattr__(self, "structural_event_uuids", tuple(sorted(set(self.structural_event_uuids))))
        object.__setattr__(self, "metadata", _json_value(dict(self.metadata)))

    @property
    def object_key(self) -> tuple[str, str]:
        if self.granularity is EvidenceGranularity.EVENT:
            assert self.event_uuid is not None
            return ("event", self.event_uuid)
        if self.granularity is EvidenceGranularity.NODE:
            assert self.node_uuid is not None
            return ("node", self.node_uuid)
        members = self.structural_event_uuids or self.structural_node_uuids
        return ("structural", "\x1f".join(members))

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "detector_name": self.detector_name,
            "detector_version": self.detector_version,
            "granularity": self.granularity.value,
            "raw_score": self.raw_score,
            "calibrated_score": self.calibrated_score,
            "native_decision": self.native_decision,
            "development_percentile": self.development_percentile,
            "query_local_percentile": self.query_local_percentile,
            "event_uuid": self.event_uuid,
            "node_uuid": self.node_uuid,
            "src_node_uuid": self.src_node_uuid,
            "dst_node_uuid": self.dst_node_uuid,
            "relation": self.relation,
            "time_ns": self.time_ns,
            "role_hint": self.role_hint.value,
            "supporting_event_uuids": list(self.supporting_event_uuids),
            "structural_node_uuids": list(self.structural_node_uuids),
            "structural_event_uuids": list(self.structural_event_uuids),
            "mapping_quality": self.mapping_quality.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "AlertEvidence":
        required = {"schema_version", "evidence_id", "detector_name", "detector_version", "granularity", "raw_score", "calibrated_score", "native_decision"}
        missing = required - set(record)
        if missing:
            raise ValueError("missing AlertEvidence fields: " + ", ".join(sorted(missing)))
        return cls(
            evidence_id=str(record["evidence_id"]), detector_name=str(record["detector_name"]),
            detector_version=str(record["detector_version"]), granularity=EvidenceGranularity(record["granularity"]),
            raw_score=float(record["raw_score"]), calibrated_score=float(record["calibrated_score"]),
            native_decision=bool(record["native_decision"]), event_uuid=record.get("event_uuid"),
            development_percentile=record.get("development_percentile"), query_local_percentile=record.get("query_local_percentile"),
            node_uuid=record.get("node_uuid"), src_node_uuid=record.get("src_node_uuid"),
            dst_node_uuid=record.get("dst_node_uuid"), relation=record.get("relation"), time_ns=record.get("time_ns"),
            role_hint=RoleHint(record.get("role_hint", RoleHint.UNKNOWN.value)),
            supporting_event_uuids=tuple(record.get("supporting_event_uuids", ())),
            structural_node_uuids=tuple(record.get("structural_node_uuids", ())),
            structural_event_uuids=tuple(record.get("structural_event_uuids", ())),
            mapping_quality=MappingQuality(record.get("mapping_quality", MappingQuality.NATIVE.value)),
            metadata=record.get("metadata", {}), schema_version=str(record["schema_version"]),
        )


def dump_evidence_jsonl(path: str | Path, evidence: Iterable[AlertEvidence]) -> None:
    rows = sorted(evidence, key=lambda item: item.evidence_id)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for item in rows:
            handle.write(json.dumps(item.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            handle.write("\n")


def load_evidence_jsonl(path: str | Path) -> tuple[AlertEvidence, ...]:
    rows: list[AlertEvidence] = []
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                try:
                    rows.append(AlertEvidence.from_record(json.loads(line)))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid AlertEvidence JSONL line {number}") from exc
    identifiers = [item.evidence_id for item in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("AlertEvidence JSONL has duplicate evidence_id")
    return tuple(sorted(rows, key=lambda item: item.evidence_id))


@dataclass(frozen=True, slots=True)
class DevelopmentCalibrator:
    """Empirical CDF calibration using a tie-stable upper rank."""

    development_scores: tuple[float, ...]

    @classmethod
    def fit(cls, scores: Iterable[float]) -> "DevelopmentCalibrator":
        values = tuple(sorted(float(score) for score in scores))
        if not values:
            raise ValueError("development calibration needs at least one score")
        if not all(math.isfinite(value) for value in values):
            raise ValueError("development calibration scores must be finite")
        return cls(values)

    def percentile(self, score: float, *, scope_values: Iterable[float] | None = None) -> float:
        value = float(score)
        if not math.isfinite(value):
            raise ValueError("score must be finite")
        population = self.development_scores if scope_values is None else tuple(sorted(float(item) for item in scope_values))
        if not population or not all(math.isfinite(item) for item in population):
            raise ValueError("calibration population must contain finite values")
        count = sum(item <= value for item in population)
        return count / len(population)


def _read_rows(source: str | Path | Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", newline="") as handle:
                return [dict(row) for row in csv.DictReader(handle)]
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("native alert input must be a list")
        return [dict(row) for row in payload]
    return [dict(row) for row in source]


def _losses(rows: Iterable[Mapping[str, Any]]) -> list[float]:
    values = [float(row["loss"]) for row in rows]
    if not values:
        raise ValueError("development artifacts contain no loss scores")
    return values


def _local_percentiles(rows: Sequence[Mapping[str, Any]], score_field: str) -> dict[int, float]:
    """Calculate rank percentiles inside a native query, then day, then file."""
    groups: dict[tuple[str, str], list[tuple[int, float]]] = {}
    for index, row in enumerate(rows):
        query_id = _optional_string(row.get("query_id"))
        day = _optional_string(row.get("day"))
        key = ("query", query_id) if query_id is not None else (("day", day) if day is not None else ("file", "all"))
        groups.setdefault(key, []).append((index, float(row[score_field])))
    result: dict[int, float] = {}
    for group in groups.values():
        calibration = DevelopmentCalibrator.fit(score for _, score in group)
        for index, score in group:
            result[index] = calibration.percentile(score)
    return result


def _evidence_id(detector: str, object_key: tuple[str, ...]) -> str:
    source = "\x1f".join((detector, *object_key)).encode()
    return detector.lower() + ":" + hashlib.sha256(source).hexdigest()[:20]


def _ordered_unique(evidence: Iterable[AlertEvidence]) -> tuple[AlertEvidence, ...]:
    ordered = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    identifiers = [item.evidence_id for item in ordered]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate evidence_id from native detector output")
    return ordered


_EDGE_RELATIONS = {
    "1": "EVENT_CONNECT", "2": "EVENT_EXECUTE", "3": "EVENT_OPEN", "4": "EVENT_READ",
    "5": "EVENT_RECVFROM", "6": "EVENT_RECVMSG", "7": "EVENT_SENDMSG", "8": "EVENT_SENDTO",
    "9": "EVENT_WRITE", "10": "EVENT_CLONE",
}


class AlertEvidenceProvider(ABC):
    @abstractmethod
    def provide(self, *args: Any, **kwargs: Any) -> tuple[AlertEvidence, ...]:
        """Return deterministic detector-native evidence."""


class VeloxEvidenceAdapter(AlertEvidenceProvider):
    def __init__(self, *, version: str) -> None:
        self.version = version

    def adapt(self, rows: str | Path | Iterable[Mapping[str, Any]], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> tuple[AlertEvidence, ...]:
        native_rows = _read_rows(rows)
        development = _read_rows(development_rows)
        calibration = DevelopmentCalibrator.fit(_losses(development))
        threshold = max(calibration.development_scores)
        local_percentiles = _local_percentiles(native_rows, "loss")
        evidence = []
        for index, row in enumerate(native_rows):
            required = ("loss", "event_uuid", "src_node_uuid", "dst_node_uuid")
            if any(_optional_string(row.get(key)) is None for key in required):
                raise ValueError("Velox native row lacks required event identity")
            loss = float(row["loss"])
            event_uuid = str(row["event_uuid"])
            edge_type = _optional_string(row.get("edge_type"))
            evidence.append(AlertEvidence(
                evidence_id=_evidence_id("Velox", ("event", event_uuid)), detector_name="Velox", detector_version=self.version,
                granularity=EvidenceGranularity.EVENT, raw_score=loss, calibrated_score=calibration.percentile(loss),
                native_decision=loss > threshold, development_percentile=calibration.percentile(loss),
                query_local_percentile=local_percentiles[index], event_uuid=event_uuid, src_node_uuid=str(row["src_node_uuid"]),
                dst_node_uuid=str(row["dst_node_uuid"]), relation=_optional_string(row.get("relation")) or _EDGE_RELATIONS.get(edge_type or ""),
                time_ns=int(row["time"]) if _optional_string(row.get("time")) is not None else None,
                role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT,
                metadata={"native_threshold": threshold, "native_edge_type": edge_type},
            ))
        return _ordered_unique(evidence)

    provide = adapt


class _PIDSMakerNodeAdapter(AlertEvidenceProvider):
    detector_name: str

    def __init__(self, *, version: str) -> None:
        self.version = version

    def adapt(self, rows: str | Path | Iterable[Mapping[str, Any]], development_rows: str | Path | Iterable[Mapping[str, Any]]) -> tuple[AlertEvidence, ...]:
        native_rows = _read_rows(rows)
        calibration = DevelopmentCalibrator.fit(_losses(_read_rows(development_rows)))
        threshold = max(calibration.development_scores)
        local_percentiles = _local_percentiles(native_rows, "loss")
        evidence = []
        for index, row in enumerate(native_rows):
            node_uuid = _optional_string(row.get("node_uuid"))
            if node_uuid is None or _optional_string(row.get("loss")) is None:
                raise ValueError(f"{self.detector_name} native row lacks node UUID or loss")
            loss = float(row["loss"])
            evidence.append(AlertEvidence(
                evidence_id=_evidence_id(self.detector_name, ("node", node_uuid)), detector_name=self.detector_name,
                detector_version=self.version, granularity=EvidenceGranularity.NODE, raw_score=loss,
                calibrated_score=calibration.percentile(loss), native_decision=loss > threshold,
                development_percentile=calibration.percentile(loss), query_local_percentile=local_percentiles[index],
                node_uuid=node_uuid, role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT,
                metadata={"native_threshold": threshold, "native_node_id": _optional_string(row.get("node"))},
            ))
        return _ordered_unique(evidence)

    provide = adapt


class RCAIDEvidenceAdapter(_PIDSMakerNodeAdapter):
    detector_name = "R-CAID"


class NODLINKEvidenceAdapter(_PIDSMakerNodeAdapter):
    detector_name = "NODLINK"


class OrthrusEvidenceProvider(AlertEvidenceProvider):
    """Compatibility translation for the frozen ORTHRUS alert artifact."""

    def __init__(self, *, version: str = "frozen") -> None:
        self.version = version

    def provide(self, source: str | Path = ORTHRUS_ALERTS_PATH, development_rows: str | Path | Iterable[Mapping[str, Any]] | None = None) -> tuple[AlertEvidence, ...]:
        rows = _read_rows(source)
        scores = [float(row["alert_score"]) for row in rows]
        calibration = DevelopmentCalibrator.fit(_losses(_read_rows(development_rows)) if development_rows is not None else scores)
        local_percentiles = _local_percentiles(rows, "alert_score")
        result = []
        for index, row in enumerate(rows):
            score = float(row["alert_score"])
            threshold = float(row["threshold"])
            event_ids = tuple(sorted(set(str(item) for item in row.get("seed_event_ids", ()))))
            for event_uuid in event_ids:
                result.append(AlertEvidence(
                    evidence_id=_evidence_id("ORTHRUS", ("alert", str(row.get("alert_id", event_uuid)), event_uuid)), detector_name="ORTHRUS", detector_version=self.version,
                    granularity=EvidenceGranularity.EVENT, raw_score=score, calibrated_score=calibration.percentile(score),
                    native_decision=score > threshold, development_percentile=calibration.percentile(score),
                    query_local_percentile=local_percentiles[index], event_uuid=event_uuid,
                    time_ns=int(row["event_time_end"]) if row.get("event_time_end") is not None else None,
                    role_hint=RoleHint.OBSERVATION, supporting_event_uuids=tuple(str(item) for item in row.get("supporting_event_ids", ())),
                    mapping_quality=MappingQuality.EXACT if row.get("mapping_status") == "MATCHED" else MappingQuality.PARTIAL,
                    metadata={"native_alert_id": row.get("alert_id"), "native_threshold": threshold},
                ))
        return _ordered_unique(result)


class KairosEvidenceProvider(AlertEvidenceProvider):
    """Compatibility translation for native KAIROS mapping output."""

    def __init__(self, *, version: str = "frozen") -> None:
        self.version = version

    def provide(self, rows: Iterable[Any], development_scores: Iterable[float] | None = None) -> tuple[AlertEvidence, ...]:
        native_rows = tuple(rows)
        calibration = DevelopmentCalibrator.fit(development_scores if development_scores is not None else (float(row.raw_loss) for row in native_rows))
        local_calibration = DevelopmentCalibrator.fit(float(row.raw_loss) for row in native_rows)
        result = []
        for row in native_rows:
            event_uuid = str(row.raw_event_id)
            tier = str(row.mapping_tier)
            quality = MappingQuality.EXACT if tier == "IDENTITY" else MappingQuality.PARTIAL
            result.append(AlertEvidence(
                evidence_id=_evidence_id("KAIROS", ("event", event_uuid)), detector_name="KAIROS", detector_version=self.version,
                granularity=EvidenceGranularity.EVENT, raw_score=float(row.raw_loss),
                calibrated_score=calibration.percentile(float(row.raw_loss)), native_decision=bool(row.anomalous_native),
                development_percentile=calibration.percentile(float(row.raw_loss)),
                query_local_percentile=local_calibration.percentile(float(row.raw_loss)),
                event_uuid=event_uuid, src_node_uuid=str(row.src), dst_node_uuid=str(row.dst), relation=str(row.relation),
                time_ns=int(row.timestamp_ns), role_hint=RoleHint.OBSERVATION, mapping_quality=quality,
                metadata={"native_id": str(row.native_id), "mapping_tier": tier},
            ))
        return _ordered_unique(result)


def fuse_same_object_noisy_or(evidence: Sequence[AlertEvidence]) -> AlertEvidence:
    """Fuse calibrated scores only after proving every input names one object."""
    if not evidence:
        raise ValueError("cannot fuse empty evidence")
    ordered = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    object_key = ordered[0].object_key
    if any(item.object_key != object_key for item in ordered[1:]):
        raise ValueError("Noisy-OR fusion requires the same underlying object")
    score = 1.0 - math.prod(1.0 - item.calibrated_score for item in ordered)
    first = ordered[0]
    detectors = sorted({item.detector_name for item in ordered})
    roles = {item.role_hint for item in ordered}
    return AlertEvidence(
        evidence_id="fusion:" + hashlib.sha256("\x1f".join(item.evidence_id for item in ordered).encode()).hexdigest()[:20],
        detector_name="Noisy-OR[" + ",".join(detectors) + "]", detector_version=ALERT_EVIDENCE_SCHEMA_VERSION,
        granularity=first.granularity, raw_score=score, calibrated_score=score,
        native_decision=any(item.native_decision for item in ordered), development_percentile=score,
        query_local_percentile=score, event_uuid=first.event_uuid, node_uuid=first.node_uuid,
        src_node_uuid=first.src_node_uuid, dst_node_uuid=first.dst_node_uuid, relation=first.relation, time_ns=first.time_ns,
        role_hint=first.role_hint if len(roles) == 1 else RoleHint.UNKNOWN,
        supporting_event_uuids=tuple(item for row in ordered for item in row.supporting_event_uuids),
        structural_node_uuids=first.structural_node_uuids, structural_event_uuids=first.structural_event_uuids,
        mapping_quality=first.mapping_quality,
        metadata={"source_evidence_ids": [item.evidence_id for item in ordered], "fusion": "noisy_or"},
    )


@dataclass(frozen=True, slots=True)
class CausalAgreement:
    """A reliability prior; it intentionally stores no provenance graph facts."""

    _reliability: Mapping[str, float]

    @classmethod
    def from_evidence(cls, evidence: Iterable[AlertEvidence]) -> "CausalAgreement":
        rows = tuple(evidence)
        by_object: dict[tuple[str, str], set[str]] = {}
        for row in rows:
            by_object.setdefault(row.object_key, set()).add(row.detector_name)
        return cls({row.evidence_id: min(1.0, len(by_object[row.object_key]) / 2.0) for row in rows})

    def reliability_for(self, evidence_id: str) -> float:
        return self._reliability.get(evidence_id, 0.0)

    def provenance_facts(self) -> tuple[()]:
        return ()


__all__ = [
    "ALERT_EVIDENCE_SCHEMA_VERSION", "ORTHRUS_ALERTS_PATH", "AlertEvidence", "AlertEvidenceProvider",
    "CausalAgreement", "DevelopmentCalibrator", "EvidenceGranularity", "KairosEvidenceProvider",
    "MappingQuality", "NODLINKEvidenceAdapter", "OrthrusEvidenceProvider", "RCAIDEvidenceAdapter",
    "RoleHint", "VeloxEvidenceAdapter", "dump_evidence_jsonl", "fuse_same_object_noisy_or", "load_evidence_jsonl",
]
