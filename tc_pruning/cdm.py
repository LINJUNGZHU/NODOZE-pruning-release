from __future__ import annotations

import gzip
import glob
import json
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Mapping, TextIO

from .models import (
    EdgeRecord,
    NodeRecord,
    Observation,
    StoredEdge,
    normalize_entity_label,
)


READ_LIKE_EVENTS = frozenset(
    {
        "EVENT_READ",
        "EVENT_RECVFROM",
        "EVENT_RECVMSG",
        "EVENT_LOADLIBRARY",
        "EVENT_MMAP",
        "EVENT_ACCEPT",
        "EVENT_READ_SOCKET_PARAMS",
    }
)

# For read/receive events the CDM subject is the information-flow destination.
# Fork/clone are the other important exception for investigation: their useful
# anchor is the newly created child rather than the parent that emitted the
# event.  Other event types are anchored at the emitting subject/source.
DESTINATION_ANCHOR_EVENTS = READ_LIKE_EVENTS | frozenset(
    {"EVENT_CLONE", "EVENT_FORK"}
)


def event_investigation_anchor(edge: EdgeRecord | StoredEdge) -> str:
    """Return the process/entity endpoint from which a POI should be traced."""
    return edge.dst if edge.relation.upper() in DESTINATION_ANCHOR_EVENTS else edge.src


def event_backward_anchor(edge: EdgeRecord | StoredEdge) -> str:
    """Return the endpoint whose history can explain a POI event."""
    return edge.dst if edge.relation.upper() in READ_LIKE_EVENTS else edge.src


def event_forward_anchor(edge: EdgeRecord | StoredEdge) -> str:
    """Return the process-side endpoint whose later activity a CDM POI exposes."""
    relation = edge.relation.upper()
    if relation in DESTINATION_ANCHOR_EVENTS:
        return edge.dst
    # Preserve the generic information-flow behavior for non-CDM relations.
    return edge.src if relation.startswith("EVENT_") else edge.dst


@dataclass(slots=True)
class ReaderStats:
    records_read: int = 0
    records_malformed: int = 0
    observations_emitted: int = 0


def _scalar(value, default=""):
    """Unwrap Avro JSON unions such as {"string": "x"}."""
    if value is None:
        return default
    if isinstance(value, Mapping):
        if not value:
            return default
        if "map" in value and len(value) == 1:
            return value["map"]
        return _scalar(next(iter(value.values())), default)
    return value


def _uuid(value) -> str:
    result = _scalar(value, "")
    if isinstance(result, bytes):
        return result.hex()
    return str(result) if result is not None else ""


def _record_kind_and_body(raw: Mapping) -> tuple[str, Mapping] | tuple[None, None]:
    datum = raw.get("datum", raw)
    if isinstance(datum, tuple) and len(datum) == 2:
        kind, body = datum
        return str(kind).rsplit(".", 1)[-1], body
    if not isinstance(datum, Mapping) or not datum:
        return None, None
    if len(datum) == 1:
        key, value = next(iter(datum.items()))
        if isinstance(value, Mapping):
            return str(key).rsplit(".", 1)[-1], value
    kind = raw.get("datumType") or raw.get("typeName")
    if kind:
        return str(kind).rsplit(".", 1)[-1], datum
    return None, None


def _node_properties(body: Mapping) -> dict[str, str]:
    result: dict[str, str] = {}
    sources = [body.get("properties")]
    base = body.get("baseObject")
    if isinstance(base, Mapping):
        sources.append(base.get("properties"))
    for source in sources:
        value = _scalar(source, {})
        if isinstance(value, Mapping):
            for key, item in value.items():
                scalar = _scalar(item, "")
                if not isinstance(scalar, (Mapping, list, tuple)) and scalar not in (None, ""):
                    result[str(key)] = str(scalar)
    for key in (
        "cmdLine",
        "path",
        "filename",
        "name",
        "gid",
        "localAddress",
        "localPort",
        "remoteAddress",
        "remotePort",
    ):
        value = _scalar(body.get(key), "")
        if not isinstance(value, (Mapping, list, tuple)) and value not in (None, ""):
            result[key] = str(value)
    return result


def _node_label(kind: str, body: Mapping, uuid: str, properties: Mapping[str, str]) -> str:
    candidates = (
        "cmdLine",
        "path",
        "filename",
        "url",
        "name",
        "localAddress",
        "remoteAddress",
    )
    for key in candidates:
        value = _scalar(body.get(key), properties.get(key, ""))
        if value not in (None, ""):
            label = str(value)
            if kind == "NetFlowObject" and key in {"localAddress", "remoteAddress"}:
                port_key = "localPort" if key == "localAddress" else "remotePort"
                port = _scalar(body.get(port_key), "")
                if port not in (None, ""):
                    label = f"{label}:{port}"
            return label
    return uuid


def _semantic_key(kind: str, node_type: str, label: str, properties: Mapping[str, str]) -> str:
    if kind == "NetFlowObject":
        address = properties.get("remoteAddress") or properties.get("localAddress")
        port = properties.get("remotePort") or properties.get("localPort")
        if address:
            return f"socket:{address}{':' + port if port else ''}"
    return normalize_entity_label(node_type, label)


def _event_data_size(body: Mapping, properties: Mapping[str, str]) -> int | None:
    for key in (
        "size",
        "bytes",
        "byteCount",
        "bytesRead",
        "bytesWritten",
    ):
        value = _scalar(body.get(key), properties.get(key, ""))
        if value in (None, "") or isinstance(value, (Mapping, list, tuple)):
            continue
        try:
            amount = int(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if amount >= 0:
            return amount
    return None


NODE_TYPES = {
    "Subject": "process",
    "FileObject": "file",
    "NetFlowObject": "socket",
    "SrcSinkObject": "srcsink",
    "MemoryObject": "memory",
    "UnnamedPipeObject": "pipe",
    "RegistryKeyObject": "registry",
    "Principal": "principal",
}


def normalize_cdm_record(raw: Mapping) -> list[Observation]:
    """Normalize one decoded CDM18/CDM20 TCCDMDatum record."""
    kind, body = _record_kind_and_body(raw)
    if kind is None or body is None:
        return []

    if kind in NODE_TYPES:
        node_uuid = _uuid(body.get("uuid"))
        if not node_uuid:
            return []
        host = _uuid(body.get("hostId"))
        properties = _node_properties(body)
        node_type = NODE_TYPES[kind]
        label = _node_label(kind, body, node_uuid, properties)
        observations: list[Observation] = [
            NodeRecord(
                uuid=node_uuid,
                node_type=node_type,
                label=label,
                host=host,
                semantic_key=_semantic_key(kind, node_type, label, properties),
                properties=properties,
            )
        ]
        if kind == "Subject":
            parent = _uuid(body.get("parentSubject"))
            if parent and parent != node_uuid:
                started = int(
                    _scalar(
                        body.get("startTimestampNanos"),
                        _scalar(body.get("startTimestamp"), 0),
                    )
                    or 0
                )
                observations.append(
                    EdgeRecord(
                        event_id=f"LINEAGE:{node_uuid}",
                        src=parent,
                        dst=node_uuid,
                        relation="EVENT_FORK",
                        timestamp_ns=started,
                        host=host,
                    )
                )
        return observations

    if kind != "Event":
        return []

    event_id = _uuid(body.get("uuid"))
    subject = _uuid(body.get("subject"))
    relation = str(_scalar(body.get("type"), "EVENT_UNKNOWN"))
    timestamp = int(_scalar(body.get("timestampNanos"), 0) or 0)
    host = _uuid(body.get("hostId"))
    observations: list[Observation] = []

    event_properties = _node_properties(body)
    data_size = _event_data_size(body, event_properties)
    executable = event_properties.get("exec") or event_properties.get("command")
    if subject and executable:
        process_properties = {
            key: event_properties[key]
            for key in ("exec", "command", "cmdLine", "gid")
            if key in event_properties
        }
        observations.append(
            NodeRecord(
                uuid=subject,
                node_type="process",
                label=executable,
                host=host,
                semantic_key=normalize_entity_label("process", executable),
                properties=process_properties,
            )
        )

    for index, field in enumerate(("predicateObject", "predicateObject2"), start=1):
        obj = _uuid(body.get(field))
        if not subject or not obj:
            continue
        path = str(_scalar(body.get(f"{field}Path"), "") or "")
        if path:
            observations.append(
                NodeRecord(
                    uuid=obj,
                    node_type="file",
                    label=path,
                    host=host,
                    semantic_key=normalize_entity_label("file", path),
                    properties={"path": path},
                )
            )
        if relation in READ_LIKE_EVENTS:
            src, dst = obj, subject
        else:
            src, dst = subject, obj
        edge_id = event_id if index == 1 else f"{event_id}:2"
        observations.append(
            EdgeRecord(
                event_id=edge_id,
                src=src,
                dst=dst,
                relation=relation,
                timestamp_ns=timestamp,
                host=host,
                data_size=data_size,
            )
        )
    return observations


class CDMStreamReader:
    """Stream CDM JSONL or Avro records without loading a source file in memory."""

    def __init__(
        self,
        paths: Iterable[str | Path],
        *,
        schema_path: str | Path | None = None,
        strict: bool = False,
        max_records: int | None = None,
    ) -> None:
        self.paths = []
        for raw_path in paths:
            path = Path(raw_path)
            if path.is_file():
                matches = [path]
            elif path.is_dir():
                matches = sorted(item for item in path.rglob("*") if item.is_file())
            else:
                matches = [Path(item) for item in sorted(glob.glob(str(path), recursive=True))]
            if not matches:
                raise FileNotFoundError(f"No CDM input files matched: {path}")
            self.paths.extend(matches)
        self.schema_path = Path(schema_path) if schema_path else None
        self.strict = strict
        self.max_records = max_records
        self.stats = ReaderStats()

    def __iter__(self) -> Iterator[Observation]:
        for path in self.paths:
            records = self._iter_json(path) if self._is_json(path) else self._iter_avro(path)
            for raw in records:
                if self.max_records is not None and self.stats.records_read >= self.max_records:
                    return
                self.stats.records_read += 1
                try:
                    observations = normalize_cdm_record(raw)
                except (TypeError, ValueError, OverflowError) as exc:
                    self.stats.records_malformed += 1
                    if self.strict:
                        raise ValueError(f"Malformed CDM record in {path}: {exc}") from exc
                    continue
                for observation in observations:
                    self.stats.observations_emitted += 1
                    yield observation

    @staticmethod
    def _is_json(path: Path) -> bool:
        suffixes = [suffix.lower() for suffix in path.suffixes]
        if suffixes and suffixes[-1] == ".gz":
            suffixes = suffixes[:-1]
        return bool(suffixes and suffixes[-1] in {".json", ".jsonl", ".ndjson"})

    def _iter_json(self, path: Path) -> Iterator[Mapping]:
        opener = gzip.open if path.suffix.lower() == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    self.stats.records_read += 1
                    self.stats.records_malformed += 1
                    if self.strict:
                        raise ValueError(
                            f"Malformed CDM JSON in {path} line {line_number}"
                        ) from exc

    def _iter_avro(self, path: Path) -> Iterator[Mapping]:
        try:
            from fastavro import reader
        except ImportError as exc:
            raise RuntimeError(
                "Avro input requires fastavro; install requirements.txt"
            ) from exc

        opener = gzip.open if path.suffix.lower() == ".gz" else open
        with opener(path, "rb") as stream:
            kwargs = {"return_record_name": True}
            if self.schema_path:
                with open(self.schema_path, "r", encoding="utf-8") as schema_stream:
                    kwargs["reader_schema"] = json.load(schema_stream)
            yield from reader(stream, **kwargs)


__all__ = [
    "CDMStreamReader",
    "DESTINATION_ANCHOR_EVENTS",
    "ReaderStats",
    "event_backward_anchor",
    "event_investigation_anchor",
    "normalize_cdm_record",
    "READ_LIKE_EVENTS",
]
