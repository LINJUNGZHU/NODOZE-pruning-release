from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator

from .cdm import ReaderStats
from .models import EdgeRecord, NodeRecord, Observation
from .store import ProvenanceStore


_LINE_RE = re.compile(
    r"^(?P<event>\d+)\s+(?P<timestamp>\d+\.\d+)\s+\d+\s+\d+\s+"
    r"(?P<command>.*?)\s+\((?P<tid>\d+)\)\s+(?P<direction>[<>])\s+"
    r"(?P<call>\S+)(?:\s+(?P<details>.*))?$"
)
_FILE_FD_RE = re.compile(r"\bfd=-?\d+\(<f>([^)]+)\)")
_SOCKET_FD_RE = re.compile(r"\bfd=-?\d+\(<(?:4|6)t?>([^)]+)\)")
_UNIX_FD_RE = re.compile(r"\bfd=-?\d+\(<u>([^)]+)\)")
_RESULT_RE = re.compile(r"(?:^|\s)res=(-?\d+)")

_READ_CALLS = frozenset({"read", "pread", "pread64", "readv", "preadv"})
_WRITE_CALLS = frozenset({"write", "pwrite", "pwrite64", "writev", "pwritev"})
_OPEN_CALLS = frozenset({"open", "openat", "creat"})
_RECV_CALLS = frozenset({"recv", "recvfrom", "recvmsg"})
_SEND_CALLS = frozenset({"send", "sendto", "sendmsg"})
_FORK_CALLS = frozenset({"clone", "fork", "vfork"})
_SUPPORTED_CALLS = (
    _READ_CALLS | _WRITE_CALLS | _OPEN_CALLS | _RECV_CALLS | _SEND_CALLS
    | _FORK_CALLS
    | frozenset({"accept", "accept4", "connect", "execve", "execveat", "unlink", "unlinkat"})
)


@dataclass(frozen=True, slots=True)
class DepImpactProperty:
    poi: str
    high_rp: str | None = None
    detection_size: int | None = None


@dataclass(frozen=True, slots=True)
class _SysdigLine:
    event: str
    timestamp_ns: int
    command: str
    tid: str
    direction: str
    call: str
    details: str


def stable_entity_id(node_type: str, identity: str, host: str) -> str:
    value = f"sysdig:{host}:{node_type}:{identity}"
    return f"sysdig:{node_type}:{uuid.uuid5(uuid.NAMESPACE_URL, value)}"


def _timestamp_ns(value: str) -> int:
    seconds, fraction = value.split(".", 1)
    return int(seconds) * 1_000_000_000 + int((fraction + "000000000")[:9])


def _parse_line(line: str) -> _SysdigLine | None:
    match = _LINE_RE.match(line.rstrip("\r\n"))
    if match is None:
        return None
    return _SysdigLine(
        event=match.group("event"),
        timestamp_ns=_timestamp_ns(match.group("timestamp")),
        command=match.group("command").strip(),
        tid=match.group("tid"),
        direction=match.group("direction"),
        call=match.group("call").lower(),
        details=match.group("details") or "",
    )


def _field(details: str, name: str) -> str | None:
    match = re.search(rf"(?:^|\s){re.escape(name)}=([^\s]+)", details)
    return match.group(1) if match else None


def _absolute_path(value: str | None, cwd: str | None) -> str | None:
    if not value or value in {"<NA>", "NULL"}:
        return None
    nested = re.search(r"\((/[^)]+)\)$", value)
    if nested:
        value = nested.group(1)
    value = value.removesuffix("(deleted)")
    if value.startswith("/"):
        return str(PurePosixPath(value))
    if cwd and cwd.startswith("/"):
        return str(PurePosixPath(cwd) / value)
    return value


def _file_path(entry: _SysdigLine | None, exit_line: _SysdigLine) -> str | None:
    details = ((entry.details + " ") if entry else "") + exit_line.details
    match = _FILE_FD_RE.search(details)
    if match:
        return _absolute_path(match.group(1), _field(details, "cwd"))
    return _absolute_path(
        _field(exit_line.details, "name")
        or (_field(entry.details, "name") if entry else None)
        or _field(exit_line.details, "exe"),
        _field(exit_line.details, "cwd")
        or (_field(entry.details, "cwd") if entry else None),
    )


def _socket_label(entry: _SysdigLine | None, exit_line: _SysdigLine) -> str | None:
    details = ((entry.details + " ") if entry else "") + exit_line.details
    for pattern in (_SOCKET_FD_RE, _UNIX_FD_RE):
        match = pattern.search(details)
        if match:
            return match.group(1)
    return _field(exit_line.details, "tuple") or (
        _field(entry.details, "tuple") if entry else None
    )


def _result(details: str) -> int | None:
    match = _RESULT_RE.search(details)
    return int(match.group(1)) if match else None


class SysdigStreamReader:
    """Stream DEPIMPACT's sysdig text format into the canonical graph model."""

    def __init__(
        self,
        paths: Iterable[str | Path],
        *,
        host: str = "sysdig",
        strict: bool = False,
        max_records: int | None = None,
    ) -> None:
        self.paths = [Path(path) for path in paths]
        self.host = host
        self.strict = strict
        self.max_records = max_records
        self.stats = ReaderStats()
        self._pending: dict[str, _SysdigLine] = {}

    def __iter__(self) -> Iterator[Observation]:
        for path in self.paths:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for line_number, raw in enumerate(stream, start=1):
                    if self.max_records is not None and self.stats.records_read >= self.max_records:
                        return
                    self.stats.records_read += 1
                    parsed = _parse_line(raw)
                    if parsed is None:
                        self.stats.records_malformed += 1
                        if self.strict:
                            raise ValueError(f"Malformed sysdig record in {path} line {line_number}")
                        continue
                    if parsed.call not in _SUPPORTED_CALLS:
                        continue
                    if parsed.direction == ">":
                        self._pending[parsed.tid] = parsed
                        continue
                    entry = self._pending.pop(parsed.tid, None)
                    if entry is not None and entry.call != parsed.call:
                        entry = None
                    for observation in self._normalize_exit(entry, parsed):
                        self.stats.observations_emitted += 1
                        yield observation

    def _normalize_exit(
        self, entry: _SysdigLine | None, exit_line: _SysdigLine
    ) -> list[Observation]:
        result = _result(exit_line.details)
        if result is not None and result < 0:
            return []
        process_id = stable_entity_id("process", exit_line.tid, self.host)
        executable = _field(exit_line.details, "exepath")
        process_label = (
            executable if executable and executable != "<NA>" else exit_line.command
        )
        observations: list[Observation] = [
            NodeRecord(process_id, "process", process_label, self.host)
        ]
        call = exit_line.call

        if call in _FORK_CALLS:
            if result is None or result == 0:
                return []
            child_id = stable_entity_id("process", str(result), self.host)
            observations.append(NodeRecord(child_id, "process", str(result), self.host))
            observations.append(self._edge(exit_line, process_id, child_id, "EVENT_FORK"))
            return observations

        if call in {"execve", "execveat"}:
            path = _absolute_path(_field(exit_line.details, "exe"), _field(exit_line.details, "cwd"))
            return self._resource_edge(observations, exit_line, process_id, "file", path, "EVENT_EXECUTE")

        if call in _READ_CALLS | _WRITE_CALLS | _OPEN_CALLS | {"unlink", "unlinkat"}:
            relation = (
                "EVENT_READ" if call in _READ_CALLS else
                "EVENT_WRITE" if call in _WRITE_CALLS else
                "EVENT_OPEN" if call in _OPEN_CALLS else
                "EVENT_UNLINK"
            )
            path = _file_path(entry, exit_line)
            data_size = result if call in _READ_CALLS | _WRITE_CALLS else None
            return self._resource_edge(
                observations, exit_line, process_id, "file", path, relation,
                data_size=data_size,
            )

        relation = (
            "EVENT_RECVFROM" if call in _RECV_CALLS else
            "EVENT_SENDTO" if call in _SEND_CALLS else
            "EVENT_ACCEPT" if call in {"accept", "accept4"} else
            "EVENT_CONNECT"
        )
        return self._resource_edge(
            observations, exit_line, process_id, "socket",
            _socket_label(entry, exit_line), relation,
            data_size=result if call in _RECV_CALLS | _SEND_CALLS else None,
        )

    def _resource_edge(
        self,
        observations: list[Observation],
        exit_line: _SysdigLine,
        process_id: str,
        node_type: str,
        label: str | None,
        relation: str,
        *,
        data_size: int | None = None,
    ) -> list[Observation]:
        if not label:
            return []
        resource_id = stable_entity_id(node_type, label, self.host)
        observations.append(NodeRecord(resource_id, node_type, label, self.host))
        if relation in {"EVENT_READ", "EVENT_RECVFROM", "EVENT_ACCEPT"}:
            src, dst = resource_id, process_id
        else:
            src, dst = process_id, resource_id
        observations.append(self._edge(exit_line, src, dst, relation, data_size))
        return observations

    def _edge(
        self,
        line: _SysdigLine,
        src: str,
        dst: str,
        relation: str,
        data_size: int | None = None,
    ) -> EdgeRecord:
        return EdgeRecord(
            f"sysdig:{line.event}", src, dst, relation,
            line.timestamp_ns, self.host, data_size,
        )


def load_depimpact_property(path: str | Path) -> DepImpactProperty:
    values: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Malformed DEPIMPACT property line: {raw}")
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()
    poi = values.get("poi") or values.get("highrp")
    if not poi:
        raise ValueError("DEPIMPACT property file must define POI or highRP")
    detection_size = values.get("detectionsize")
    return DepImpactProperty(
        poi=poi,
        high_rp=values.get("highrp"),
        detection_size=int(detection_size) if detection_size else None,
    )


def resolve_depimpact_poi(
    store: ProvenanceStore, specification: DepImpactProperty
) -> dict:
    parameters: list[object] = [specification.poi]
    size_clause = ""
    selection_rule = "latest_write"
    if specification.detection_size is not None:
        size_clause = " AND e.data_size=?"
        parameters.append(specification.detection_size)
        selection_rule = "latest_matching_size_write"
    row = store.conn.execute(
        """
        SELECT e.event_id
        FROM edges e JOIN nodes n ON n.uuid=e.dst
        WHERE n.node_type='file' AND n.label=? AND e.relation='EVENT_WRITE'
        """ + size_clause + " ORDER BY e.timestamp_ns DESC, e.id DESC LIMIT 1",
        parameters,
    ).fetchone()
    if row is None and size_clause:
        row = store.conn.execute(
            """
            SELECT e.event_id
            FROM edges e JOIN nodes n ON n.uuid=e.dst
            WHERE n.node_type='file' AND n.label=? AND e.relation='EVENT_WRITE'
            ORDER BY e.timestamp_ns DESC, e.id DESC LIMIT 1
            """,
            (specification.poi,),
        ).fetchone()
        selection_rule = "latest_write_size_fallback"
    if row is None:
        raise ValueError(f"No successful write found for DEPIMPACT POI: {specification.poi}")
    return {
        "event_ids": [row["event_id"]],
        "metadata": {
            "source_kind": "depimpact_property",
            "oracle_event_ranking": False,
            "poi": specification.poi,
            "high_rp": specification.high_rp,
            "detection_size": specification.detection_size,
            "selection_rule": selection_rule,
        },
    }


__all__ = [
    "DepImpactProperty",
    "SysdigStreamReader",
    "load_depimpact_property",
    "resolve_depimpact_poi",
    "stable_entity_id",
]
