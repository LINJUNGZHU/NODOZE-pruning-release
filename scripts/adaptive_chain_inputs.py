"""Read-only inputs for adaptive pruning; reference construction is offline only.

Historical rows are weighted semantic counts from completed UTC days. Their
``timestamp_ns`` is a conservative aggregate boundary, never an event timestamp.
Reference paths are automatically derived positive-subgraph witnesses, never
independently reviewed complete attack chains.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from tc_pruning.frequency_cache import CACHE_VERSION, DAY_NS


_SCOPE = "reference-positive-subgraph only; not complete attacks"


def _connect(database: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _canonical(value: Any) -> str:
    if value is None or not str(value).strip():
        raise ValueError("event and node identities must be nonempty")
    return str(value).strip().upper()


def _integer(value: Any, label: str) -> int:
    result = int(value)
    if isinstance(value, bool) or (not isinstance(value, str) and result != value):
        raise ValueError(f"{label} must be an exact integer")
    return result


def _plan(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[str]:
    return [str(row[3]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params)]


def _cache_metadata(conn: sqlite3.Connection) -> tuple[dict[str, Any], list[str]]:
    try:
        metadata = dict(conn.execute("SELECT key,value FROM frequency_cache_meta"))
        if int(metadata.get("version", -1)) != CACHE_VERSION:
            raise ValueError("incompatible cache version")
        if metadata.get("stale") != "0" or int(metadata.get("day_ns", -1)) != DAY_NS:
            raise ValueError("stale cache or incompatible day units")
        source_edges = int(metadata["source_edges"])
        expected_maximum = int(metadata["maximum_timestamp_ns"])
        if source_edges < 0:
            raise ValueError("invalid source edge count")
        # INDEXED BY prevents a missing timestamp index from silently causing a
        # 39-million-event scan. COUNT(*) is intentionally not repeated here.
        maximum_sql = "SELECT MAX(timestamp_ns) FROM edges INDEXED BY idx_edges_time"
        query_plan = _plan(conn, maximum_sql)
        maximum = conn.execute(maximum_sql).fetchone()
        source_has_events = maximum is not None and maximum[0] is not None
        actual_maximum = int(maximum[0]) if source_has_events else 0
        if actual_maximum != expected_maximum or bool(source_edges) != source_has_events:
            raise ValueError("cache source timestamp or empty-graph state differs")
        conn.execute("SELECT day,host,src_pattern,dst_pattern,relation,event_count FROM freq_event_daily LIMIT 0")
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "frequency cache is missing, stale, or unverifiable; run build-frequency-cache offline before this experiment"
        ) from exc
    return {
        "cache_version": CACHE_VERSION,
        "source_edges_from_cache_metadata": source_edges,
        "source_maximum_timestamp_ns": expected_maximum,
        "observed_source_maximum_timestamp_ns": actual_maximum,
        "freshness_validation": "version, day units, cache invalidation flag, and indexed source maximum timestamp",
        "source_edge_count_independently_scanned": False,
        "freshness_limitations": "row count and in-place edits bypassing cache invalidation are not independently audited",
    }, query_plan


def load_historical_rows(
    database: str | Path, cutoff_ns: int, hosts: Iterable[str],
    program_semantics: Iterable[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load host-scoped weighted history; exclude the entire current UTC day.

    An existing offline cache and its timestamp index are required. No fallback
    raw-event aggregation is allowed. Host identities must be explicit; unknown
    or empty host identities cannot silently pool several machines' behavior.
    When program_semantics is supplied, only exact source/destination matches
    are loaded. This includes the selected programs' direct interactions, but
    excludes unmatched programs and paths through unmatched peers. The bounded
    result is materialized as a list; unfiltered calls retain the legacy scope.
    """
    if isinstance(hosts, (str, bytes)):
        raise ValueError("hosts must be an iterable of explicit host identities")
    selected_hosts: set[str] = set()
    for host in hosts:
        if not isinstance(host, str) or not host.strip():
            raise ValueError("host identities must be nonempty strings")
        selected_hosts.add(host.strip())
    if not selected_hosts:
        raise ValueError("at least one explicit host is required")
    selected_programs: list[str] | None = None
    if program_semantics is not None:
        if isinstance(program_semantics, (str, bytes)):
            raise ValueError("program_semantics must be an iterable of explicit semantic keys")
        unique_programs: set[str] = set()
        for semantic in program_semantics:
            if not isinstance(semantic, str) or not semantic.strip():
                raise ValueError("program_semantics must contain nonempty strings")
            unique_programs.add(semantic.strip())
        if not unique_programs:
            raise ValueError("program_semantics must not be empty when supplied")
        selected_programs = sorted(unique_programs)
    cutoff = _integer(cutoff_ns, "cutoff_ns")
    cutoff_day = cutoff // DAY_NS
    aggregate_timestamp = cutoff_day * DAY_NS - 1
    ordered_hosts = sorted(selected_hosts)
    placeholders = ",".join("?" for _ in ordered_hosts)
    semantic_clause = ""
    if selected_programs is not None:
        program_placeholders = ",".join("?" for _ in selected_programs)
        semantic_clause = (
            f"AND (src_pattern IN ({program_placeholders}) "
            f"OR dst_pattern IN ({program_placeholders})) "
        )
    sql = (
        "SELECT host,src_pattern,dst_pattern,relation,SUM(event_count) AS count "
        "FROM freq_event_daily "
        f"WHERE day < ? AND host IN ({placeholders}) {semantic_clause}"
        "GROUP BY host,src_pattern,dst_pattern,relation "
        "ORDER BY host,src_pattern,dst_pattern,relation"
    )
    params = (cutoff_day, *ordered_hosts, *(selected_programs or []), *(selected_programs or []))
    with closing(_connect(database)) as conn:
        if len(params) > conn.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER):
            raise ValueError("too many host/program_semantics selectors for this SQLite parameter limit")
        metadata, freshness_plan = _cache_metadata(conn)
        query_plan = _plan(conn, sql, params)
        if not any("SEARCH freq_event_daily" in line and "day" in line for line in query_plan):
            raise RuntimeError("frequency cache requires a day index; rebuild with build-frequency-cache offline")
        rows = []
        for row in conn.execute(sql, params):
            count = int(row["count"])
            if count <= 0:
                raise RuntimeError("frequency cache contains nonpositive aggregate event counts")
            src, dst = str(row["src_pattern"]), str(row["dst_pattern"])
            rows.append({
                "host": str(row["host"]), "src_semantic": src, "dst_semantic": dst,
                "src_type": src.split(":", 1)[0] if ":" in src else "unknown",
                "dst_type": dst.split(":", 1)[0] if ":" in dst else "unknown",
                "relation": str(row["relation"]), "count": count, "event_count": count,
                "timestamp_ns": aggregate_timestamp,
            })
    provenance = {
        "source": "freq_event_daily", "database": str(Path(database).resolve()),
        "read_only": True, "hosts": ordered_hosts, "cutoff_ns": cutoff,
        "program_semantics": selected_programs,
        "history_scope": "explicit_hosts_and_program_semantics" if selected_programs is not None else "explicit_hosts_all_patterns",
        "semantic_filter_rule": "exact src_pattern OR dst_pattern match to one listed program semantic" if selected_programs is not None else "no program semantic filter",
        "history_scope_limitations": (
            "Only direct interactions of listed program semantics are included; unmatched programs and paths through unmatched peers are excluded."
            if selected_programs is not None else "All patterns from explicitly selected hosts are included; unspecified hosts are excluded."
        ),
        "cutoff_day_exclusive": cutoff_day, "complete_days_only": True,
        "temporal_scope": "complete UTC days only; excludes the entire current day, including events before cutoff",
        "timestamp_is_aggregate_boundary": True, "aggregate_timestamp_ns": aggregate_timestamp,
        "timestamp_semantics": "last completed UTC day end, not an actual event timestamp",
        "weight_semantics": "SUM(event_count), not number of distinct daily rows",
        "historical_pattern_count": len(rows),
        "historical_event_count": sum(row["count"] for row in rows),
        "query_plan": query_plan, "freshness_query_plan": freshness_plan, **metadata,
    }
    return rows, provenance


def load_source_events(database: str | Path, event_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Resolve reference IDs with indexed, case-aware lookups and node semantics."""
    wanted = sorted({_canonical(value) for value in event_ids})
    if not wanted:
        return []
    alternatives: set[str] = set(wanted)
    for event in wanted:
        stem, marker, suffix = event.partition("#")
        if marker:
            alternatives.add(stem + marker + suffix.lower())
    found: dict[str, dict[str, Any]] = {}
    with closing(_connect(database)) as conn:
        values = sorted(alternatives)
        # Stay below SQLite builds with a 999-variable limit.
        for start in range(0, len(values), 400):
            chunk = tuple(values[start:start + 400])
            placeholders = ",".join("?" for _ in chunk)
            sql = (
                "SELECT e.id AS edge_id,e.event_id,e.src,e.dst,e.relation,e.timestamp_ns,e.host,e.data_size,"
                "ns.node_type AS src_type,nd.node_type AS dst_type,"
                "ns.semantic_key AS src_semantic,nd.semantic_key AS dst_semantic "
                "FROM edges e LEFT JOIN nodes ns ON ns.uuid=e.src LEFT JOIN nodes nd ON nd.uuid=e.dst "
                f"WHERE e.event_id IN ({placeholders}) ORDER BY e.timestamp_ns,e.event_id"
            )
            plan = _plan(conn, sql, chunk)
            if not any("SEARCH e " in line and "event_id" in line for line in plan):
                raise RuntimeError("source events require an event_id index; refusing an unbounded raw graph scan")
            for row in conn.execute(sql, chunk):
                event = _canonical(row["event_id"])
                if event in found:
                    raise ValueError(f"ambiguous source event identity after canonicalization: {event}")
                result = dict(row)
                result["event_id"] = event
                for side in ("src", "dst"):
                    result[side] = _canonical(result[side])
                    result[f"{side}_type"] = result[f"{side}_type"] or "unknown"
                    result[f"{side}_semantic"] = result[f"{side}_semantic"] or result[side]
                found[event] = result
    return sorted(found.values(), key=lambda row: (row["timestamp_ns"], row["event_id"]))


def derive_reference_chains(
    source_positive_rows: Iterable[Mapping[str, Any]], source: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build a deterministic positive-subgraph path cover without online inputs.

    First select a longest strict-time prefix to each terminal event. Then add
    a longest prefix/suffix witness through every as-yet-uncovered event. This
    covers branches omitted at merges without enumerating exponentially many
    paths. Isolated events remain an explicit singleton list, not fake chains.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("reference source provenance must be nonempty")
    events: dict[str, dict[str, Any]] = {}
    for row in source_positive_rows:
        event = _canonical(row["event_id"])
        if event in events:
            raise ValueError(f"duplicate reference-positive event identity: {event}")
        events[event] = {
            "event_id": event, "src": _canonical(row["src"]), "dst": _canonical(row["dst"]),
            "relation": str(row["relation"]).upper(),
            "timestamp_ns": _integer(row["timestamp_ns"], "timestamp_ns"),
            "host": str(row.get("host") or ""),
        }
    ordered = sorted(events.values(), key=lambda row: (row["timestamp_ns"], row["event_id"]))
    count = len(ordered)
    endpoints = [(row["dst"], row["src"]) if row["relation"] == "EVENT_EXECUTE"
                 else (row["src"], row["dst"]) for row in ordered]
    predecessors: list[list[int]] = [[] for _ in ordered]
    successors: list[list[int]] = [[] for _ in ordered]
    for right in range(count):
        for left in range(right):
            if (ordered[left]["timestamp_ns"] < ordered[right]["timestamp_ns"]
                    and ordered[left]["host"] == ordered[right]["host"]
                    and endpoints[left][1] == endpoints[right][0]):
                predecessors[right].append(left)
                successors[left].append(right)
    prefixes: list[tuple[str, ...]] = []
    for index, row in enumerate(ordered):
        previous = min((prefixes[left] for left in predecessors[index]),
                       key=lambda path: (-len(path), path), default=())
        prefixes.append(previous + (row["event_id"],))
    suffixes: list[tuple[str, ...]] = [() for _ in ordered]
    for index in reversed(range(count)):
        following = min((suffixes[right] for right in successors[index]),
                        key=lambda path: (-len(path), path), default=())
        suffixes[index] = (ordered[index]["event_id"],) + following
    selected: set[tuple[str, ...]] = {prefixes[index] for index in range(count)
                                     if not successors[index] and len(prefixes[index]) >= 2}
    covered = {event for path in selected for event in path}
    for index, row in enumerate(ordered):
        if row["event_id"] in covered:
            continue
        path = prefixes[index] + suffixes[index][1:]
        if len(path) >= 2:
            selected.add(path)
            covered.update(path)
    chains = []
    for path in sorted(selected):
        digest = hashlib.sha256(json.dumps([source, path], separators=(",", ":")).encode()).hexdigest()
        chains.append({
            "id": "derived-positive-path-" + digest[:20], "event_ids": list(path),
            "scope_complete": False,
            "provenance": {"kind": "derived_reference", "source": source, "scope": _SCOPE,
                           "method": "terminal_longest_prefix_with_uncovered_event_witness_completion"},
        })
    lengths = [len(chain["event_ids"]) for chain in chains]
    singletons = sorted(set(events) - covered)
    source_digest = hashlib.sha256(json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    diagnostics = {
        "source": source, "scope": _SCOPE, "source_positive_event_count": count,
        "source_positive_graph_sha256": source_digest,
        "reference_chain_count": len(chains), "covered_event_count": len(covered),
        "singletons": singletons, "singleton_count": len(singletons),
        "accounted_event_count": len(covered) + len(singletons),
        "length_min": min(lengths) if lengths else None, "length_max": max(lengths) if lengths else None,
        "terminal_event_count": sum(not targets for targets in successors),
        "exhaustive_path_enumeration": False,
        "path_semantics": "deterministic strict-time directed path cover of source-positive events, not all possible paths",
        "ground_truth_used_for_selection": False, "uses_online_scores_or_candidates": False,
        "independently_reviewed_complete_attacks": False,
    }
    return chains, diagnostics


__all__ = ["load_historical_rows", "load_source_events", "derive_reference_chains"]
