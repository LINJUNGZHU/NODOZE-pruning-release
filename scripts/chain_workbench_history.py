"""Read-only, bounded history adapters for the window study.

``cutoff_ns`` must precede every allowed candidate event, not a selected POI.
Without expansion it is the original window start; with backward expansion it
is the original start minus the registered maximum extension, shared by tracks.
Existing completed-day caches retain their original exact host/program scope.
Without a cache, the fallback reads at most ``max_recent_events + 1`` raw events
from the preceding 24 hours, keeping the latest ``max_recent_events`` BEFORE
host/program filtering. This global cap guarantees bounded indexed reads; a
busy unrelated program may therefore reduce usable support. The extra event
only detects truncation and never trains the model. No cache is built here.

Node metadata are the current database snapshot; their temporal validity is
not independently certified. Strictly historical events are not necessarily
benign events. Both limitations accompany every returned history provenance.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import closing
import math
from numbers import Integral, Real
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any

from scripts.adaptive_chain_inputs import _cache_metadata, _connect, _plan, load_historical_rows
from tc_pruning.frequency import FrequencyModel
from tc_pruning.frequency_cache import DAY_NS


MAX_RECENT_EVENTS = 250_000
_LIMIT_SCOPE = "global_pre_window_events_before_host_and_program_filter"
_LIMITATIONS = {
    "history_certified_benign": False,
    "node_metadata_time_safety_verified": False,
    "history_safety_limitations": (
        "Event times precede the registered candidate horizon, but history is not certified benign; "
        "node semantic metadata come from the current database snapshot and may contain later enrichment."
    ),
}


def _integer(value: Any, name: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return int(value)


def _scope(rows: Iterable[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    hosts: set[str] = set()
    programs: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("candidate rows must be mappings")
        host = row.get("host")
        if not isinstance(host, str) or not host.strip():
            raise ValueError("history requires explicit nonempty candidate host identities")
        hosts.add(host.strip())
        for side in ("src", "dst"):
            if str(row.get(f"{side}_type", "")).lower() == "process":
                semantic = row.get(f"{side}_semantic")
                if isinstance(semantic, str) and semantic.strip():
                    programs.add(semantic.strip())
    return sorted(hosts), sorted(programs)


def _cache_present(conn: sqlite3.Connection) -> bool:
    # A partial/malformed cache is invalid, not an absent cache eligible for
    # silent fallback. Schema-only lookup never scans a raw event table.
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND (name='frequency_cache_meta' OR name GLOB 'freq_*') LIMIT 1"
    ).fetchone() is not None


def prepare_history(
    database: str | Path, rows: Iterable[Mapping[str, Any]], cutoff_ns: int, *,
    history_database: str | Path | None = None, max_recent_events: int = MAX_RECENT_EVENTS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return weighted semantic history and explicit source/support limitations.

    An explicit ``history_database`` replaces the source database for history.
    Missing caches allow recent raw history; stale/incomplete caches fail.
    Candidate rows contribute only exact host and process-semantic selectors;
    labels, scores, POI status, and candidate events never train this adapter.
    """
    cutoff = _integer(cutoff_ns, "cutoff_ns")
    limit = _integer(max_recent_events, "max_recent_events", minimum=1, maximum=MAX_RECENT_EVENTS)
    hosts, programs = _scope(rows)
    selected_database = Path(history_database if history_database is not None else database).resolve()
    base = {
        "database": str(selected_database), "read_only": True, "cutoff_ns": cutoff,
        "cutoff_semantics": "registered_earliest_allowed_candidate_start_exclusive",
        "history_database_explicit": history_database is not None,
        "hosts": hosts, "program_semantics": programs,
        "history_scope": "explicit_hosts_and_program_semantics", **_LIMITATIONS,
    }
    # Validate even a cache with no usable selectors: otherwise a stale source
    # could be silently accepted merely because its candidate semantics differ.
    with closing(_connect(selected_database)) as conn:
        cached = _cache_present(conn)
        if cached:
            _cache_metadata(conn)
        if not hosts or not programs:
            return [], {
                **base, "mode": "cold_start", "cold_start": True,
                "cold_start_reason": "no_explicit_host_or_process_semantics",
                "historical_pattern_count": 0, "historical_event_count": 0,
                "cache_present": cached,
            }
        if not cached:
            return _recent_history(conn, cutoff, limit, hosts, programs, base)
    history, provenance = load_historical_rows(selected_database, cutoff, hosts, programs)
    return history, {
        **provenance, **base, "mode": "completed_day_cache", "cache_present": True,
        "cold_start": not history, "history_truncated": False,
        "max_recent_events": limit,
    }


def _recent_history(
    conn: sqlite3.Connection, cutoff: int, limit: int, hosts: list[str],
    programs: list[str], base: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lower = max(0, cutoff - DAY_NS)
    sql = (
        "SELECT id,src,dst,relation,timestamp_ns,host FROM edges INDEXED BY idx_edges_time "
        "WHERE timestamp_ns >= ? AND timestamp_ns < ? "
        "ORDER BY timestamp_ns DESC,id DESC LIMIT ?"
    )
    params = (lower, cutoff, limit + 1)
    try:
        plan = _plan(conn, sql, params)
        if not any("SEARCH edges USING INDEX idx_edges_time" in line for line in plan):
            raise RuntimeError("recent history requires an indexed timestamp range; refusing a raw scan")
        if any("TEMP B-TREE" in line for line in plan):
            raise RuntimeError("recent history must not sort an unbounded raw timestamp range")
        fetched = list(conn.execute(sql, params))
    except sqlite3.Error as exc:
        raise RuntimeError("recent history requires the existing idx_edges_time timestamp index and source schema") from exc
    truncated = len(fetched) > limit
    considered = fetched[:limit]
    selected_hosts, selected_programs = set(hosts), set(programs)
    scoped = [row for row in considered if row["host"] in selected_hosts]
    wanted = sorted({row[side] for row in scoped for side in ("src", "dst")})
    nodes: dict[str, tuple[str, str]] = {}
    hydration_plan: list[str] = []
    for start in range(0, len(wanted), 400):
        chunk = tuple(wanted[start:start + 400])
        placeholders = ",".join("?" for _ in chunk)
        node_sql = f"SELECT uuid,node_type,semantic_key FROM nodes WHERE uuid IN ({placeholders})"
        if not hydration_plan:
            hydration_plan = _plan(conn, node_sql, chunk)
            if not any("SEARCH nodes" in line for line in hydration_plan):
                raise RuntimeError("node hydration requires an identity index; refusing a raw scan")
        for node in conn.execute(node_sql, chunk):
            nodes[node["uuid"]] = (str(node["node_type"]), str(node["semantic_key"]))
    aggregates: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    missing_nodes = 0
    excluded_programs = 0
    for row in scoped:
        src, dst = nodes.get(row["src"]), nodes.get(row["dst"])
        if src is None or dst is None:
            missing_nodes += 1
            continue
        if src[1] not in selected_programs and dst[1] not in selected_programs:
            excluded_programs += 1
            continue
        key = (str(row["host"]), src[0], dst[0], src[1], dst[1], str(row["relation"]))
        aggregate = aggregates.get(key)
        if aggregate is None:
            aggregate = {"host": key[0], "src_type": key[1], "dst_type": key[2],
                         "src_semantic": key[3], "dst_semantic": key[4], "relation": key[5],
                         "timestamp_ns": int(row["timestamp_ns"]), "count": 0, "event_count": 0}
            aggregates[key] = aggregate
        aggregate["count"] += 1
        aggregate["event_count"] += 1
        aggregate["timestamp_ns"] = max(aggregate["timestamp_ns"], int(row["timestamp_ns"]))
    history = [aggregates[key] for key in sorted(aggregates)]
    return history, {
        **base, "mode": "recent_raw_history", "source": "edges_indexed_recent_past",
        "cache_present": False, "cache_absence_action": "bounded_recent_raw_fallback",
        "cold_start": not history, "complete_days_only": False,
        "history_window_start_ns": lower, "history_window_end_exclusive_ns": cutoff,
        "history_window_seconds": 86_400, "max_recent_events": limit,
        "history_truncated": truncated, "history_limit_scope": _LIMIT_SCOPE,
        "history_scope_limitations": (
            "Latest bounded events across all hosts are selected before exact host/program filtering; "
            "unrelated busy programs can displace matching history. No support beyond the preceding 24 hours is used."
        ),
        "raw_rows_fetched": len(fetched), "raw_rows_considered": len(considered),
        "raw_rows_matching_hosts": len(scoped), "rows_excluded_for_missing_nodes": missing_nodes,
        "rows_excluded_for_program_semantics": excluded_programs,
        "historical_pattern_count": len(history),
        "historical_event_count": sum(row["count"] for row in history),
        "timestamp_is_aggregate_boundary": False,
        "timestamp_semantics": "maximum observed event time in each weighted semantic pattern",
        "query_plan": plan, "node_hydration_query_plan": hydration_plan,
    }


def complete_missing_rarity(
    database: str | Path, rows: Iterable[Mapping[str, Any]], cutoff_ns: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Copy rows and fill absent ``components.rarity`` using the legacy model.

    Existing rarity values are preserved exactly. Missing values require the
    original database's valid completed-day frequency cache. This function does
    not substitute contextual surprise or build a frequency cache. All model
    counts come from the three small legacy aggregate tables; constructing a
    ``ProvenanceStore`` (which counts raw edges on open) is deliberately avoided.
    """
    cutoff = _integer(cutoff_ns, "cutoff_ns")
    copied: list[dict[str, Any]] = []
    missing: list[tuple[int, tuple[str, str, str]]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("candidate rows must be mappings")
        components = row.get("components", {})
        if not isinstance(components, Mapping):
            raise ValueError("components must be a mapping")
        result = dict(row)
        result["components"] = dict(components)
        if "rarity" in components:
            value = components["rarity"]
            if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("existing rarity must be a finite number in [0, 1]")
        else:
            pattern = tuple(row.get(key) for key in ("src_type", "relation", "dst_type"))
            if any(not isinstance(value, str) or not value.strip() for value in pattern):
                raise ValueError("missing rarity requires explicit src_type, relation, and dst_type")
            missing.append((len(copied), pattern))
        copied.append(result)
    provenance: dict[str, Any] = {
        "model": "tc_pruning.frequency.FrequencyModel", "read_only": True,
        "database": str(Path(database).resolve()), "cutoff_ns": cutoff,
        "cutoff_day_exclusive": cutoff // DAY_NS, "complete_days_only": True,
        "filled_rows": len(missing), "preserved_rows": len(copied) - len(missing),
        "existing_rarity_unchanged": True, "raw_event_count_scan": False,
    }
    if not missing:
        return copied, {**provenance, "mode": "existing_legacy_rarity"}
    with closing(_connect(database)) as conn:
        metadata, plan = _cache_metadata(conn)
        model = FrequencyModel.from_cache(SimpleNamespace(conn=conn), before_timestamp_ns=cutoff)
    scores: dict[tuple[str, str, str], float] = {}
    for index, pattern in missing:
        if pattern not in scores:
            scores[pattern] = model.edge_rarity(SimpleNamespace(src_type=pattern[0], relation=pattern[1], dst_type=pattern[2]))
        copied[index]["components"]["rarity"] = scores[pattern]
    return copied, {
        **provenance, "mode": "completed_day_legacy_frequency_cache",
        "freshness_query_plan": plan, "frequency_cache": metadata,
        "weights": {"node": model.node_weight, "relation": model.relation_weight, "pattern": model.pattern_weight},
    }


__all__ = ["prepare_history", "complete_missing_rarity"]
