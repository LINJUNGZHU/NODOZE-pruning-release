"""Offline completeness of fixed, observed positive-event subgraphs.

Events, rather than entities or enumerated paths, are the graph vertices. An
event can precede another when its causal destination equals the other's causal
source, both exact timestamps are positive and strictly increasing, and known
hosts agree. EVENT_EXECUTE follows the existing source contract: its stored
endpoints are reversed only for causality. Missing hosts permit an explicitly
counted inferred dependency; missing times provide no causal evidence.

Weak components partition the observed events. Components with at least two
events are reference subgraphs, while isolated events have their own denominator.
None of these components is certified as an independent, complete real attack.
Native references exclude LINEAGE events; augmented references include them.

Completeness requires *every* event in a component. Root-to-sink reachability is
a separate, weaker metric with a fixed denominator of originally reachable
terminal pairs. Reachability after deletion uses the FULL induced event DAG.
The transitive reduction defines fork/join neighborhoods only, avoiding inflated
branch counts without deleting dependencies needed after an intermediate loss.

Construction indexes causal sources and materializes all admissible dependencies.
Graph storage is O(N + E); reachability uses at most O(N squared) bits and the
explicit terminal-pair list can also be quadratic. Bitsets avoid enumerating all
paths. No events, components, dependencies, or terminal pairs are silently capped.
This operates on fixed offline positive references, not the full candidate graph.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from hashlib import sha256
from numbers import Integral
import json
import re
from typing import Any


SCHEMA_VERSION = "observed-reference-subgraphs-v1"
SCOPE = "fixed_observed_positive_subgraphs_not_complete_attacks"
_SUMMARY_COUNTS = (
    "reference_subgraph_count", "singleton_event_count", "reference_events",
    "reference_dependencies", "terminal_pairs", "fork_count", "join_count",
    "input_events", "excluded_synthetic_events", "synthetic_events",
    "inferred_host_dependencies", "unverifiable_time_events",
)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string identity")
    return value.strip().upper()


def _timestamp(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ValueError("timestamp_ns must be an exact nonnegative int64 integer")
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9]+", value.strip()):
            raise ValueError("timestamp_ns must be an exact nonnegative int64 integer")
        value = int(value.strip())
    elif isinstance(value, Integral):
        value = int(value)
    else:
        raise ValueError("timestamp_ns must be an exact nonnegative int64 integer")
    if not 0 <= value < 2**63:
        raise ValueError("timestamp_ns must be an exact nonnegative int64 integer")
    return value


def _canonical_event(row: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        raise ValueError("reference events must be mappings")
    identity = _identifier(row.get("event_id"), "event_id")
    src = _identifier(row.get("src"), "src")
    dst = _identifier(row.get("dst"), "dst")
    relation = _identifier(row.get("relation"), "relation")
    host = row.get("host")
    if host is None:
        host = ""
    if not isinstance(host, str):
        raise ValueError("host must be a string or None")
    host = host.strip().upper()
    causal_src, causal_dst = (dst, src) if relation == "EVENT_EXECUTE" else (src, dst)
    return {
        "event_id": identity, "src": src, "dst": dst, "relation": relation,
        "timestamp_ns": _timestamp(row.get("timestamp_ns")), "host": host,
        "causal_src": causal_src, "causal_dst": causal_dst,
        "synthetic": "LINEAGE" in identity or "LINEAGE" in relation,
    }


def _reachability(adjacency: list[list[int]], present: set[int] | None = None) -> list[int]:
    """Bitset descendants, with vertex indices already in topological order."""
    reach = [0] * len(adjacency)
    for source in range(len(adjacency) - 1, -1, -1):
        if present is not None and source not in present:
            continue
        for target in adjacency[source]:
            if present is None or target in present:
                reach[source] |= (1 << target) | reach[target]
    return reach


def _cover_edges(adjacency: list[list[int]], reach: list[int]) -> list[list[int]]:
    cover = [[] for _ in adjacency]
    for source, targets in enumerate(adjacency):
        covered = 0
        for target in targets:  # topological order makes redundant edges detectable
            if not covered & (1 << target):
                cover[source].append(target)
                covered |= (1 << target) | reach[target]
    return cover


def derive_reference_subgraphs(
    rows: Iterable[Mapping[str, Any]], *, include_synthetic: bool = False,
) -> dict[str, Any]:
    """Derive a deterministic private model from fixed observed positive rows.

    Only identity, endpoints, relation, host and timestamp fields are consumed.
    Unknown (None/missing/zero) timestamps remain required isolated events.
    Malformed timestamps and duplicate canonical event identities are rejected.
    ``events`` and ``components`` contain identities and must remain local.
    """
    if not isinstance(include_synthetic, bool):
        raise ValueError("include_synthetic must be bool")
    events = []
    seen: set[str] = set()
    excluded = 0
    for row in rows:
        event = _canonical_event(row)
        if event["event_id"] in seen:
            raise ValueError("duplicate canonical event_id in reference events")
        seen.add(event["event_id"])
        if event["synthetic"] and not include_synthetic:
            excluded += 1
        else:
            events.append(event)
    events.sort(key=lambda row: (row["timestamp_ns"], row["event_id"]))
    identities = [event["event_id"] for event in events]
    sources: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event["timestamp_ns"] > 0:
            sources[event["causal_src"]].append(index)
    adjacency: list[list[int]] = [[] for _ in events]
    undirected: list[list[int]] = [[] for _ in events]
    incoming: list[list[int]] = [[] for _ in events]
    inferred_hosts = 0
    for source, event in enumerate(events):
        if event["timestamp_ns"] == 0:
            continue
        for target in sources.get(event["causal_dst"], ()):
            following = events[target]
            if event["timestamp_ns"] >= following["timestamp_ns"]:
                continue
            if event["host"] and following["host"] and event["host"] != following["host"]:
                continue
            adjacency[source].append(target)
            incoming[target].append(source)
            undirected[source].append(target)
            undirected[target].append(source)
            inferred_hosts += int(not event["host"] or not following["host"])
    reach = _reachability(adjacency)
    cover = _cover_edges(adjacency, reach)
    cover_incoming: list[list[int]] = [[] for _ in events]
    for source, targets in enumerate(cover):
        for target in targets:
            cover_incoming[target].append(source)
    components = []
    visited: set[int] = set()
    for start in range(len(events)):
        if start in visited:
            continue
        pending = [start]
        visited.add(start)
        members = []
        while pending:
            vertex = pending.pop()
            members.append(vertex)
            for neighbor in undirected[vertex]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)
        members.sort()
        member_ids = [identities[index] for index in members]
        roots = [index for index in members if not incoming[index]]
        sinks = [index for index in members if not adjacency[index]]
        canonical_members = json.dumps(sorted(member_ids), separators=(",", ":")).encode()
        components.append({
            "id": "subgraph-" + sha256(canonical_members).hexdigest(),
            "event_ids": member_ids,
            "dependencies": [[identities[a], identities[b]] for a in members for b in adjacency[a]],
            "cover_dependencies": [[identities[a], identities[b]] for a in members for b in cover[a]],
            "roots": [identities[index] for index in roots],
            "sinks": [identities[index] for index in sinks],
            "terminal_pairs": [[identities[a], identities[b]] for a in roots for b in sinks
                               if a != b and reach[a] & (1 << b)],
            "fork_event_ids": [identities[index] for index in members if len(cover[index]) > 1],
            "join_event_ids": [identities[index] for index in members if len(cover_incoming[index]) > 1],
        })
    components.sort(key=lambda item: tuple(sorted(item["event_ids"])))
    summary = {
        "reference_subgraph_count": sum(len(c["event_ids"]) > 1 for c in components),
        "singleton_event_count": sum(len(c["event_ids"]) == 1 for c in components),
        "reference_events": len(events),
        "reference_dependencies": sum(map(len, adjacency)),
        "terminal_pairs": sum(len(c["terminal_pairs"]) for c in components),
        "fork_count": sum(len(c["fork_event_ids"]) for c in components),
        "join_count": sum(len(c["join_event_ids"]) for c in components),
        "input_events": len(seen), "excluded_synthetic_events": excluded,
        "synthetic_events": sum(event["synthetic"] for event in events),
        "inferred_host_dependencies": inferred_hosts,
        "unverifiable_time_events": sum(event["timestamp_ns"] == 0 for event in events),
        "include_synthetic": include_synthetic,
        "independent_attack_count": None, "attack_stage_completeness": None, "scope": SCOPE,
    }
    return {"schema_version": SCHEMA_VERSION, "events": events,
            "components": components, "summary": summary}


def _stages(stages: Mapping[str, Iterable[str]], reference: set[str]) -> dict[str, set[str]]:
    if not isinstance(stages, Mapping) or not stages:
        raise ValueError("stages must be a nonempty ordered mapping")
    result = {}
    previous = None
    for name, values in stages.items():
        if not isinstance(name, str) or not name.strip() or name == "surviving":
            raise ValueError("stage names must be nonempty and cannot be 'surviving'")
        if values is None or isinstance(values, (str, bytes, Mapping)):
            raise ValueError("stage events must be an iterable of event identities")
        try:
            current = {_identifier(value, "stage event_id") for value in values} & reference
        except TypeError as error:
            raise ValueError("stage events must be an iterable of event identities") from error
        if previous is not None and not current <= previous:
            raise ValueError("reference stage event sets must be nested")
        result[name] = current
        previous = current
    return result


def _ratio(count: int, total: int) -> float | None:
    return count / total if total else None


def _component_stage(
    component: Mapping[str, Any], retained: set[str], reach: list[int], index: Mapping[str, int],
) -> dict[str, Any]:
    members = set(component["event_ids"])
    kept = sorted(members & retained)
    missing = sorted(members - retained)
    dependencies = component["dependencies"]
    pairs = component["terminal_pairs"]
    kept_dependencies = sum(a in retained and b in retained for a, b in dependencies)
    kept_pairs = sum(bool(reach[index[a]] & (1 << index[b])) for a, b in pairs)
    out_cover: dict[str, set[str]] = defaultdict(set)
    in_cover: dict[str, set[str]] = defaultdict(set)
    for source, target in component["cover_dependencies"]:
        out_cover[source].add(target)
        in_cover[target].add(source)
    forks = component["fork_event_ids"]
    joins = component["join_event_ids"]
    kept_forks = sum({center} | out_cover[center] <= retained for center in forks)
    kept_joins = sum({center} | in_cover[center] <= retained for center in joins)
    return {
        "status": "complete" if not missing else ("partial" if kept else "missing"),
        "complete": not missing, "missing_event_ids": missing, "retained_event_ids": kept,
        "reference_events": len(members), "retained_events": len(kept),
        "event_retention": _ratio(len(kept), len(members)),
        "reference_dependencies": len(dependencies), "retained_dependencies": kept_dependencies,
        "dependency_retention": _ratio(kept_dependencies, len(dependencies)),
        "terminal_pairs": len(pairs), "reachable_terminal_pairs": kept_pairs,
        "terminal_reachability": _ratio(kept_pairs, len(pairs)),
        "fork_count": len(forks), "complete_forks": kept_forks,
        "fork_retention": _ratio(kept_forks, len(forks)),
        "join_count": len(joins), "complete_joins": kept_joins,
        "join_retention": _ratio(kept_joins, len(joins)),
    }


def evaluate_subgraphs(
    model: Mapping[str, Any], stages: Mapping[str, Iterable[str]], *, detail: bool = False,
) -> dict[str, Any]:
    """Evaluate nested observed-event stages against an unchanged private model.

    Empty denominators yield None, never a perfect-retention assertion. Unrelated
    event identities are ignored before checking nesting. First-loss counts assign
    each multi-event component once; singletons have separate event counts.
    ``detail=False`` emits only fixed aggregate metadata and counts/rates. With
    ``detail=True``, component identities and missing-event lists are also emitted
    and the output must remain local. Pipeline stages are not attack lifecycle
    stages: attack-stage completeness and independent-attack counts remain None.
    """
    if not isinstance(detail, bool):
        raise ValueError("detail must be bool")
    if model.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported reference subgraph schema_version")
    events = model["events"]
    identities = [event["event_id"] for event in events]
    index = {identity: i for i, identity in enumerate(identities)}
    stage_sets = _stages(stages, set(identities))
    components = model["components"]
    summary = {key: model["summary"][key] for key in _SUMMARY_COUNTS}
    summary.update(include_synthetic=model["summary"]["include_synthetic"],
                   independent_attack_count=None, attack_stage_completeness=None, scope=SCOPE)
    adjacency: list[list[int]] = [[] for _ in events]
    dependencies = []
    terminal_pairs = []
    forks = []
    joins = []
    multi_sets = []
    singleton_ids: set[str] = set()
    for component in components:
        member_set = set(component["event_ids"])
        if len(member_set) > 1:
            multi_sets.append(member_set)
        else:
            singleton_ids.update(member_set)
        for source, target in component["dependencies"]:
            a, b = index[source], index[target]
            adjacency[a].append(b)
            dependencies.append((a, b))
        terminal_pairs.extend((index[a], index[b]) for a, b in component["terminal_pairs"])
        out_cover: dict[str, set[str]] = defaultdict(set)
        in_cover: dict[str, set[str]] = defaultdict(set)
        for source, target in component["cover_dependencies"]:
            out_cover[source].add(target)
            in_cover[target].add(source)
        forks.extend({center} | out_cover[center] for center in component["fork_event_ids"])
        joins.extend({center} | in_cover[center] for center in component["join_event_ids"])
    points = {}
    detail_reach: dict[str, list[int]] = {}
    first_loss = {name: 0 for name in stage_sets}
    previous_complete = set(range(len(multi_sets)))
    for name, retained in stage_sets.items():
        present = {index[identity] for identity in retained}
        reach = _reachability(adjacency, present)
        if detail:
            detail_reach[name] = reach
        complete = {i for i, members in enumerate(multi_sets) if members <= retained}
        kept_dependencies = sum(a in present and b in present for a, b in dependencies)
        kept_pairs = sum(bool(reach[a] & (1 << b)) for a, b in terminal_pairs)
        kept_forks = sum(neighbors <= retained for neighbors in forks)
        kept_joins = sum(neighbors <= retained for neighbors in joins)
        first_loss[name] = len(previous_complete - complete)
        previous_complete = complete
        points[name] = {
            "reference_subgraph_count": len(multi_sets), "complete_subgraphs": len(complete),
            "subgraph_retention": _ratio(len(complete), len(multi_sets)),
            "singleton_event_count": len(singleton_ids),
            "retained_singleton_events": len(singleton_ids & retained),
            "reference_events": len(identities), "retained_reference_events": len(retained),
            "event_retention": _ratio(len(retained), len(identities)),
            "reference_dependencies": len(dependencies), "retained_dependencies": kept_dependencies,
            "dependency_retention": _ratio(kept_dependencies, len(dependencies)),
            "terminal_pairs": len(terminal_pairs), "reachable_terminal_pairs": kept_pairs,
            "terminal_reachability": _ratio(kept_pairs, len(terminal_pairs)),
            "fork_count": len(forks), "complete_forks": kept_forks,
            "fork_retention": _ratio(kept_forks, len(forks)),
            "join_count": len(joins), "complete_joins": kept_joins,
            "join_retention": _ratio(kept_joins, len(joins)),
            "independent_attack_count": None, "attack_stage_completeness": None,
        }
    first_loss["surviving"] = len(previous_complete)
    result = {"summary": summary, "stages": points, "first_loss_counts": first_loss}
    if detail:
        details = []
        for component in components:
            members = set(component["event_ids"])
            component_stages = {}
            first_missing = None
            for name, retained in stage_sets.items():
                point = _component_stage(component, retained, detail_reach[name], index)
                if not point["complete"] and first_missing is None:
                    first_missing = name
                component_stages[name] = point
            # Reconstruct lists so private diagnostic consumers cannot mutate the model.
            item = {"id": component["id"], "is_singleton": len(members) == 1,
                    "first_loss_stage": first_missing, "stages": component_stages}
            for field in ("event_ids", "roots", "sinks", "fork_event_ids", "join_event_ids"):
                item[field] = list(component[field])
            for field in ("dependencies", "cover_dependencies", "terminal_pairs"):
                item[field] = [list(pair) for pair in component[field]]
            details.append(item)
        result["components"] = details
    return result
