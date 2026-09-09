"""Independent, ground-truth-separated diagnostics for causal-search coverage."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
import time
from typing import Iterable

from .alert_evaluation import time_respecting_groundtruth_context
from .causal import CausalSearchConfig, DirectionalEdgeCache, build_alert_context
from .evaluation import AttackAnnotations
from .frequency_snapshot import default_snapshot_path, load_snapshot
from .models import StoredEdge
from .nodoze import NODOZEFrequencyModel
from .store import ProvenanceStore


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def summarize_coverage_funnel(
    *, truth_ids: set[str], database_ids: set[str], causal_scope_ids: set[str],
    exhaustive_candidate_ids: set[str], current_candidate_ids: set[str],
    pruned_ids: set[str],
) -> dict[str, object]:
    database_truth = truth_ids & database_ids
    scope_truth = truth_ids & causal_scope_ids
    exhaustive_truth = truth_ids & exhaustive_candidate_ids
    current_truth = truth_ids & current_candidate_ids
    pruned_truth = truth_ids & pruned_ids
    return {
        "groundtruth_manifest": {"count": len(truth_ids)},
        "database_match": {
            "count": len(database_truth),
            "recall": _ratio(len(database_truth), len(truth_ids)),
        },
        "independent_causal_scope": {
            "truth_count": len(scope_truth),
            "recall": _ratio(len(scope_truth), len(truth_ids)),
        },
        "exhaustive_diagnostic_search": {
            "truth_count": len(exhaustive_truth),
            "recall": _ratio(len(exhaustive_truth), len(truth_ids)),
        },
        "current_candidate_search": {
            "truth_count": len(current_truth),
            "recall": _ratio(len(current_truth), len(truth_ids)),
        },
        "pruned_output": {
            "truth_count": len(pruned_truth),
            "recall": _ratio(len(pruned_truth), len(truth_ids)),
        },
        "losses": {
            "not_in_database": sorted(truth_ids - database_ids),
            "outside_poi_causal_scope": sorted(database_truth - scope_truth),
            "not_recovered_by_exhaustive_search": sorted(scope_truth - exhaustive_truth),
            "lost_by_current_search": sorted(exhaustive_truth - current_truth),
            "lost_by_pruning": sorted(current_truth - pruned_truth),
        },
    }


def _relation_recovery(
    event_ids: set[str], paths: list[tuple[str, ...]], edge_by_event: dict[str, StoredEdge]
) -> dict[str, object]:
    valid_paths = [path for path in paths if path and all(item in edge_by_event for item in path)]
    evidence = sum(set(path) <= event_ids for path in valid_paths)
    selected_edges = sorted(
        (edge_by_event[item] for item in event_ids if item in edge_by_event),
        key=lambda edge: (edge.timestamp_ns, edge.edge_id),
    )
    reachable = 0
    for path in valid_paths:
        first, last = edge_by_event[path[0]], edge_by_event[path[-1]]
        earliest = {first.src: -1}
        for edge in selected_edges:
            arrival = earliest.get(edge.src)
            if arrival is not None and edge.timestamp_ns >= arrival:
                previous = earliest.get(edge.dst)
                if previous is None or edge.timestamp_ns < previous:
                    earliest[edge.dst] = edge.timestamp_ns
        reachable += last.dst in earliest
    total = len(valid_paths)
    return {
        "predefined_relationships": total,
        "time_respecting_directed_reachable": reachable,
        "time_respecting_directed_reachability": _ratio(reachable, total),
        "groundtruth_connection_evidence_retained": evidence,
        "groundtruth_connection_evidence_retention": _ratio(evidence, total),
    }


def run_search_diagnostic(
    store: ProvenanceStore,
    annotations: AttackAnnotations,
    groundtruth: AttackAnnotations,
    current_report: dict[str, object],
    base_config: CausalSearchConfig,
) -> dict[str, object]:
    poi_edges = [
        edge for event_id in annotations.seed_event_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    if not poi_edges:
        raise ValueError("no POI events from the annotation manifest exist in the database")
    cutoff = min(edge.timestamp_ns for edge in poi_edges)
    snapshot = load_snapshot(default_snapshot_path(store.path, cutoff // 86_400_000_000_000))
    model = snapshot.nodoze

    truth_ids = set(groundtruth.attack_event_ids)
    truth_edges = [
        edge for event_id in truth_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    database_ids = {edge.event_id for edge in truth_edges}
    causal_scope_ids = time_respecting_groundtruth_context(poi_edges, truth_edges)

    total_timeout_seconds = 120.0
    exhaustive_config = replace(
        base_config,
        min_edge_suspicion=0.0,
        min_path_suspicion=0.0,
        branch_suspicion_quantile=0.0,
        min_frontier_relevance=0.0,
        path_relevance_decay=1.0,
        resource_max_edges=1_000_000,
        resource_max_states=250_000,
        resource_max_hops=None,
        resource_timeout_seconds=total_timeout_seconds / 2.0,
    )
    cache = DirectionalEdgeCache(store)
    exhaustive_edges: dict[int, StoredEdge] = {}
    reasons: Counter[str] = Counter()
    truncated_paths = 0
    groups = annotations.seed_event_groups or [{item} for item in annotations.seed_event_ids]
    diagnostic_started = time.perf_counter()
    completed_groups = 0
    for group in groups:
        remaining = total_timeout_seconds - (time.perf_counter() - diagnostic_started)
        if remaining <= 0:
            reasons["global_timeout_resource_limit"] += len(groups) - completed_groups
            truncated_paths += len(groups) - completed_groups
            break
        # build_alert_context performs one backward and one forward expansion;
        # split the remaining global allowance so one group cannot multiply it.
        group_config = replace(
            exhaustive_config, resource_timeout_seconds=max(0.01, remaining / 2.0)
        )
        context = build_alert_context(
            store, group, model, config=group_config, edge_cache=cache
        )
        completed_groups += 1
        exhaustive_edges.update({edge.edge_id: edge for edge in context.graph.edges})
        reasons.update(context.termination_reasons)
        truncated_paths += context.truncated_path_count
    exhaustive_ids = {edge.event_id for edge in exhaustive_edges.values()}
    current_ids = set(current_report.get("candidate_event_ids", []))
    edge_by_event = {edge.event_id: edge for edge in truth_edges}
    edge_by_event.update({edge.event_id: edge for edge in exhaustive_edges.values()})

    resource_reasons = {
        key: value for key, value in reasons.items()
        if "resource_limit" in key or key == "timeout_resource_limit"
    }
    pruning_rows = []
    for row in current_report.get("results", []):
        kept_ids = set(row.get("kept_event_ids", []))
        funnel = summarize_coverage_funnel(
            truth_ids=truth_ids,
            database_ids=database_ids,
            causal_scope_ids=causal_scope_ids,
            exhaustive_candidate_ids=exhaustive_ids,
            current_candidate_ids=current_ids,
            pruned_ids=kept_ids,
        )
        pruning_rows.append({
            "requested_keep_ratio": row.get("requested_keep_ratio"),
            "actual_keep_ratio": row.get("actual_keep_ratio"),
            "pruned_output": funnel["pruned_output"],
            "key_relation_recovery": _relation_recovery(
                kept_ids, groundtruth.attack_paths, edge_by_event
            ),
            "lost_by_pruning_event_ids": funnel["losses"]["lost_by_pruning"],
        })

    base_funnel = summarize_coverage_funnel(
        truth_ids=truth_ids,
        database_ids=database_ids,
        causal_scope_ids=causal_scope_ids,
        exhaustive_candidate_ids=exhaustive_ids,
        current_candidate_ids=current_ids,
        pruned_ids=set(),
    )
    base_funnel.pop("pruned_output")
    base_funnel["losses"].pop("lost_by_pruning")
    return {
        "diagnostic_mode": "heuristic_early_stopping_disabled",
        "online_algorithm_uses_groundtruth": False,
        "groundtruth_use": "offline coverage accounting and independent scope check only",
        "diagnostic_search_config": asdict(exhaustive_config),
        "resource_protection": {
            "incomplete": bool(resource_reasons or truncated_paths),
            "global_timeout_seconds": total_timeout_seconds,
            "completed_poi_groups": completed_groups,
            "total_poi_groups": len(groups),
            "truncated_path_count": truncated_paths,
            "triggered_reasons": resource_reasons,
        },
        "database_queries": cache.db_queries,
        "cache_hits": cache.cache_hits,
        "diagnostic_candidate_events": len(exhaustive_ids),
        "coverage_funnel_before_pruning": base_funnel,
        "key_relation_recovery_before_pruning": {
            "independent_causal_scope": _relation_recovery(
                causal_scope_ids, groundtruth.attack_paths, edge_by_event
            ),
            "exhaustive_candidate": _relation_recovery(
                exhaustive_ids, groundtruth.attack_paths, edge_by_event
            ),
            "current_candidate": _relation_recovery(
                current_ids, groundtruth.attack_paths, edge_by_event
            ),
        },
        "pruning_rows": pruning_rows,
    }


__all__ = ["run_search_diagnostic", "summarize_coverage_funnel"]
