from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from time import perf_counter
import json

from .depimpact import merge_parallel_edges
from .models import Neighborhood, StoredEdge
from .store import ProvenanceStore


PROTOCOL_VERSION = "tc-pruning-evaluation-v2.0"


def _ratio(numerator: int, denominator: int, *, reason: str = "zero_denominator") -> dict:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        **({"reason": reason} if not denominator else {}),
    }


def _path_ratio(numerator: int, diagnostics: list[dict], *, conditional_denominator: int | None = None) -> dict:
    invalid = sum(not item["reference_valid"] for item in diagnostics)
    denominator = len(diagnostics) if conditional_denominator is None else conditional_denominator
    if invalid:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "value": None,
            "reason": "invalid_derived_reference_paths",
            "invalid_reference_count": invalid,
        }
    return _ratio(
        numerator, denominator,
        reason=("candidate_contains_no_complete_derived_path" if conditional_denominator is not None else "zero_denominator"),
    )


def _unique_edges(edges: Iterable[StoredEdge]) -> list[StoredEdge]:
    return list({edge.event_id: edge for edge in edges}.values())


def _path_diagnostic(
    path_id: str,
    event_ids: list[str],
    edge_by_event: dict[str, StoredEdge],
    candidate_ids: set[str],
    retained_ids: set[str],
    *,
    source: str,
    verification_status: str,
) -> dict:
    known = [edge_by_event.get(event_id) for event_id in event_ids]
    missing_database = [event_id for event_id, edge in zip(event_ids, known) if edge is None]
    continuity_errors = []
    temporal_errors = []
    for index, (left, right) in enumerate(zip(known, known[1:])):
        if left is None or right is None:
            continue
        if left.dst != right.src:
            continuity_errors.append({
                "after_event_id": left.event_id,
                "before_event_id": right.event_id,
                "left_dst": left.dst,
                "right_src": right.src,
            })
        if left.timestamp_ns > right.timestamp_ns:
            temporal_errors.append({
                "earlier_position": index,
                "left_event_id": left.event_id,
                "right_event_id": right.event_id,
            })
    reference_valid = not missing_database and not continuity_errors and not temporal_errors
    missing_candidate = sorted(set(event_ids) - candidate_ids)
    missing_retained = sorted(set(event_ids) - retained_ids)
    return {
        "path_id": path_id,
        "source": source,
        "verification_status": verification_status,
        "start_node_uuid": known[0].src if known and known[0] else None,
        "end_node_uuid": known[-1].dst if known and known[-1] else None,
        "required_event_ids": event_ids,
        "constraints": {
            "exact_event_sequence": True,
            "nondecreasing_timestamp": True,
            "directed_endpoint_continuity": True,
            "alternative_reachability_allowed": False,
        },
        "reference_valid": reference_valid,
        "candidate_satisfied": reference_valid and not missing_candidate,
        "retained_satisfied": reference_valid and not missing_retained,
        "missing_database_event_ids": missing_database,
        "missing_candidate_event_ids": missing_candidate,
        "missing_retained_event_ids": missing_retained,
        "continuity_errors": continuity_errors,
        "temporal_order_errors": temporal_errors,
        "failure_reason": (
            "invalid_reference_path" if not reference_valid else
            "candidate_missing_required_events" if missing_candidate else
            "retained_missing_required_events" if missing_retained else None
        ),
    }


def evaluate_protocol_v2(
    *,
    candidate_graph: Neighborhood,
    retained_edges: Iterable[StoredEdge],
    annotations: dict,
    requested_retention: float,
    merge_threshold_seconds: float,
    incomplete: bool = False,
    truncation_reason: str | None = None,
) -> dict:
    candidate = _unique_edges(candidate_graph.edges)
    retained = _unique_edges(retained_edges)
    candidate_ids = {edge.event_id for edge in candidate}
    retained_ids = {edge.event_id for edge in retained} & candidate_ids
    candidate_nodes = {endpoint for edge in candidate for endpoint in (edge.src, edge.dst)}
    retained_nodes = {
        endpoint for edge in retained if edge.event_id in retained_ids
        for endpoint in (edge.src, edge.dst)
    }
    truth_nodes = set(annotations.get("attack_node_uuids", []))
    truth_events = set(annotations.get("attack_event_ids", []))
    edge_by_event = {edge.event_id: edge for edge in candidate}
    for edge in retained:
        edge_by_event.setdefault(edge.event_id, edge)

    merge = merge_parallel_edges(
        Neighborhood(candidate_graph.nodes, candidate),
        threshold_seconds=merge_threshold_seconds,
    )
    edge_by_id = {edge.edge_id: edge for edge in candidate}
    event_groups = []
    retained_group_count = 0
    for group_index, representative in enumerate(merge.edges, start=1):
        members = [edge_by_id[item].event_id for item in merge.groups[representative.edge_id]]
        kept = sorted(set(members) & retained_ids)
        status = "fully_retained" if len(kept) == len(members) else (
            "partially_retained" if kept else "removed"
        )
        retained_group_count += status == "fully_retained"
        event_groups.append({
            "group_id": f"event-group-{group_index}",
            "representative_event_id": representative.event_id,
            "member_event_ids": members,
            "retained_member_event_ids": kept,
            "status": status,
        })

    derived_paths = [list(path) for path in annotations.get("attack_paths", [])]
    verified_paths = [list(path) for path in annotations.get("verified_attack_paths", [])]
    metadata = annotations.get("metadata", {})
    path_diagnostics = [
        _path_diagnostic(
            f"derived-path-{index}", path, edge_by_event, candidate_ids, retained_ids,
            source=metadata.get("groundtruth_source", "annotation_manifest"),
            verification_status="automatically_derived_not_human_verified",
        )
        for index, path in enumerate(derived_paths, start=1)
    ]
    verified_diagnostics = [
        _path_diagnostic(
            f"verified-path-{index}", path, edge_by_event, candidate_ids, retained_ids,
            source=metadata.get("verified_path_source", "annotation_manifest"),
            verification_status="human_verified",
        )
        for index, path in enumerate(verified_paths, start=1)
    ]
    candidate_truth_events = candidate_ids & truth_events
    retained_truth_events = retained_ids & truth_events
    candidate_derived_paths = sum(item["candidate_satisfied"] for item in path_diagnostics)
    retained_derived_paths = sum(item["retained_satisfied"] for item in path_diagnostics)
    retained_verified_paths = sum(item["retained_satisfied"] for item in verified_diagnostics)
    event_count = len(candidate_ids)
    retained_event_count = len(retained_ids)
    node_count = len(candidate_nodes)
    retained_node_count = len(retained_nodes)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "graph_size": {
            "candidate_node_count": node_count,
            "retained_node_count": retained_node_count,
            "candidate_event_count": event_count,
            "retained_event_count": retained_event_count,
            "candidate_event_group_count": len(event_groups),
            "retained_event_group_count": retained_group_count,
            "partially_retained_event_group_count": sum(
                item["status"] == "partially_retained" for item in event_groups
            ),
            "requested_retention": requested_retention,
            "actual_event_retention": retained_event_count / event_count if event_count else None,
            "node_compression": 1 - retained_node_count / node_count if node_count else None,
            "event_compression": 1 - retained_event_count / event_count if event_count else None,
            "isolated_node_policy": "excluded; nodes are stable UUID endpoints of retained events",
            "event_identity_policy": "deduplicate_by_event_id",
            "incomplete": incomplete,
            "truncation_reason": truncation_reason,
        },
        "metrics": {
            "candidate_node_recall": _ratio(len(candidate_nodes & truth_nodes), len(truth_nodes)),
            "final_node_recall": _ratio(len(retained_nodes & truth_nodes), len(truth_nodes)),
            "candidate_derived_event_recall": _ratio(len(candidate_truth_events), len(truth_events)),
            "final_derived_event_recall": _ratio(len(retained_truth_events), len(truth_events)),
            "conditional_derived_event_retention": _ratio(
                len(retained_truth_events), len(candidate_truth_events),
                reason="candidate_contains_no_derived_events",
            ),
            "candidate_derived_reference_path_coverage": _path_ratio(
                candidate_derived_paths, path_diagnostics
            ),
            "derived_reference_path_retention": _path_ratio(
                retained_derived_paths, path_diagnostics
            ),
            "conditional_derived_reference_path_retention": _path_ratio(
                retained_derived_paths, path_diagnostics,
                conditional_denominator=candidate_derived_paths,
            ),
            "verified_attack_path_retention": _ratio(
                retained_verified_paths, len(verified_paths),
                reason="no_human_verified_paths_supplied",
            ),
        },
        "unmatched_annotations": {
            "node_ids": sorted(truth_nodes - candidate_nodes),
            "event_ids": sorted(truth_events - set(edge_by_event)),
        },
        "path_diagnostics": path_diagnostics + verified_diagnostics,
        "event_groups": event_groups,
    }


def build_protocol_v2_report(
    store: ProvenanceStore,
    result: dict,
    annotations: dict,
    *,
    result_path: str,
    annotation_path: str,
) -> dict:
    started = perf_counter()
    candidate_edges = [
        edge for event_id in result.get("candidate_event_ids", [])
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    candidate_graph = store.neighborhood_from_edges(candidate_edges)
    all_truth_event_ids = set(annotations.get("attack_event_ids", []))
    database_truth_edges = {
        event_id: edge for event_id in all_truth_event_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    }
    all_truth_nodes = set(annotations.get("attack_node_uuids", []))
    database_truth_nodes = {
        node_id for node_id in all_truth_nodes if store.get_node(node_id) is not None
    }
    merge_threshold = float(result.get("depimpact", {}).get("merge_threshold_seconds", 10.0))
    rows = []
    audits = []
    for raw in result.get("results", []):
        kept = [
            edge for event_id in raw.get("kept_event_ids", [])
            if (edge := store.get_edge_by_event_id(event_id)) is not None
        ]
        audit = evaluate_protocol_v2(
            candidate_graph=candidate_graph,
            retained_edges=kept,
            annotations=annotations,
            requested_retention=float(raw["requested_keep_ratio"]),
            merge_threshold_seconds=merge_threshold,
            incomplete=bool(result.get("incomplete", False)),
            truncation_reason=(result.get("candidate_construction") or {}).get("truncation_reason"),
        )
        audit["budget"] = {
            "budget_feasible": bool(raw.get("budget_feasible", True)),
            "budget_overflow_events": int(raw.get("budget_overflow_edges", 0)),
            "hard_protection_policy": result.get("connectivity_policy"),
            "protected_alert_events": len(result.get("matched_seed_event_ids", [])),
        }
        audits.append(audit)
        g, m = audit["graph_size"], audit["metrics"]
        rows.append({
            "scenario": annotations.get("name", result.get("scenario_wide_groundtruth_name")),
            "input_mode": result.get("input_mode", "unknown"),
            "method": "adaptive_fusion_connectivity",
            "requested_retention": g["requested_retention"],
            "actual_event_retention": g["actual_event_retention"],
            "nodes_before": g["candidate_node_count"],
            "nodes_after": g["retained_node_count"],
            "events_before": g["candidate_event_count"],
            "events_after": g["retained_event_count"],
            "event_compression": g["event_compression"],
            "final_node_recall": m["final_node_recall"],
            "final_derived_event_recall": m["final_derived_event_recall"],
            "verified_attack_path_retention": m["verified_attack_path_retention"],
        })
    evaluation_seconds = perf_counter() - started
    metadata = annotations.get("metadata", {})
    phase = result.get("runtime_breakdown_seconds", {})
    resource = result.get("resource_usage", {})
    baseline_rss = resource.get("baseline_rss_mb")
    peak_rss = resource.get("peak_rss_mb")
    return {
        "protocol_version": PROTOCOL_VERSION,
        "protocol_scope": "offline_evaluation_only; search/scoring/pruning inputs unchanged",
        "inputs": {
            "result": str(Path(result_path).resolve()),
            "annotations": str(Path(annotation_path).resolve()),
            "input_mode": result.get("input_mode", "unknown"),
        },
        "reference_annotations": {
            "human_reviewed_nodes": {
                "source": metadata.get("groundtruth_source"),
                "version_or_hash": metadata.get("groundtruth_source_sha256"),
                "scope": metadata.get("label_scope"),
                "generation_rule": "read entity UUIDs from source CSV",
                "verification_status": "human_reviewed_entity_labels",
                "database_match": _ratio(len(database_truth_nodes), len(all_truth_nodes)),
                "unmatched_ids": sorted(all_truth_nodes - database_truth_nodes),
            },
            "rule_derived_events": {
                "source": metadata.get("groundtruth_source"),
                "version_or_hash": metadata.get("groundtruth_source_sha256"),
                "scope": "events in fixed scenario scope",
                "generation_rule": metadata.get("attack_event_rule"),
                "verification_status": "automatically_derived_not_eventwise_human_verified",
                "database_match": _ratio(len(database_truth_edges), len(all_truth_event_ids)),
                "unmatched_ids": sorted(all_truth_event_ids - set(database_truth_edges)),
            },
            "derived_reference_paths": {
                "source": metadata.get("groundtruth_source"),
                "version_or_hash": metadata.get("groundtruth_source_sha256"),
                "scope": metadata.get("path_rule"),
                "generation_rule": metadata.get("path_rule"),
                "verification_status": "automatically_derived_not_human_verified",
                "count": len(annotations.get("attack_paths", [])),
            },
            "human_verified_paths": {
                "source": metadata.get("verified_path_source"),
                "version_or_hash": metadata.get("verified_path_hash"),
                "scope": None,
                "generation_rule": None,
                "verification_status": "not_available",
                "count": len(annotations.get("verified_attack_paths", [])),
            },
        },
        "main_results_table": rows,
        "diagnostic_table": [
            {
                "scenario": annotations.get("name"),
                "poi_count_and_source": {
                    "count": len(result.get("annotated_seed_event_ids", [])),
                    "source": result.get("annotation_name"),
                },
                "label_database_match": {
                    "nodes": _ratio(len(database_truth_nodes), len(all_truth_nodes)),
                    "derived_events": _ratio(len(database_truth_edges), len(all_truth_event_ids)),
                },
                "candidate_node_recall": audit["metrics"]["candidate_node_recall"],
                "candidate_derived_event_recall": audit["metrics"]["candidate_derived_event_recall"],
                "conditional_event_retention_by_budget": [
                    {"requested_retention": item["graph_size"]["requested_retention"],
                     "metric": item["metrics"]["conditional_derived_event_retention"]}
                    for item in audits
                ],
                "derived_reference_path_retention_by_budget": [
                    {"requested_retention": item["graph_size"]["requested_retention"],
                     "metric": item["metrics"]["derived_reference_path_retention"]}
                    for item in audits
                ],
                "time_respecting_reachability": {
                    "value": None,
                    "reason": "not_recoverable_from_existing_result_without_conflating_reachability_and_strict_paths",
                },
                "per_poi_metrics": {
                    "value": None,
                    "reason": "existing_result_does_not_store_each_POI_candidate_event_ID_set",
                    "macro_micro_status": "N/A",
                },
                "incomplete": bool(result.get("incomplete", False)),
                "truncation_reason": (result.get("candidate_construction") or {}).get("truncation_reason"),
            }
        ],
        "performance_table": [{
            "scenario": annotations.get("name"),
            "candidate_construction_seconds": phase.get("causal_search_and_candidate_build"),
            "features_and_diffusion_seconds": sum(
                float(phase.get(key, 0.0)) for key in (
                    "rarity_lookup", "edge_merge_weight_and_backward_impact",
                    "behavior_feature_extraction", "poi_conditioned_diffusion",
                    "per_poi_merge_features_impact_diffusion",
                )
            ),
            "single_budget_pruning_seconds": None,
            "single_budget_pruning_reason": "existing_result_times_all_budgets_and_ablations_together",
            "evaluation_seconds": evaluation_seconds,
            "single_processing_seconds": None,
            "single_processing_reason": "existing_elapsed_seconds_includes_all_budgets_and_ablations",
            "whole_experiment_seconds": result.get("elapsed_seconds"),
            "baseline_rss_mib": baseline_rss,
            "baseline_rss_reason": None if baseline_rss is not None else "not_recorded_by_existing_experiment",
            "process_peak_rss_mib": peak_rss,
            "peak_measurement_scope": resource.get("measurement_scope", resource.get("peak_memory_measurement")),
            "sampled_incremental_rss_mib": resource.get("peak_rss_increment_mb"),
            "sampled_incremental_rss_reason": (
                None if resource.get("peak_rss_increment_mb") is not None else "baseline_RSS_not_recorded"
            ),
        }],
        "budget_reports": audits,
        "curves": {
            "actual_event_retention_vs_derived_event_recall": [
                {"actual_event_retention": item["graph_size"]["actual_event_retention"],
                 "derived_event_recall": item["metrics"]["final_derived_event_recall"]}
                for item in audits
            ],
            "actual_event_retention_vs_derived_reference_path_retention": [
                {"actual_event_retention": item["graph_size"]["actual_event_retention"],
                 "derived_reference_path_retention": item["metrics"]["derived_reference_path_retention"]}
                for item in audits
            ],
        },
        "legacy_metric_mapping": {
            "attack_event_recall": "final_derived_event_recall (old scalar lacked numerator/denominator and label type)",
            "complete_path_retention": "derived_reference_path_retention (not verified_attack_path_retention)",
            "single_run_latency_seconds": "whole_experiment_seconds (included all budgets/ablations)",
            "critical_relation_strict_recovery": "legacy diagnostic only; no fixed relation manifest is present in these result files",
        },
        "unavailable_items": [
            "verified_event_recall: no human-verified event manifest",
            "verified_attack_path_retention: no human-verified path manifest",
            "precision/FPR/F1: no exhaustive negative labels",
            "storage_byte_compression: no same-format candidate/output serialization",
            "per-POI macro/micro metrics: candidate event IDs per POI were not serialized",
            "single-budget latency and baseline/incremental RSS: not recorded in existing run",
        ],
    }


def restat_result_file(db_path: str, result_path: str, annotation_path: str, output_path: str) -> dict:
    result = json.loads(Path(result_path).read_text(encoding="utf-8-sig"))
    annotations = json.loads(Path(annotation_path).read_text(encoding="utf-8-sig"))
    with ProvenanceStore(db_path) as store:
        report = build_protocol_v2_report(
            store, result, annotations,
            result_path=result_path, annotation_path=annotation_path,
        )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


__all__ = ["PROTOCOL_VERSION", "build_protocol_v2_report", "evaluate_protocol_v2", "restat_result_file"]
