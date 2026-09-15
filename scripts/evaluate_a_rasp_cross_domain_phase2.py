#!/usr/bin/env python3
"""Join ORTHRUS/PDF truth only after Phase 2 online artifacts are frozen."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime
import gzip
import json
from pathlib import Path
from statistics import fmean, median

from scripts.run_a_rasp_r import _first_observed
from tc_pruning.orthrus_groundtruth import _strict_temporal_paths, load_orthrus_groundtruth
from tc_pruning.pdf_critical_edges import evaluate_pdf_critical_retention, load_pdf_critical_manifest
from tc_pruning.store import ProvenanceStore


def _load_gzip(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def _edges_by_events(store, event_ids):
    result = {}
    values = sorted(set(event_ids))
    for offset in range(0, len(values), 800):
        chunk = values[offset:offset + 800]
        placeholders = ",".join("?" for _ in chunk)
        for row in store.conn.execute(
            "SELECT id edge_id,event_id,src,dst,relation,timestamp_ns FROM edges "
            f"WHERE event_id IN ({placeholders})", chunk,
        ):
            result[str(row["event_id"])] = dict(row)
    return result


def _distribution(values):
    ordered = sorted(values)
    if not ordered:
        return {"mean": None, "p50": None, "p95": None}
    position = (len(ordered) - 1) * 0.95
    low = int(position)
    high = min(len(ordered) - 1, low + 1)
    p95 = ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return {"mean": fmean(ordered), "p50": median(ordered), "p95": p95}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--online-dir", required=True)
    parser.add_argument("--orthrus-groundtruth-dir", required=True)
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--pdf-critical-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.online_dir)
    manifest_bytes = (root / "online-results.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    queries = [_load_gzip(root / item["path"]) for item in manifest["artifacts"]]
    performance = json.loads((root / "performance.json").read_text(encoding="utf-8"))["queries"]
    pdf = load_pdf_critical_manifest(args.pdf_critical_manifest, args.pdf)
    truth_by_scenario = {
        scenario: load_orthrus_groundtruth(
            Path(args.orthrus_groundtruth_dir) / f"node_Nginx_Backdoor_{scenario}.csv"
        ) for scenario in ("06", "12", "13")
    }
    cutoffs = {
        scenario: max(row["query_time_ns"] for row in queries if row["scenario"] == scenario)
        for scenario in truth_by_scenario
    }
    per_scenario = {}
    with ProvenanceStore(args.db) as store:
        observable = {
            scenario: {
                node for node in truth["node_ids"]
                if (first := _first_observed(store, node)) is not None and first <= cutoffs[scenario]
            }
            for scenario, truth in truth_by_scenario.items()
        }
        for scenario in sorted(truth_by_scenario):
            scenario_queries = [row for row in queries if row["scenario"] == scenario]
            truth = set(truth_by_scenario[scenario]["node_ids"])
            obs = observable[scenario]
            variant_names = sorted(scenario_queries[0]["variants"])
            budget_keys = sorted(scenario_queries[0]["absolute_budgets"], key=float)
            per_scenario[scenario] = {}
            candidate_cache = {}
            for variant in variant_names:
                candidate_events = set()
                for query in scenario_queries:
                    candidate_key = query["variants"][variant]["candidate_set"]
                    candidate_events.update(query["candidate_sets"][candidate_key])
                candidate_key = frozenset(candidate_events)
                if candidate_key not in candidate_cache:
                    cached_edges = _edges_by_events(store, candidate_events)
                    candidate_cache[candidate_key] = (
                        cached_edges,
                        _strict_temporal_paths(cached_edges.values(), truth),
                    )
                candidate_edges, candidate_paths = candidate_cache[candidate_key]
                candidate_nodes = {
                    str(edge[side]) for edge in candidate_edges.values() for side in ("src", "dst")
                }
                candidate_gt_ids = obs & candidate_nodes
                per_scenario[scenario][variant] = {}
                for budget_key in budget_keys:
                    selected = {
                        event for query in scenario_queries
                        for event in query["variants"][variant]["budgets"][budget_key]["selected_event_ids"]
                    }
                    raw_event_cost = sum(
                        len(set(query["variants"][variant]["budgets"][budget_key]["selected_event_ids"]))
                        for query in scenario_queries
                    )
                    selected_nodes = {
                        str(candidate_edges[event][side])
                        for event in selected if event in candidate_edges
                        for side in ("src", "dst")
                    }
                    selected_gt_ids = obs & selected_nodes
                    selected_edges = [
                        candidate_edges[event] for event in selected
                        if event in candidate_edges
                    ]
                    retained_paths = _strict_temporal_paths(selected_edges, truth)
                    canonical_retained = sum(
                        set(path) <= selected for path in candidate_paths.values()
                    )
                    pdf_metrics = evaluate_pdf_critical_retention(
                        pdf, scenario=scenario,
                        candidate_event_ids=candidate_events,
                        selected_event_ids=selected,
                    )
                    absolute_budget = sum(
                        int(query["absolute_budgets"][budget_key]) for query in scenario_queries
                    )
                    baseline_candidate_events = sum(
                        int(query["baseline_candidate_events"]) for query in scenario_queries
                    )
                    feasible = all(
                        query["variants"][variant]["budgets"][budget_key].get("budget_feasible", True)
                        for query in scenario_queries
                    )
                    per_scenario[scenario][variant][budget_key] = {
                        "observable_gt_nodes": len(obs),
                        "candidate_gt_nodes": len(candidate_gt_ids),
                        "selected_gt_nodes": len(selected_gt_ids),
                        "candidate_gt_node_ids": sorted(candidate_gt_ids),
                        "selected_gt_node_ids": sorted(selected_gt_ids),
                        "observable_candidate_recall": len(candidate_gt_ids) / len(obs),
                        "observable_final_recall": len(selected_gt_ids) / len(obs),
                        "conditional_selection_recall": len(selected_gt_ids) / len(candidate_gt_ids) if candidate_gt_ids else None,
                        "candidate_events": len(candidate_events),
                        "selected_event_union": len(selected),
                        "raw_event_cost": raw_event_cost,
                        "absolute_budget_sum": absolute_budget,
                        "baseline_candidate_events": baseline_candidate_events,
                        "actual_keep_ratio": raw_event_cost / baseline_candidate_events,
                        "budget_feasible": feasible,
                        "candidate_pdf_critical_events": pdf_metrics["candidate_critical_edges"],
                        "selected_pdf_critical_events": pdf_metrics["retained_candidate_critical_edges"],
                        "candidate_complete_pdf_paths": pdf_metrics["candidate_complete_attack_paths"],
                        "complete_pdf_paths": pdf_metrics["retained_candidate_complete_attack_paths"],
                        "candidate_strict_temporal_paths": len(candidate_paths),
                        "retained_strict_temporal_paths": len(retained_paths),
                        "canonical_candidate_paths_fully_retained": canonical_retained,
                        "strict_path_retention": len(retained_paths) / len(candidate_paths) if candidate_paths else None,
                    }
    aggregate = {}
    variants = sorted(next(iter(per_scenario.values())))
    budgets = sorted(next(iter(next(iter(per_scenario.values())).values())), key=float)
    for variant in variants:
        aggregate[variant] = {}
        for budget in budgets:
            rows = [per_scenario[scenario][variant][budget] for scenario in sorted(per_scenario)]
            obs = sum(row["observable_gt_nodes"] for row in rows)
            candidate = sum(row["candidate_gt_nodes"] for row in rows)
            selected = sum(row["selected_gt_nodes"] for row in rows)
            strict_candidate = sum(row["candidate_strict_temporal_paths"] for row in rows)
            strict_selected = sum(row["retained_strict_temporal_paths"] for row in rows)
            aggregate[variant][budget] = {
                "observable_gt_nodes": obs,
                "candidate_gt_nodes": candidate,
                "selected_gt_nodes": selected,
                "observable_candidate_recall": candidate / obs,
                "observable_final_recall": selected / obs,
                "conditional_selection_recall": selected / candidate if candidate else None,
                "candidate_events": sum(row["candidate_events"] for row in rows),
                "selected_event_union": sum(row["selected_event_union"] for row in rows),
                "raw_event_cost": sum(row["raw_event_cost"] for row in rows),
                "actual_keep_ratio": sum(row["raw_event_cost"] for row in rows) / sum(row["baseline_candidate_events"] for row in rows),
                "budget_feasible": all(row["budget_feasible"] for row in rows),
                "candidate_pdf_critical_events": sum(row["candidate_pdf_critical_events"] for row in rows),
                "selected_pdf_critical_events": sum(row["selected_pdf_critical_events"] for row in rows),
                "candidate_complete_pdf_paths": sum(row["candidate_complete_pdf_paths"] for row in rows),
                "complete_pdf_paths": sum(row["complete_pdf_paths"] for row in rows),
                "candidate_strict_temporal_paths": strict_candidate,
                "retained_strict_temporal_paths": strict_selected,
                "strict_path_retention": strict_selected / strict_candidate if strict_candidate else None,
            }
    motif_counts = Counter(
        motif["motif_type"] for query in queries for motif in query["modules"]["motifs"]
    )
    motif_rows = [
        motif for query in queries for motif in query["modules"]["motifs"]
    ]
    maximum_budget = sum(max(query["absolute_budgets"].values()) for query in queries)
    preserver_cost = sum(
        query["modules"]["preserver"]["preserver_raw_event_cost"] for query in queries
    )
    module_metrics = {
        "reverse_root_count": sum(len(query["modules"]["reverse"]["roots"]) for query in queries),
        "forward_sphere_count": sum(len(query["modules"]["forward"]["spheres"]) for query in queries),
        "forward_verified_root_count": sum(
            sphere["verification_score"] > 0
            for query in queries for sphere in query["modules"]["forward"]["spheres"]
        ),
        "motif_count_by_type": dict(sorted(motif_counts.items())),
        "verified_motif_count": sum(float(motif["motif_verification"]) > 0 for motif in motif_rows),
        "motif_raw_event_cost": sum(len(set(motif["raw_event_ids"])) for motif in motif_rows),
        "demand_pair_count": sum(query["modules"]["preserver"]["demand_pair_count"] for query in queries),
        "preserved_demand_count": sum(query["modules"]["preserver"]["preserved_demand_count"] for query in queries),
        "preserver_raw_event_cost": preserver_cost,
        "preserver_fraction_of_max_budget": preserver_cost / maximum_budget,
        "candidate_gain_by_module_at_20_percent": {
            "phase1_over_v0_gt_nodes": aggregate["V4_phase1"]["0.20"]["candidate_gt_nodes"] - aggregate["V0_legacy"]["0.20"]["candidate_gt_nodes"],
            "reverse_over_phase1_gt_nodes": aggregate["D_reverse"]["0.20"]["candidate_gt_nodes"] - aggregate["V4_phase1"]["0.20"]["candidate_gt_nodes"],
            "forward_over_reverse_gt_nodes": aggregate["E_forward"]["0.20"]["candidate_gt_nodes"] - aggregate["D_reverse"]["0.20"]["candidate_gt_nodes"],
        },
    }
    demand_count = module_metrics["demand_pair_count"]
    module_metrics["reachability_preservation_rate"] = (
        module_metrics["preserved_demand_count"] / demand_count if demand_count else 1.0
    )
    timings = {
        key: _distribution([float(row[key]) for row in performance])
        for key in (
            "candidate_build_seconds", "reverse_rr_seconds", "forward_sphere_seconds",
            "motif_seconds", "preserver_seconds", "selector_seconds", "total_online_seconds",
        )
    }
    timings["peak_rss_bytes"] = max(int(row["peak_rss_bytes"]) for row in performance)
    output = {
        "schema_version": "a-rasp-cross-domain-phase2-evaluation-v1",
        "dataset": "DARPA TC CADETS E3 only (development)",
        "online_sha256": __import__("hashlib").sha256(manifest_bytes).hexdigest(),
        "groundtruth_loaded_after_online_results_frozen": True,
        "attack_node_groundtruth": "PIDSMaker/ORTHRUS",
        "critical_event_groundtruth": "DARPA E3 PDF manifest",
        "per_scenario": per_scenario,
        "aggregate": aggregate,
        "module_metrics": module_metrics,
        "performance": timings,
    }
    Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({variant: rows["0.20"] for variant, rows in aggregate.items()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
