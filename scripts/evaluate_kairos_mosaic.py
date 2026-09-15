#!/usr/bin/env python3
"""Offline-only ORTHRUS/PDF evaluation for frozen KAIROS-MOSAIC outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tc_pruning.investigation.mosaic_offline import evaluate_online_artifact
from tc_pruning.orthrus_groundtruth import load_orthrus_groundtruth
from tc_pruning.pdf_critical_edges import (
    evaluate_pdf_critical_retention,
    load_pdf_critical_manifest,
)
from tc_pruning.store import ProvenanceStore


def _hash_payload(payload):
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


def _extend_event_cache(store, event_ids, cache):
    missing = sorted(set(event_ids) - cache.keys())
    for offset in range(0, len(missing), 400):
        chunk = missing[offset: offset + 400]
        placeholders = ",".join("?" for _ in chunk)
        for row in store.conn.execute(
            f"SELECT event_id,src,dst,relation,timestamp_ns FROM edges "
            f"WHERE event_id IN ({placeholders})",
            tuple(chunk),
        ):
            cache[str(row["event_id"])] = (
                str(row["src"]), str(row["dst"]), str(row["relation"]).upper(),
                int(row["timestamp_ns"]),
            )


def _projected_known_tp(selected, event_cache, reference_projection, window_ns):
    selected_projection = {
        (row[0], row[1], row[2], row[3] // window_ns)
        for event in selected if (row := event_cache.get(event)) is not None
    }
    return len(selected_projection & reference_projection)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="append", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--orthrus-dir", required=True)
    parser.add_argument("--pdf-manifest", required=True)
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    pdf_manifest = load_pdf_critical_manifest(args.pdf_manifest, args.pdf)
    results = []
    event_cache = {}
    with ProvenanceStore(args.db) as store:
        for source_name in args.online:
            source = Path(source_name)
            online = json.loads(source.read_text(encoding="utf-8"))
            scenario = str(online["scenario"]).zfill(2)
            csv_path = Path(args.orthrus_dir) / f"node_Nginx_Backdoor_{scenario}.csv"
            node_truth = load_orthrus_groundtruth(csv_path)
            reference_events = {
                str(edge["event_id"]) for edge in pdf_manifest["critical_edges"]
                if str(edge["scenario"]).zfill(2) == scenario
            }
            projection_window = int(online["config"]["projection_window_ns"])
            candidate_ids = online["retrieval_ablations"]["R4"]["event_ids"]
            _extend_event_cache(store, set(candidate_ids) | reference_events, event_cache)
            reference_projection = {
                (row[0], row[1], row[2], row[3] // projection_window)
                for event in reference_events
                if (row := event_cache.get(event)) is not None
            }
            endpoints = {
                event: event_cache[event][:2] for event in candidate_ids
                if event in event_cache
            }
            metrics = evaluate_online_artifact(
                online, reference_event_ids=reference_events,
                reference_node_ids=node_truth["node_ids"], edge_endpoints=endpoints,
            )
            pdf_metrics = evaluate_pdf_critical_retention(
                pdf_manifest, scenario=scenario,
                candidate_event_ids=candidate_ids,
                selected_event_ids=online["selection_ablations"]["S5"]["event_ids"],
            )
            ablations = {}
            for family in ("kairos_ablations", "retrieval_ablations", "selection_ablations"):
                ablations[family] = {}
                for name, layer in online[family].items():
                    selected = set(layer["event_ids"])
                    selected_nodes = {
                        str(node).casefold() for event in selected
                        for node in event_cache.get(event, ())[:2]
                    }
                    truth_nodes = {str(node).casefold() for node in node_truth["node_ids"]}
                    layer_pdf = evaluate_pdf_critical_retention(
                        pdf_manifest, scenario=scenario,
                        candidate_event_ids=selected, selected_event_ids=selected,
                    )
                    known_projected_tp = _projected_known_tp(
                        selected, event_cache, reference_projection, projection_window
                    )
                    ablations[family][name] = {
                        "known_tp": len(selected & reference_events),
                        "known_fn": len(reference_events - selected),
                        "known_recall": len(selected & reference_events) / len(reference_events) if reference_events else 1.0,
                        "raw_event_count": layer["raw_event_count"],
                        "projected_edge_count": layer["projected_edge_count"],
                        "known_projected_tp": known_projected_tp,
                        "unlabeled_output_edges": max(
                            0, layer["projected_edge_count"] - known_projected_tp
                        ),
                        "unlabeled_output_raw_events": max(
                            0, layer["raw_event_count"] - len(selected & reference_events)
                        ),
                        "attack_node_tp": len(selected_nodes & truth_nodes),
                        "attack_node_fn": len(truth_nodes - selected_nodes),
                        "attack_node_recall": (
                            len(selected_nodes & truth_nodes) / len(truth_nodes)
                            if truth_nodes else 1.0
                        ),
                        "complete_pdf_paths": layer_pdf["candidate_complete_attack_paths"],
                    }
            frontier = []
            frontier_events = set()
            for checkpoint in online["quality_size_frontier"]:
                frontier_events.update(checkpoint.get("added_event_ids", ()))
                frontier.append({
                    "raw_event_count": checkpoint["raw_event_count"],
                    "projected_edge_count": checkpoint["projected_edge_count"],
                    "known_tp": len(frontier_events & reference_events),
                    "known_fn": len(reference_events - frontier_events),
                    "minimum_objective_ratio": checkpoint["minimum_ratio"],
                })
            recommended_layer = online["r2_relation_fair"]
            recommended_events = set(recommended_layer["event_ids"])
            recommended_nodes = {
                str(node).casefold() for event in recommended_events
                for node in event_cache.get(event, ())[:2]
            }
            truth_nodes = {str(node).casefold() for node in node_truth["node_ids"]}
            recommended_pdf = evaluate_pdf_critical_retention(
                pdf_manifest, scenario=scenario,
                candidate_event_ids=online["retrieval_ablations"]["R2"]["event_ids"],
                selected_event_ids=recommended_events,
            )
            recommended = {
                "candidate_layer": "R2",
                "selector": "relation_round_robin",
                "raw_event_count": recommended_layer["raw_event_count"],
                "projected_edge_count": recommended_layer["projected_edge_count"],
                "known_tp": len(recommended_events & reference_events),
                "known_fn": len(reference_events - recommended_events),
                "attack_node_tp": len(recommended_nodes & truth_nodes),
                "attack_node_fn": len(truth_nodes - recommended_nodes),
                "complete_pdf_paths": recommended_pdf["retained_candidate_complete_attack_paths"],
            }
            rare_long_gap = {}
            for bucket, event_ids in online["retrieval_audit"].get(
                "temporal_memory_event_ids_by_gap_bucket", {}
            ).items():
                bucket_events = set(event_ids)
                recovered = len(bucket_events & reference_events)
                rare_long_gap[bucket] = {
                    "candidate_growth": len(bucket_events),
                    "known_gt_recovery": recovered,
                    "unlabeled_growth": len(bucket_events) - recovered,
                }
            results.append({
                "online_source": str(source.resolve()),
                "online_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "track": online["track"], "scenario": scenario,
                "orthrus": {key: value for key, value in node_truth.items() if key != "nodes"},
                "candidate_selection_decomposition": metrics,
                "pdf_critical": pdf_metrics,
                "ablations": ablations,
                "fn_vs_projected_edges": frontier,
                "r2_relation_fair": recommended,
                "rare_long_gap_ablation": rare_long_gap,
                "performance": online["performance"],
            })
    payload = {
        "schema_version": "kairos-mosaic-offline-evaluation-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "groundtruth_completeness": "PARTIAL_POSITIVE_GT",
        "results": results,
    }
    payload["content_sha256"] = _hash_payload(payload)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"runs": len(results), "content_sha256": payload["content_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
