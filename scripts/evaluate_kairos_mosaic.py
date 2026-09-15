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
            candidate_ids = online["retrieval_ablations"]["R4"]["event_ids"]
            endpoints = {}
            for event in candidate_ids:
                edge = store.get_edge_by_event_id(event)
                if edge is not None:
                    endpoints[event] = (edge.src, edge.dst)
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
                    ablations[family][name] = {
                        "known_tp": len(selected & reference_events),
                        "known_fn": len(reference_events - selected),
                        "known_recall": len(selected & reference_events) / len(reference_events) if reference_events else 1.0,
                        "raw_event_count": layer["raw_event_count"],
                        "projected_edge_count": layer["projected_edge_count"],
                    }
            results.append({
                "online_source": str(source.resolve()),
                "online_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "track": online["track"], "scenario": scenario,
                "orthrus": {key: value for key, value in node_truth.items() if key != "nodes"},
                "candidate_selection_decomposition": metrics,
                "pdf_critical": pdf_metrics,
                "ablations": ablations,
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
