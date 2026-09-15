#!/usr/bin/env python3
"""Offline-only miss taxonomy; never imported by the online runner."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from scripts.run_a_rasp_r import _first_observed, _load_identities, _scenario
from tc_pruning.investigation.alert_context import build_alert_context_packets
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.offline_analysis.candidate_miss import CandidateMissAnalyzer
from tc_pruning.orthrus_groundtruth import load_orthrus_groundtruth
from tc_pruning.store import ProvenanceStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--identities", required=True)
    parser.add_argument("--evaluation", required=True)
    parser.add_argument("--orthrus-groundtruth-dir", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--max-hops", type=int, default=12)
    args = parser.parse_args()
    evaluation = json.loads(Path(args.evaluation).read_text(encoding="utf-8"))
    alerts = json.loads(Path(args.alerts).read_text(encoding="utf-8"))
    registry = InvestigationSemanticsRegistry.cadets()
    records = {}
    search_bounds = {}
    with ProvenanceStore(args.db) as store:
        packets = build_alert_context_packets(
            alerts, store=store, identities=_load_identities(Path(args.identities))
        )
        for scenario in ("12", "13"):
            scenario_packets = [p for p in packets if _scenario(p.query_time_ns) == scenario]
            cutoff = max(p.query_time_ns for p in scenario_packets)
            scenario_start = (cutoff // 86_400_000_000_000) * 86_400_000_000_000
            search_bounds[scenario] = {
                "minimum_time_ns": scenario_start,
                "maximum_time_ns": cutoff,
                "scope": "complete UTC scenario-day provenance, not candidate graph",
            }
            anchors = {endpoint.raw_node_id for p in scenario_packets for endpoint in p.endpoints}
            truth = set(load_orthrus_groundtruth(
                Path(args.orthrus_groundtruth_dir) / f"node_Nginx_Backdoor_{scenario}.csv"
            )["node_ids"])
            observable = {
                node for node in truth
                if (first := _first_observed(store, node)) is not None and first <= cutoff
            }
            candidate = set(evaluation["per_scenario"][scenario]["V4_common_cause"]["candidate_gt_node_ids"])
            analyzer = CandidateMissAnalyzer(
                store, registry, max_hops=args.max_hops,
                minimum_time_ns=scenario_start,
            )
            records[scenario] = [
                analyzer.analyze(node, anchors, cutoff_ns=cutoff).to_dict()
                for node in sorted(observable - candidate)
            ]
    counts = Counter(
        label for scenario_records in records.values()
        for record in scenario_records for label in record["taxonomy_labels"]
    )
    output = {
        "schema_version": "candidate-miss-taxonomy-v1",
        "offline_only": True,
        "source_online_evaluation": str(Path(args.evaluation).resolve()),
        "scenarios": records,
        "search_bounds": search_bounds,
        "taxonomy_counts": dict(sorted(counts.items())),
    }
    Path(args.output_json).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Candidate Miss Taxonomy", "", "This is offline-only diagnostic output and is never fed back into the online run.", ""]
    for scenario, scenario_records in records.items():
        lines += [f"## Scenario {scenario} ({len(scenario_records)} misses)", ""]
        for record in scenario_records:
            labels = ", ".join(record["taxonomy_labels"])
            lines.append(f"- `{record['node_id']}`: {labels}; hops={record['minimum_hops']}; anchor=`{record['nearest_anchor']}`")
        lines.append("")
    Path(args.output_md).write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(output["taxonomy_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
