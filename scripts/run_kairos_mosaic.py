#!/usr/bin/env python3
"""Run the frozen, label-isolated KAIROS-MOSAIC online pipeline."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import gzip
import hashlib
import json
from pathlib import Path
import resource
import statistics
import time

from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.investigation.causal_corridors import CausalCorridorBuilder, CorridorConfig
from tc_pruning.investigation.graph_views import CleanPropagationConfig
from tc_pruning.investigation.kairos_components import KairosAnchorComponentBuilder
from tc_pruning.investigation.mosaic_experiment import run_online_experiment
from tc_pruning.investigation.progressive_purification import ProgressivePurification
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.investigation.target_compatibility import (
    TargetConditionedCompatibility,
    TargetContext,
)
from tc_pruning.store import ProvenanceStore


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _percentile(values, percentile):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * percentile) - 1))]


def _load_incident_ids(directory: Path | None, scenario: str) -> set[str]:
    if directory is None:
        return set()
    result = set()
    for path in sorted(directory.glob("*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            payload = json.load(stream)
        if str(payload.get("scenario", "")).zfill(2) != scenario.zfill(2):
            continue
        result.update(payload.get("seed_event_ids", ()))
        result.update(payload.get("candidate_sets", {}).get("V4", ()))
    return result


def _load_edges(store: ProvenanceStore, event_ids) -> dict:
    result = {}
    for event_id in sorted(set(event_ids)):
        edge = store.get_edge_by_event_id(event_id)
        if edge is not None:
            result[event_id] = edge
    return result


def _retrieve_layers(store, evidence, config, incident_ids):
    mapped = _load_edges(store, (row.raw_event_id for row in evidence))
    incident = _load_edges(store, incident_ids)
    all_edges = {**mapped, **incident}
    node_mass = defaultdict(float)
    for row in evidence:
        node_mass[row.src] += row.loss_percentile
        node_mass[row.dst] += row.loss_percentile
    nodes = [node for node, _ in sorted(node_mass.items(), key=lambda item: (-item[1], item[0]))]
    nodes = nodes[:int(config["seed_node_limit"])]
    earliest = min(row.timestamp_ns for row in evidence)
    latest = max(row.timestamp_ns for row in evidence)
    recent_start = earliest - int(config["inverse_lookback_ns"])
    long_start = earliest - int(config["long_history_lookback_ns"])
    scan_limit = int(config["per_node_scan_limit"])
    inverse = set()
    target_raw = set(incident)
    long_history = set()
    for node in nodes:
        for edge in store.get_directional_edges(
            node, direction="backward", minimum_time_ns=recent_start,
            maximum_time_ns=latest, scan_limit=scan_limit,
        ):
            all_edges[edge.event_id] = edge
            inverse.add(edge.event_id)
        for edge in store.get_directional_edges(
            node, direction="forward", minimum_time_ns=earliest,
            maximum_time_ns=latest + int(config["target_forward_ns"]),
            scan_limit=scan_limit,
        ):
            all_edges[edge.event_id] = edge
            target_raw.add(edge.event_id)
        for edge in store.get_directional_edges(
            node, direction="backward", minimum_time_ns=long_start,
            maximum_time_ns=recent_start - 1, scan_limit=scan_limit,
        ):
            gap = max(1, earliest - edge.timestamp_ns)
            signal = 1.0 / (1.0 + __import__("math").log1p(gap / 1_000_000_000))
            if signal >= float(config["long_history_threshold"]):
                all_edges[edge.event_id] = edge
                long_history.add(edge.event_id)

    base_edges = tuple(mapped.values())
    context = TargetContext(
        relations=frozenset(row.relation for row in evidence),
        resources=frozenset(edge.dst_semantic for edge in base_edges if edge.dst_semantic),
        process_lineage=frozenset(edge.src_semantic for edge in base_edges if edge.src_semantic),
        neighborhood=frozenset(node_mass),
    )
    matcher = TargetConditionedCompatibility()
    target = set()
    for event in target_raw:
        edge = all_edges[event]
        match = matcher.score(
            context, relation=edge.relation, process=edge.src_semantic,
            resource=edge.dst_semantic, remote=None, command=None,
            nodes={edge.src, edge.dst},
        )
        if match.total >= float(config["target_match_threshold"]):
            target.add(event)

    registry = InvestigationSemanticsRegistry.cadets()
    graph = CleanPropagationBuilder(registry, CleanPropagationConfig()).build(
        all_edges.values(), cutoff_ns=latest + int(config["target_forward_ns"]),
        history_cutoff_ns=earliest,
    )
    fanout_count = Counter(edge.causal_source for edge in graph.propagation_edges)
    support = {row.raw_event_id: row.loss_percentile for row in evidence}
    purified = ProgressivePurification().run(
        graph,
        frequency={edge.raw_event_id: fanout_count[edge.causal_source] for edge in graph.propagation_edges},
        fanout={edge.raw_event_id: fanout_count[edge.causal_source] for edge in graph.propagation_edges},
        kairos_support=support,
        target_support={event: 1.0 for event in target},
        unique_coverage={row.raw_event_id for row in evidence if row.anomalous_native},
    )
    components = KairosAnchorComponentBuilder().build(evidence)
    corridor_builder = CausalCorridorBuilder(CorridorConfig(
        int(config["corridor_k_paths"]), int(config["corridor_max_states"]),
        int(config["corridor_max_events"]),
    ))
    corridors = []
    for left, right in zip(components, components[1:]):
        corridors.extend(corridor_builder.between(purified.graph, left, right))
    corridor_ids = {event for corridor in corridors for event in corridor.raw_event_ids}
    return all_edges, {
        "inverse": inverse,
        "target": target,
        "long_history": long_history,
        "corridor": corridor_ids,
    }, {
        "seed_nodes": len(nodes),
        "purification_stop_reason": purified.stop_reason,
        "purification_rounds": [asdict(row) for row in purified.rounds],
        "anchor_components": len(components),
        "causal_corridors": len(corridors),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--scenario", required=True, choices=("06", "12", "13"))
    parser.add_argument("--track", choices=("A", "B"), required=True)
    parser.add_argument("--incident-dir")
    parser.add_argument("--config", default="configs/kairos_mosaic.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.track == "A" and not args.incident_dir:
        parser.error("Track A requires --incident-dir")
    evidence_path = Path(args.evidence)
    config_path = Path(args.config)
    evidence_payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    config = json.loads(config_path.read_text(encoding="utf-8"))
    evidence = tuple(KairosEvidence(**row) for row in evidence_payload["evidence"])
    incident_ids = _load_incident_ids(
        Path(args.incident_dir) if args.incident_dir else None, args.scenario
    )
    started = time.perf_counter()
    with ProvenanceStore(args.db) as store:
        edges, layers, retrieval_audit = _retrieve_layers(
            store, evidence, config, incident_ids
        )
    retrieval_seconds = time.perf_counter() - started
    samples = []
    result = None
    for _ in range(int(config.get("timing_repetitions", 5))):
        run_started = time.perf_counter()
        result = run_online_experiment(
            evidence, edges.values(), scenario=args.scenario, config=config,
            layer_event_ids=layers,
        )
        samples.append(time.perf_counter() - run_started)
    assert result is not None
    result.update({
        "track": args.track,
        "input_hashes": {
            "evidence": _hash(evidence_path), "config": _hash(config_path),
        },
        "mapping_audit": evidence_payload.get("audit", {}),
        "retrieval_audit": retrieval_audit,
        "performance": {
            "retrieval_seconds": retrieval_seconds,
            "selection_seconds_samples": samples,
            "selection_p50_seconds": statistics.median(samples),
            "selection_p95_seconds": _percentile(samples, 0.95),
            "rows_scanned_or_materialized": len(edges),
            "rss_max_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
    })
    result.pop("content_sha256", None)
    result["content_sha256"] = hashlib.sha256(json.dumps(
        result, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "scenario": args.scenario, "track": args.track,
        "R4_raw_events": result["retrieval_ablations"]["R4"]["raw_event_count"],
        "S5_raw_events": result["selection_ablations"]["S5"]["raw_event_count"],
        "p95_seconds": result["performance"]["selection_p95_seconds"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
