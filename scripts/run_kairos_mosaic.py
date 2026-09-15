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
import re
import statistics
import time

from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.investigation.causal_corridors import CausalCorridorBuilder, CorridorConfig
from tc_pruning.investigation.graph_views import CleanPropagationConfig
from tc_pruning.investigation.kairos_components import KairosAnchorComponentBuilder
from tc_pruning.investigation.inverse_coverage import SourceAwareInverseCoverage
from tc_pruning.investigation.mosaic_experiment import (
    run_online_experiment,
    validate_evidence_payload,
    validate_online_payload,
)
from tc_pruning.investigation.progressive_purification import ProgressivePurification
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.investigation.target_compatibility import (
    TargetConditionedCompatibility,
    TargetContext,
)
from tc_pruning.investigation.temporal_memory import (
    LongShortTemporalMemory,
    RarePairHistoryKey,
)
from tc_pruning.store import ProvenanceStore


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_content_hash(path: Path, declared: str | None = None) -> str:
    actual = _hash(path)
    if declared is not None and declared != actual:
        raise ValueError(
            f"database content SHA-256 mismatch: declared {declared}, actual {actual}"
        )
    return actual


def _percentile(values, percentile):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * percentile) - 1))]


def _process_read_bytes():
    try:
        for line in Path("/proc/self/io").read_text(encoding="utf-8").splitlines():
            if line.startswith("read_bytes:"):
                return int(line.split(":", 1)[1])
    except OSError:
        pass
    return None


def _load_incident_ids(directory: Path | None, scenario: str) -> tuple[set[str], dict[str, str]]:
    if directory is None:
        return set(), {}
    result = set()
    hashes = {}
    for path in sorted(directory.glob("*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict):
            raise ValueError(f"invalid incident artifact: {path.name}")
        artifact_scenario = str(payload.get("scenario", "")).zfill(2)
        seed_event_ids = payload.get("seed_event_ids", ())
        if not isinstance(seed_event_ids, (list, tuple)) or not all(
            isinstance(event, str) for event in seed_event_ids
        ):
            raise ValueError(f"invalid incident seed schema: {path.name}")
        if artifact_scenario != scenario.zfill(2):
            continue
        result.update(seed_event_ids)
        sanitized = {
            "scenario": artifact_scenario,
            "seed_event_ids": sorted(set(seed_event_ids)),
        }
        hashes[f"artifact_{len(hashes):03d}"] = hashlib.sha256(json.dumps(
            sanitized, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
    return result, hashes


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
    inverse_scan = set()
    target_raw = set(incident)
    long_raw = set()
    for node in nodes:
        for edge in store.get_directional_edges(
            node, direction="backward", minimum_time_ns=recent_start,
            maximum_time_ns=latest, scan_limit=scan_limit,
        ):
            all_edges[edge.event_id] = edge
            inverse_scan.add(edge.event_id)
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
            all_edges[edge.event_id] = edge
            long_raw.add(edge.event_id)

    memory = LongShortTemporalMemory()
    history_by_key = defaultdict(list)
    memory_events = inverse_scan | long_raw
    for event in sorted(memory_events, key=lambda item: (all_edges[item].timestamp_ns, item)):
        edge = all_edges[event]
        key = RarePairHistoryKey(edge.src_semantic, edge.relation.upper(), edge.dst_semantic)
        memory.observe(key, edge.timestamp_ns, event)
        history_by_key[key].append(event)
    long_history = set()
    memory_event_min_gap = {}
    short_memory_hits = 0
    long_memory_hits = 0
    for edge in mapped.values():
        key = RarePairHistoryKey(edge.src_semantic, edge.relation.upper(), edge.dst_semantic)
        memory_score = memory.score(key, edge.timestamp_ns)
        short_memory_hits += int(memory_score.short_count > 0)
        long_memory_hits += int(memory_score.long_count > 0)
        if memory_score.fused >= float(config["long_history_threshold"]):
            for event in history_by_key.get(key, ()):
                if all_edges[event].timestamp_ns >= edge.timestamp_ns:
                    continue
                long_history.add(event)
                gap = edge.timestamp_ns - all_edges[event].timestamp_ns
                memory_event_min_gap[event] = min(
                    gap, memory_event_min_gap.get(event, gap)
                )

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

    support = {row.raw_event_id: row.loss_percentile for row in evidence}
    unique_coverage = {row.raw_event_id for row in evidence if row.anomalous_native}
    registry = InvestigationSemanticsRegistry.cadets()

    def purified_graph(event_ids, *, target_ids=frozenset()):
        graph = CleanPropagationBuilder(registry, CleanPropagationConfig()).build(
            (all_edges[event] for event in event_ids if event in all_edges),
            cutoff_ns=latest + int(config["target_forward_ns"]),
            history_cutoff_ns=long_start,
        )
        fanout_count = Counter(edge.causal_source for edge in graph.propagation_edges)
        return ProgressivePurification().run(
            graph,
            frequency={
                edge.raw_event_id: fanout_count[edge.causal_source]
                for edge in graph.propagation_edges
            },
            fanout={
                edge.raw_event_id: fanout_count[edge.causal_source]
                for edge in graph.propagation_edges
            },
            kairos_support=support,
            target_support={event: 1.0 for event in target_ids},
            unique_coverage=unique_coverage,
        )

    components = KairosAnchorComponentBuilder().build(evidence)
    inverse_purified = purified_graph(set(mapped) | inverse_scan)
    roots = SourceAwareInverseCoverage().explain(inverse_purified.graph, components)
    inverse = {
        event for root in roots for event in root.witness_event_ids
        if event in inverse_scan
    }
    envelope_ids = set(mapped) | inverse | target | long_history
    k5_ids = set(mapped) | inverse | target
    memory_bucket_events = defaultdict(list)
    for event in sorted(long_history - k5_ids):
        memory_bucket_events[memory.gap_bucket(memory_event_min_gap[event])].append(event)
    memory_bucket_additions = dict(sorted(memory_bucket_events.items()))
    envelope_purified = purified_graph(envelope_ids, target_ids=target)
    corridor_builder = CausalCorridorBuilder(CorridorConfig(
        int(config["corridor_k_paths"]), int(config["corridor_max_states"]),
        int(config["corridor_max_events"]),
    ))
    corridors = []
    for left, right in zip(components, components[1:]):
        corridors.extend(corridor_builder.between(envelope_purified.graph, left, right))
    corridor_ids = {event for corridor in corridors for event in corridor.raw_event_ids}
    return all_edges, {
        "inverse": inverse,
        "target": target,
        "long_history": long_history,
        "corridor": corridor_ids,
    }, {
        "seed_nodes": len(nodes),
        "purification_stop_reason": envelope_purified.stop_reason,
        "purification_rounds": [asdict(row) for row in envelope_purified.rounds],
        "inverse_purification_stop_reason": inverse_purified.stop_reason,
        "anchor_components": len(components),
        "inverse_roots": len(roots),
        "temporal_memory_short_hits": short_memory_hits,
        "temporal_memory_long_hits": long_memory_hits,
        "temporal_memory_event_ids_by_gap_bucket": memory_bucket_additions,
        "causal_corridors": len(corridors),
    }, tuple(corridor.path_bundle for corridor in corridors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--scenario", required=True, choices=("06", "12", "13"))
    parser.add_argument("--track", choices=("A", "B"), required=True)
    parser.add_argument("--incident-dir")
    parser.add_argument("--db-content-sha256")
    parser.add_argument("--config", default="configs/kairos_mosaic.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.track == "A" and not args.incident_dir:
        parser.error("Track A requires --incident-dir")
    if args.track == "B" and args.incident_dir:
        parser.error("Track B forbids --incident-dir")
    if args.db_content_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.db_content_sha256):
        parser.error("--db-content-sha256 must be 64 lowercase hexadecimal characters")
    evidence_path = Path(args.evidence)
    config_path = Path(args.config)
    evidence_payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    validate_evidence_payload(evidence_payload)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    evidence = tuple(KairosEvidence(**row) for row in evidence_payload["evidence"])
    incident_ids, incident_hashes = _load_incident_ids(
        Path(args.incident_dir) if args.incident_dir else None, args.scenario
    )
    started = time.perf_counter()
    read_bytes_before = _process_read_bytes()
    if evidence:
        with ProvenanceStore(args.db) as store:
            database_events = store.edge_count()
            edges, layers, retrieval_audit, path_bundles = _retrieve_layers(
                store, evidence, config, incident_ids
            )
    else:
        with ProvenanceStore(args.db) as store:
            database_events = store.edge_count()
            edges = _load_edges(store, incident_ids)
        layers = {
            "inverse": set(), "target": set(edges),
            "long_history": set(), "corridor": set(),
        }
        path_bundles = ()
        retrieval_audit = {
            "seed_nodes": 0,
            "purification_stop_reason": (
                "NO_NATIVE_ALERT_WITH_INCIDENT_CONTEXT" if edges else "NO_NATIVE_ALERT"
            ),
            "purification_rounds": [], "anchor_components": 0, "causal_corridors": 0,
        }
    retrieval_seconds = time.perf_counter() - started
    read_bytes_after = _process_read_bytes()
    samples = []
    result = None
    for _ in range(int(config.get("timing_repetitions", 5))):
        run_started = time.perf_counter()
        result = run_online_experiment(
            evidence, edges.values(), scenario=args.scenario, config=config,
            layer_event_ids=layers, path_bundles=path_bundles, compute_hash=False,
        )
        samples.append(time.perf_counter() - run_started)
    assert result is not None
    input_hashes = {
        "evidence": _hash(evidence_path), "config": _hash(config_path),
        "incident_artifacts": incident_hashes,
        "database_identity": {
            "path": str(Path(args.db).resolve()),
            "size_bytes": Path(args.db).stat().st_size,
            "raw_events": database_events,
            "content_sha256": _verified_content_hash(
                Path(args.db), args.db_content_sha256
            ),
        },
    }
    mapping_audit = dict(evidence_payload["audit"])
    decision_sha256 = hashlib.sha256(json.dumps({
        "result": result,
        "input_hashes": input_hashes,
        "mapping_audit": mapping_audit,
        "retrieval_audit": retrieval_audit,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result.update({
        "track": args.track,
        "input_hashes": input_hashes,
        "decision_sha256": decision_sha256,
        "mapping_audit": mapping_audit,
        "retrieval_audit": retrieval_audit,
        "performance": {
            "retrieval_seconds": retrieval_seconds,
            "selection_seconds_samples": samples,
            "selection_p50_seconds": statistics.median(samples),
            "selection_p95_seconds": _percentile(samples, 0.95),
            "rows_scanned_or_materialized": len(edges),
            "database_raw_events": database_events,
            "materialization_ratio": len(edges) / database_events if database_events else 0.0,
            "storage_read_bytes_procfs": (
                max(0, read_bytes_after - read_bytes_before)
                if read_bytes_before is not None and read_bytes_after is not None else None
            ),
            "rss_max_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
    })
    validate_online_payload(result)
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
