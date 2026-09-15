#!/usr/bin/env python3
"""Run label-free A_rasp cross-domain Phase 2 ablations on CADETS E3."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import resource
import time

import numpy as np

from scripts.compare_route_c_a_rasp import _load_rows
from scripts.run_a_rasp_r import _baseline_by_seed, _load_identities, bounded_candidate_union
from scripts.run_rcvp import _arrays, _select_fork
from tc_pruning.frequency_snapshot import default_snapshot_path, load_snapshot
from tc_pruning.investigation.alert_context import build_alert_context_packets
from tc_pruning.investigation.branch_fair_selector import BranchFairConfig, LazyGreedySelector
from tc_pruning.investigation.candidate_builder import CandidateConfig, MultiViewCandidateBuilder
from tc_pruning.investigation.evidence_units import EvidenceUnit, ecdf_relevance
from tc_pruning.investigation.forward_sphere import ForwardCausalSphereBuilder, ForwardSphereConfig, OnlineForwardSignals
from tc_pruning.investigation.graph_views import CleanPropagationConfig
from tc_pruning.investigation.motifs import TemporalCausalMotifBuilder
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.rasp_adapter import select_with_frozen_a_rasp
from tc_pruning.investigation.reachability import TemporalDemandPair, TemporalReachabilityPreserver
from tc_pruning.investigation.reverse_reachability import ReverseReachabilityConfig, TemporalReverseReachability
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import StoredEdge
from tc_pruning.store import ProvenanceStore


def _canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))


def _write_gzip(path: Path, value) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(_canonical(value))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scenario(timestamp_ns: int) -> str:
    return datetime.fromtimestamp(timestamp_ns / 1e9, UTC).strftime("%d")


def _family(edge: StoredEdge) -> str:
    relation = edge.relation.upper()
    if relation in {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"}:
        return "CONTROL"
    if relation in {"EVENT_READ", "EVENT_MMAP", "EVENT_LOADLIBRARY"}:
        return "FILE_READ"
    if relation in {"EVENT_WRITE", "EVENT_CREATE_OBJECT", "EVENT_TRUNCATE", "EVENT_RENAME", "EVENT_LINK", "EVENT_UNLINK"}:
        return "FILE_WRITE"
    if relation == "EVENT_EXECUTE":
        return "EXECUTION"
    if relation in {"EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_READ_SOCKET_PARAMS"}:
        return "NETWORK_IN"
    if relation in {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG"}:
        return "NETWORK_OUT"
    return "OTHER"


def _legacy_masks(rows, scores, budgets):
    arrays = _arrays(rows)
    result = {}
    for key, budget in budgets.items():
        mask = _select_fork(np.asarray(scores), arrays, min(len(rows), budget))
        result[key] = sorted(str(row["event_id"]) for row, keep in zip(rows, mask) if bool(keep))
    return result


def _units(
    edges, scores, *, registry, anchors, certificate_by_event, sphere_by_event,
):
    raw_scores = {edge.event_id: float(score) for edge, score in zip(edges, scores)}
    normalized = ecdf_relevance(raw_scores)
    result = []
    for edge in edges:
        try:
            source, _ = registry.causal_endpoints(edge)
        except ValueError:
            source = edge.src
        roots = sphere_by_event.get(edge.event_id, ())
        branches = frozenset(
            (f"root:{root}" for root in roots),
        ) or frozenset({f"{_family(edge)}:{source}"})
        certs = certificate_by_event.get(edge.event_id, frozenset())
        verification = 1.0 if roots else (0.75 if certs else 0.25)
        result.append(EvidenceUnit(
            f"edge:{edge.event_id}", "edge", (edge.event_id,), (edge.src, edge.dst),
            branches, frozenset({node for node in (edge.src, edge.dst) if node in anchors}),
            None, certs, raw_scores[edge.event_id], normalized[edge.event_id], verification,
        ))
    return result, raw_scores, normalized


def _fair_select(units, mandatory, budgets, config):
    unit_tuple = tuple(units)
    unit_by_id = {unit.unit_id: unit for unit in unit_tuple}
    feasible = {key: budget for key, budget in budgets.items() if len(mandatory) <= budget}
    trajectory = None
    if feasible:
        trajectory = LazyGreedySelector(config).select(
            unit_tuple, mandatory_event_ids=set(mandatory), budget=max(feasible.values())
        )
    result = {}
    for key, budget in sorted(budgets.items(), key=lambda item: item[1]):
        if len(mandatory) > budget:
            result[key] = {
                "selected_event_ids": sorted(mandatory),
                "budget_feasible": False,
                "budget_overflow_events": len(mandatory) - budget,
                "selector": {},
            }
            continue
        selected_events = set(mandatory)
        selected_units = []
        branch_coverage = {}
        anchor_coverage = {}
        motif_coverage = {}
        assert trajectory is not None
        for unit_id in trajectory.selected_unit_ids:
            unit = unit_by_id[unit_id]
            new_events = set(unit.raw_event_ids) - selected_events
            if len(selected_events) + len(new_events) > budget:
                continue
            selected_events.update(new_events)
            selected_units.append(unit_id)
            for branch in unit.branch_ids:
                branch_coverage[branch] = branch_coverage.get(branch, 0) + 1
            for anchor in unit.anchor_ids:
                anchor_coverage[anchor] = anchor_coverage.get(anchor, 0) + 1
            if unit.motif_type:
                motif_coverage[unit.motif_type] = motif_coverage.get(unit.motif_type, 0) + 1
            if len(selected_events) >= budget:
                break
        result[key] = {
            "selected_event_ids": sorted(selected_events),
            "budget_feasible": True,
            "budget_overflow_events": 0,
            "selector": {
                "branch_coverage": dict(sorted(branch_coverage.items())),
                "anchor_coverage": dict(sorted(anchor_coverage.items())),
                "motif_coverage": dict(sorted(motif_coverage.items())),
                "heap_pushes": trajectory.heap_pushes,
                "heap_pops": trajectory.heap_pops,
                "utility_recomputes": trajectory.utility_recomputes,
                "candidate_units": trajectory.candidate_units,
                "selected_units": len(selected_units),
                "budget_sweep_policy": "single_max_budget_greedy_trajectory_prefix",
            },
        }
    return result


def _bounded_reconstruction(
    baseline_event_ids, roots, spheres, *, minimum_new=50, maximum_new=2000,
):
    baseline = set(baseline_event_ids)
    cap = max(minimum_new, min(maximum_new, math.floor(0.02 * len(baseline))))
    rr_ranked = []
    for root in roots:
        rr_ranked.extend((root.root_score, event) for event in root.witness_event_ids)
    rr_limit = max(1, cap // 2)
    rr = []
    for _, event in sorted(rr_ranked, key=lambda item: (-item[0], item[1])):
        if event not in baseline and event not in rr:
            rr.append(event)
        if len(rr) >= rr_limit:
            break
    sphere_ranked = []
    for sphere in spheres:
        if sphere.verification_score <= 0.05:
            continue
        round_gain = {
            event: round_row.marginal_gain
            for round_row in sphere.rounds for event in round_row.new_events
        }
        sphere_ranked.extend(
            (sphere.verification_score + round_gain.get(event, 0.0), event)
            for event in sphere.raw_event_ids
        )
    forward = []
    for _, event in sorted(sphere_ranked, key=lambda item: (-item[0], item[1])):
        if event not in baseline and event not in rr and event not in forward:
            forward.append(event)
        if len(rr) + len(forward) >= cap:
            break
    return tuple(rr), tuple(forward), cap


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--identities", required=True)
    parser.add_argument("--full-history", required=True)
    parser.add_argument("--config", default="configs/a_rasp_cross_domain_phase2.json")
    parser.add_argument("--rasp-config", default="configs/rasp_v1.json")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    rasp_config = json.loads(Path(args.rasp_config).read_text(encoding="utf-8"))
    ratios = tuple(float(value) for value in config["budget_ratios"])
    candidate_cfg = config["candidate"]
    rr_cfg = config["reverse_reachability"]
    sphere_cfg = config["forward_sphere"]
    selector_cfg = config["selector"]
    clean_cfg = config["propagation"]["clean_view"]
    output = Path(args.output_dir)
    baseline = _baseline_by_seed(Path(args.full_history))
    registry = InvestigationSemanticsRegistry.cadets()
    alert_input = json.loads(Path(args.alerts).read_text(encoding="utf-8"))
    artifacts = []
    performance = []
    snapshots = {}
    with ProvenanceStore(args.db) as store:
        packets = build_alert_context_packets(
            alert_input, store=store, identities=_load_identities(Path(args.identities))
        )
        for packet in sorted(packets, key=lambda item: (item.query_time_ns, item.query_id)):
            query_started = time.perf_counter()
            base = baseline[packet.seed_event_ids[0]]
            base_ids = tuple(base["edge_ids"])
            budgets = {
                f"{ratio:.2f}": max(1, math.floor(ratio * len(base_ids)))
                for ratio in ratios
            }
            cap = max(len(base_ids), math.floor(len(base_ids) * float(candidate_cfg["phase1_factor"])))
            history_start = packet.query_time_ns - int(candidate_cfg["history_horizon_seconds"]) * 1_000_000_000
            build_started = time.perf_counter()
            discovery = MultiViewCandidateBuilder(store, registry, CandidateConfig(
                candidate_cap=cap, history_start_ns=history_start, cutoff_ns=packet.query_time_ns,
                max_strict_depth=int(candidate_cfg["strict_depth"]),
                max_control_depth=int(candidate_cfg["control_depth"]), enable_common_cause=True,
            )).build(packet)
            v4_ids = bounded_candidate_union(base_ids, (edge.edge_id for edge in discovery.edges), cap=cap)
            candidate_build_seconds = time.perf_counter() - build_started
            full_edges = tuple(
                edge for page in store.iter_edges_by_time(history_start, packet.query_time_ns)
                for edge in page
            )
            graphs = CleanPropagationBuilder(registry, CleanPropagationConfig(
                relation_weights=clean_cfg["relation_weights"], tau_ns=clean_cfg["tau_ns"],
                alpha=float(clean_cfg["alpha"]), gamma=float(clean_cfg["gamma"]),
                progressive_clean=bool(clean_cfg["progressive_clean"]),
                progressive_rounds=int(clean_cfg["progressive_rounds"]),
            )).build(full_edges, cutoff_ns=packet.query_time_ns, history_cutoff_ns=packet.query_time_ns)
            rr_started = time.perf_counter()
            rr = TemporalReverseReachability(ReverseReachabilityConfig(
                samples=int(rr_cfg["samples"]), seed=int(rr_cfg["seed"]),
                max_hops=int(rr_cfg["max_hops"]), max_sketch_size=int(rr_cfg["max_sketch_size"]),
            )).run(graphs, {endpoint.raw_node_id: packet.query_time_ns for endpoint in packet.endpoints})
            reverse_seconds = time.perf_counter() - rr_started
            roots = rr.roots[: min(8, int(rr_cfg["top_roots"]))]
            day = packet.query_time_ns // 86_400_000_000_000
            snapshots.setdefault(day, load_snapshot(default_snapshot_path(args.db, day)))
            v4_rows = _load_rows(store.conn, list(v4_ids), snapshots[day].rarity, set(packet.seed_event_ids))
            v4_selection = select_with_frozen_a_rasp(v4_rows, config=rasp_config, absolute_budget=max(budgets.values()))
            v4_edges = [store.get_edge_by_event_id(str(row["event_id"])) for row in v4_rows]
            v4_edges = [edge for edge in v4_edges if edge is not None]
            _, _, v4_normalized = _units(v4_edges, v4_selection.scores, registry=registry,
                anchors=set(packet.all_alert_endpoint_ids), certificate_by_event={}, sphere_by_event={})
            rare = frozenset(
                str(row["event_id"]) for row in v4_rows
                if float(row["components"]["rarity"]) >= 0.8
            )
            sphere_started = time.perf_counter()
            spheres = [ForwardCausalSphereBuilder(ForwardSphereConfig(
                max_rounds=int(sphere_cfg["max_rounds"]),
                max_events=int(sphere_cfg["max_events_per_root"]),
                min_marginal_gain=float(sphere_cfg["min_marginal_gain"]),
                low_gain_patience=int(sphere_cfg["low_gain_patience"]),
            )).build(root.node_id, graphs, OnlineForwardSignals(
                anchor_ids=frozenset(packet.all_alert_endpoint_ids),
                normalized_relevance=v4_normalized, rare_event_ids=rare,
            ), backward_support=root.source_support) for root in roots]
            forward_seconds = time.perf_counter() - sphere_started
            full_by_event = {edge.event_id: edge for edge in full_edges}
            v4_event_ids = {str(row["event_id"]) for row in v4_rows}
            rr_added, sphere_added, reconstruction_cap = _bounded_reconstruction(
                v4_event_ids, roots, spheres
            )
            rr_event_ids = set(rr_added)
            sphere_event_ids = set(sphere_added)
            d_ids = tuple(dict.fromkeys((*v4_ids, *(full_by_event[event].edge_id for event in rr_added if event in full_by_event))))
            e_ids = tuple(dict.fromkeys((*d_ids, *(full_by_event[event].edge_id for event in sphere_added if event in full_by_event))))
            recon_events = rr_event_ids | sphere_event_ids
            verification_by_event = {
                event: sphere.verification_score
                for sphere in spheres for event in sphere.raw_event_ids
            }
            motif_started = time.perf_counter()
            motifs = TemporalCausalMotifBuilder(max_bridge_hops=int(config["motif"]["max_bridge_hops"])).build(
                (full_by_event[event] for event in sorted(recon_events) if event in full_by_event),
                anchor_ids=packet.all_alert_endpoint_ids,
                verified_terminal_ids={node for sphere in spheres if sphere.verification_score > 0 for node in sphere.node_ids[-1:]},
                normalized_relevance=v4_normalized,
                verification=verification_by_event,
            )
            motif_seconds = time.perf_counter() - motif_started
            certificate_by_event = {}
            for certificate in discovery.ledger.certificates:
                if certificate.item_type == "event":
                    certificate_by_event.setdefault(certificate.item_id, set()).add(certificate.certificate_type.value)
            certificate_by_event = {key: frozenset(value) for key, value in certificate_by_event.items()}
            sphere_by_event = {}
            for sphere in spheres:
                for event in sphere.raw_event_ids:
                    sphere_by_event.setdefault(event, set()).add(sphere.root_id)
            sphere_by_event = {key: tuple(sorted(value)) for key, value in sphere_by_event.items()}
            candidate_sets = {"V0": base_ids, "V4": v4_ids, "D": d_ids, "E": e_ids}
            scored = {}
            units_by_set = {}
            for name, ids in candidate_sets.items():
                rows = _load_rows(store.conn, list(ids), snapshots[day].rarity, set(packet.seed_event_ids))
                selection = select_with_frozen_a_rasp(rows, config=rasp_config, absolute_budget=max(budgets.values()))
                edges = [store.get_edge_by_event_id(str(row["event_id"])) for row in rows]
                edges = [edge for edge in edges if edge is not None]
                units, raw_scores, normalized = _units(
                    edges, selection.scores, registry=registry,
                    anchors=set(packet.all_alert_endpoint_ids),
                    certificate_by_event=certificate_by_event,
                    sphere_by_event=sphere_by_event,
                )
                scored[name] = (rows, selection.scores, raw_scores, normalized)
                units_by_set[name] = units
            demands = []
            for index, root in enumerate(roots):
                if not root.witness_event_ids:
                    continue
                last = full_by_event.get(root.witness_event_ids[-1])
                if last is None:
                    continue
                _, target = registry.causal_endpoints(last)
                demands.append(TemporalDemandPair(
                    f"root-anchor:{index}", root.node_id, target, "ROOT_ANCHOR", target,
                    "reverse reachable root witness", (history_start, packet.query_time_ns), root.root_score,
                ))
            e_edges = [full_by_event[str(row["event_id"])] for row in scored["E"][0] if str(row["event_id"]) in full_by_event]
            edge_costs = {
                edge.event_id: 1.0 / max(0.01, scored["E"][3].get(edge.event_id, 0.0) + verification_by_event.get(edge.event_id, 0.0))
                for edge in e_edges
            }
            preserve_started = time.perf_counter()
            preserver = TemporalReachabilityPreserver(registry).preserve(
                e_edges, demands, edge_costs, budget=max(budgets.values())
            )
            preserver_seconds = time.perf_counter() - preserve_started
            motif_units = [EvidenceUnit(
                motif.motif_id, "motif", motif.raw_event_ids, motif.node_ids,
                frozenset({f"motif:{motif.motif_type.value}"}),
                frozenset(set(motif.node_ids) & set(packet.all_alert_endpoint_ids)),
                motif.motif_type.value, frozenset(), motif.motif_relevance,
                motif.motif_score, motif.motif_verification,
            ) for motif in motifs]
            normal_only = BranchFairConfig(
                lambda_relevance=1.0, lambda_branch=0.0, lambda_anchor=0.0,
                lambda_motif=0.0, lambda_verification=0.0, lambda_redundancy=0.0,
            )
            fair_config = BranchFairConfig(
                lambda_relevance=float(selector_cfg["lambda_relevance"]),
                lambda_branch=float(selector_cfg["lambda_branch"]),
                lambda_anchor=float(selector_cfg["lambda_anchor"]),
                lambda_motif=float(selector_cfg["lambda_motif"]),
                lambda_verification=float(selector_cfg["lambda_verification"]),
                lambda_redundancy=float(selector_cfg["lambda_redundancy"]),
            )
            seeds = set(packet.seed_event_ids)
            selector_started = time.perf_counter()
            variants = {
                "V0_legacy": {"candidate_set": "V0", "budgets": {key: {"selected_event_ids": value, "budget_feasible": True} for key, value in _legacy_masks(scored["V0"][0], scored["V0"][1], budgets).items()}},
                "V4_phase1": {"candidate_set": "V4", "budgets": {key: {"selected_event_ids": value, "budget_feasible": True} for key, value in _legacy_masks(scored["V4"][0], scored["V4"][1], budgets).items()}},
                "B_normalized": {"candidate_set": "V4", "budgets": _fair_select(units_by_set["V4"], seeds, budgets, normal_only)},
                "C_branch_fair": {"candidate_set": "V4", "budgets": _fair_select(units_by_set["V4"], seeds, budgets, fair_config)},
                "D_reverse": {"candidate_set": "D", "budgets": {key: {"selected_event_ids": value, "budget_feasible": True} for key, value in _legacy_masks(scored["D"][0], scored["D"][1], budgets).items()}},
                "E_forward": {"candidate_set": "E", "budgets": {key: {"selected_event_ids": value, "budget_feasible": True} for key, value in _legacy_masks(scored["E"][0], scored["E"][1], budgets).items()}},
                "F_motifs": {"candidate_set": "E", "budgets": _fair_select((*units_by_set["E"], *motif_units), seeds, budgets, fair_config)},
                "G_preserver": {"candidate_set": "E", "budgets": _fair_select(units_by_set["E"], seeds | set(preserver.event_ids), budgets, fair_config)},
                "H_full": {"candidate_set": "E", "budgets": _fair_select((*units_by_set["E"], *motif_units), seeds | set(preserver.event_ids), budgets, fair_config)},
            }
            selector_seconds = time.perf_counter() - selector_started
            query_payload = {
                "schema_version": "a-rasp-cross-domain-phase2-query-v1",
                "query_id": base["query"]["query_id"], "packet_id": packet.query_id,
                "scenario": _scenario(packet.query_time_ns), "query_time_ns": packet.query_time_ns,
                "seed_event_ids": sorted(seeds),
                "baseline_candidate_events": len(base_ids), "absolute_budgets": budgets,
                "candidate_sets": {},
                "variants": variants,
                "modules": {
                    "reverse": {"roots": [asdict(root) for root in roots], "number_of_sketches": rr.number_of_sketches, "mean_sketch_size": rr.mean_sketch_size, "p95_sketch_size": rr.p95_sketch_size, "sampling_seed": rr.sampling_seed, "stability": rr.stability, "fallback_mode": rr.fallback_mode},
                    "forward": {"spheres": [asdict(sphere) for sphere in spheres]},
                    "reconstruction_resource_guard": {"max_new_events": reconstruction_cap, "reverse_added": len(rr_added), "forward_added": len(sphere_added)},
                    "motifs": [asdict(motif) for motif in motifs],
                    "preserver": asdict(preserver),
                },
            }
            # Reconstruct candidate event IDs from the already-scored rows; this avoids
            # quadratic edge lookup in the serialized path above.
            query_payload["candidate_sets"] = {
                key: sorted(str(row["event_id"]) for row in scored[key][0])
                for key in candidate_sets
            }
            safe = str(base["query"]["query_id"]).replace(":", "-")
            artifact_path = output / "online" / f"{safe}.json.gz"
            artifacts.append({
                "query_id": base["query"]["query_id"], "scenario": _scenario(packet.query_time_ns),
                "path": str(artifact_path.relative_to(output)), "sha256": _write_gzip(artifact_path, query_payload),
            })
            performance.append({
                "query_id": base["query"]["query_id"],
                "candidate_build_seconds": candidate_build_seconds,
                "reverse_rr_seconds": reverse_seconds,
                "forward_sphere_seconds": forward_seconds,
                "motif_seconds": motif_seconds,
                "preserver_seconds": preserver_seconds,
                "selector_seconds": selector_seconds,
                "total_online_seconds": time.perf_counter() - query_started,
                "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            })
            print(json.dumps({"query": base["query"]["query_id"], "scenario": _scenario(packet.query_time_ns), "roots": len(roots), "spheres": len(spheres), "motifs": len(motifs), "e_events": len(e_ids)}, sort_keys=True), flush=True)
    manifest = {
        "schema_version": "a-rasp-cross-domain-phase2-online-v1",
        "dataset": "DARPA TC CADETS E3 only", "ground_truth_used": False,
        "arrival_policy": "zero_delay_event_time_end", "config": config,
        "artifacts": artifacts,
    }
    _write_json(output / "online-results.json", manifest)
    _write_json(output / "performance.json", {"queries": performance})
    print(hashlib.sha256((output / "online-results.json").read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
