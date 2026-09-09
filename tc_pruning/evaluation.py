from __future__ import annotations

import json
import hashlib
import time
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable

import psutil

from .diffusion import diffuse_importance
from .behavior import analyze_behaviors
from .depimpact import compute_depimpact_relevance
from .entry_ranking import discover_attack_entries, evaluate_entry_ranks
from .frequency import FrequencyModel
from .models import Neighborhood, StoredEdge
from .alert_evaluation import (
    aggregate_alert_metrics,
    associate_groundtruth_components,
    evaluate_alert_context,
    time_respecting_groundtruth_context,
)
from .causal import (
    CausalSearchConfig,
    DirectionalEdgeCache,
    build_alert_context,
    build_cumulative_forward_contexts,
)
from .cdm import event_investigation_anchor
from .nodoze import NODOZEFrequencyModel
from .pruning import PruningResult, adaptive_prune
from .rdp_guard import (
    PrefixAggregateScores,
    PrefixScoreAccumulator,
    RDPGuardScores,
    fuse_rarity_diffusion,
    recommend_operating_point,
    score_map_digest,
)
from .reconstruction import reconstruct_retained_paths
from .score_ledger import (
    candidate_graph_digest,
    verify_score_ledger,
    write_score_ledger,
)
from .store import ProvenanceStore
from .frequency_snapshot import default_snapshot_path, load_snapshot
from .window_search import (
    InvestigationWindow,
    WindowSearchLimits,
    build_window_context,
    expand_window_context,
    parse_kairos_window,
)


def _score_distribution(values: Iterable[float]) -> dict[str, float | int]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"count": 0, "nonzero": 0, "distinct_rounded": 0}
    at = lambda fraction: ordered[round(fraction * (len(ordered) - 1))]
    return {
        "count": len(ordered),
        "nonzero": sum(value > 0.0 for value in ordered),
        "distinct_rounded": len({round(value, 12) for value in ordered}),
        "min": ordered[0],
        "p50": at(0.5),
        "p90": at(0.9),
        "max": ordered[-1],
    }


@dataclass(slots=True)
class AttackAnnotations:
    name: str
    seed_uuids: set[str]
    attack_event_ids: set[str]
    attack_node_uuids: set[str]
    seed_event_ids: set[str] = field(default_factory=set)
    seed_event_groups: list[set[str]] = field(default_factory=list)
    seed_event_group_ids: list[str] = field(default_factory=list)
    seed_event_sequences: list[tuple[str, ...]] = field(default_factory=list)
    investigation_windows: dict[str, tuple[int, int]] = field(default_factory=dict)
    attack_paths: list[tuple[str, ...]] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def load(
        cls, path: str | Path, *, require_seeds: bool = True
    ) -> "AttackAnnotations":
        with open(path, "r", encoding="utf-8") as stream:
            raw = json.load(stream)
        seeds = set(raw.get("seed_uuids") or [])
        seed_events = set(raw.get("seed_event_ids") or [])
        raw_groups = [
            group for group in (raw.get("seed_event_groups") or [])
            if isinstance(group, dict) and group.get("seed_event_ids")
        ]
        seed_event_sequences = [
            tuple(dict.fromkeys(str(event_id) for event_id in group["seed_event_ids"]))
            for group in raw_groups
        ]
        seed_event_groups = [set(sequence) for sequence in seed_event_sequences]
        seed_event_group_ids = [
            str(group.get("group_id") or f"group-{index + 1}")
            for index, group in enumerate(raw_groups)
        ]
        investigation_windows: dict[str, tuple[int, int]] = {}
        for group_id, group in zip(seed_event_group_ids, raw_groups):
            start = group.get("window_start_ns")
            end = group.get("window_end_ns")
            if (start is None) != (end is None):
                raise ValueError(
                    "both window_start_ns and window_end_ns must be supplied"
                )
            if start is not None:
                start_ns, end_ns = int(start), int(end)
                if end_ns < start_ns:
                    raise ValueError(
                        "window_end_ns must be greater than or equal to window_start_ns"
                    )
                investigation_windows[group_id] = (start_ns, end_ns)
        for group in seed_event_groups:
            seed_events.update(group)
        attack_paths = [
            tuple(str(event_id) for event_id in path)
            for path in (raw.get("attack_paths") or [])
            if isinstance(path, list) and path
        ]
        if require_seeds and not seeds and not seed_events:
            raise ValueError(
                "annotation manifest requires seed_uuids or seed_event_ids"
            )
        return cls(
            name=str(raw.get("name") or Path(path).stem),
            seed_uuids=seeds,
            attack_event_ids=set(raw.get("attack_event_ids") or []),
            attack_node_uuids=set(raw.get("attack_node_uuids") or []),
            seed_event_ids=seed_events,
            seed_event_groups=seed_event_groups,
            seed_event_group_ids=seed_event_group_ids,
            seed_event_sequences=seed_event_sequences,
            investigation_windows=investigation_windows,
            attack_paths=attack_paths,
            metadata=dict(raw.get("metadata") or {}),
        )


@dataclass(slots=True)
class EvaluationMetrics:
    original_nodes: int
    kept_nodes: int
    original_edges: int
    kept_edges: int
    node_compression: float
    edge_compression: float
    annotated_attack_nodes: int
    matched_attack_nodes: int
    annotated_attack_edges: int
    matched_attack_edges: int
    attack_node_coverage: float | None
    attack_edge_coverage: float | None
    attack_node_retention: float | None
    attack_edge_retention: float | None
    attack_reachability: float | None
    annotated_attack_paths: int
    matched_attack_paths: int
    attack_path_coverage: float | None
    attack_path_retention: float | None


def _safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def _optional_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def build_paper_main_result(
    *, scenario: str, method: str, nodes_before: int, nodes_after: int,
    events_before: int, events_after: int, attack_event_recall: float | None,
    complete_path_retention: float | None, latency_seconds: float,
) -> dict[str, object]:
    """Return one compact, publication-facing main-result row."""
    return {
        "scenario": scenario,
        "method": method,
        "nodes_before": nodes_before,
        "nodes_after": nodes_after,
        "events_before": events_before,
        "events_after": events_after,
        "event_compression_ratio": (
            1.0 - events_after / events_before if events_before else 0.0
        ),
        "attack_event_recall": attack_event_recall,
        "complete_path_retention": complete_path_retention,
        "single_run_latency_seconds": latency_seconds,
    }


def _directed_reachable_nodes(edges: Iterable[StoredEdge], seeds: set[str]) -> set[str]:
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.src, set()).add(edge.dst)
    reached = set(seeds)
    frontier = list(seeds)
    while frontier:
        node = frontier.pop()
        for neighbor in adjacency.get(node, set()):
            if neighbor not in reached:
                reached.add(neighbor)
                frontier.append(neighbor)
    return reached


def _causally_reachable_nodes(
    edges: Iterable[StoredEdge], seed_event_ids: set[str], fallback_seeds: set[str]
) -> set[str]:
    materialized = list(edges)
    alert_edges = [edge for edge in materialized if edge.event_id in seed_event_ids]
    if not alert_edges:
        return _directed_reachable_nodes(materialized, fallback_seeds)
    incoming: dict[str, list[StoredEdge]] = {}
    outgoing: dict[str, list[StoredEdge]] = {}
    for edge in materialized:
        incoming.setdefault(edge.dst, []).append(edge)
        outgoing.setdefault(edge.src, []).append(edge)
    reached: set[str] = set()
    for alert in alert_edges:
        reached.update((alert.src, alert.dst))
        backward_best: dict[str, int] = {alert.src: alert.timestamp_ns}
        backward = [(alert.src, alert.timestamp_ns)]
        while backward:
            node, anchor = backward.pop()
            for edge in incoming.get(node, []):
                if edge.timestamp_ns > anchor:
                    continue
                reached.add(edge.src)
                previous = backward_best.get(edge.src)
                if previous is None or edge.timestamp_ns > previous:
                    backward_best[edge.src] = edge.timestamp_ns
                    backward.append((edge.src, edge.timestamp_ns))
        forward_best: dict[str, int] = {alert.dst: alert.timestamp_ns}
        forward = [(alert.dst, alert.timestamp_ns)]
        while forward:
            node, anchor = forward.pop()
            for edge in outgoing.get(node, []):
                if edge.timestamp_ns < anchor:
                    continue
                reached.add(edge.dst)
                previous = forward_best.get(edge.dst)
                if previous is None or edge.timestamp_ns < previous:
                    forward_best[edge.dst] = edge.timestamp_ns
                    forward.append((edge.dst, edge.timestamp_ns))
    return reached


def compute_metrics(
    graph: Neighborhood,
    kept_edges: Iterable[StoredEdge],
    annotations: AttackAnnotations,
) -> EvaluationMetrics:
    kept_edges = list(kept_edges)
    original_nodes = set(graph.nodes)
    kept_nodes = {
        endpoint for edge in kept_edges for endpoint in (edge.src, edge.dst)
    }
    if not annotations.seed_event_ids:
        kept_nodes.update(annotations.seed_uuids & original_nodes)
    original_event_ids = {edge.event_id for edge in graph.edges}
    kept_event_ids = {edge.event_id for edge in kept_edges}
    relevant_attack_events = annotations.attack_event_ids & original_event_ids
    relevant_attack_nodes = annotations.attack_node_uuids & original_nodes
    matched_attack_paths = [
        path for path in annotations.attack_paths if set(path) <= original_event_ids
    ]
    retained_attack_paths = [
        path for path in matched_attack_paths if set(path) <= kept_event_ids
    ]
    reached = _causally_reachable_nodes(
        kept_edges,
        annotations.seed_event_ids,
        annotations.seed_uuids & original_nodes,
    )

    return EvaluationMetrics(
        original_nodes=len(original_nodes),
        kept_nodes=len(kept_nodes),
        original_edges=len(graph.edges),
        kept_edges=len(kept_edges),
        node_compression=1.0 - _safe_ratio(len(kept_nodes), len(original_nodes)),
        edge_compression=1.0 - _safe_ratio(len(kept_edges), len(graph.edges)),
        annotated_attack_nodes=len(annotations.attack_node_uuids),
        matched_attack_nodes=len(relevant_attack_nodes),
        annotated_attack_edges=len(annotations.attack_event_ids),
        matched_attack_edges=len(relevant_attack_events),
        attack_node_coverage=_optional_ratio(
            len(relevant_attack_nodes), len(annotations.attack_node_uuids)
        ),
        attack_edge_coverage=_optional_ratio(
            len(relevant_attack_events), len(annotations.attack_event_ids)
        ),
        attack_node_retention=_optional_ratio(
            len(relevant_attack_nodes & kept_nodes), len(relevant_attack_nodes)
        ),
        attack_edge_retention=_optional_ratio(
            len(relevant_attack_events & kept_event_ids), len(relevant_attack_events)
        ),
        attack_reachability=_optional_ratio(
            len(relevant_attack_nodes & reached), len(relevant_attack_nodes)
        ),
        annotated_attack_paths=len(annotations.attack_paths),
        matched_attack_paths=len(matched_attack_paths),
        attack_path_coverage=_optional_ratio(
            len(matched_attack_paths), len(annotations.attack_paths)
        ),
        attack_path_retention=_optional_ratio(
            len(retained_attack_paths), len(matched_attack_paths)
        ),
    )


class _PeakRSSMonitor:
    """Exception-safe process RSS sampler shared by one experiment call."""

    def __init__(self) -> None:
        self.process = psutil.Process()
        self.baseline_bytes = self.process.memory_info().rss
        self.peak_bytes = self.baseline_bytes
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self.stop_event.wait(0.01):
            self.sample_now()

    def sample_now(self) -> None:
        self.peak_bytes = max(self.peak_bytes, self.process.memory_info().rss)

    def __enter__(self) -> "_PeakRSSMonitor":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_event.set()
        self.thread.join(timeout=0.2)
        self.sample_now()


def _run_experiment_core(
    store: ProvenanceStore,
    annotations: AttackAnnotations,
    *,
    keep_ratios: Iterable[float],
    rarity_weight: float = 0.6,
    damping: float = 0.85,
    diffusion_mode: str = "undirected_ppr",
    path_weight: float = 0.0,
    impact_weight: float = 0.0,
    behavior_weight: float = 0.0,
    path_decay: float = 0.95,
    pruning_mode: str = "ratio",
    fusion_mode: str = "additive",
    score_mass_target: float = 0.95,
    protect_alert_edges: bool = False,
    groundtruth_annotations: (
        AttackAnnotations | Callable[[], AttackAnnotations] | None
    ) = None,
    pruning_scope: str = "auto",
    causal_search_config: CausalSearchConfig | None = None,
    merge_threshold_seconds: float = 10.0,
    data_flow_alpha: float = 1e-4,
    kmeans_restarts: int = 20,
    depimpact_random_seed: int = 0,
    behavior_min_cluster_size: int = 3,
    behavior_fallback_gap_seconds: float = 30.0,
    embedding_dimensions: int = 32,
    minimum_token_frequency: int = 1,
    connectivity_protection: bool = False,
    use_frequency_cache: bool = False,
    use_frequency_snapshot: bool = False,
    progress_callback: Callable[[dict], None] | None = None,
    include_method_comparison: bool = True,
    poi_aggregation: str = "joint",
    previous_kept_event_ids: set[str] | None = None,
    churn_slack_ratio: float = 0.0,
    positive_score_only: bool = False,
    certificate_topology_policy: str = "strict_chain",
    score_ledger_dir: str | Path | None = None,
    high_score_threshold: float = 0.8,
    high_score_quantile: float = 0.99,
    prefix_score_accumulator: PrefixScoreAccumulator | None = None,
    include_internal_state: bool = False,
    _rss_monitor: _PeakRSSMonitor | None = None,
) -> dict:
    if pruning_scope not in {"auto", "merged", "per-alert"}:
        raise ValueError("pruning_scope must be auto, merged, or per-alert")
    if fusion_mode not in {"additive", "rdp_guard"}:
        raise ValueError("fusion_mode must be additive or rdp_guard")
    if poi_aggregation not in {"joint", "noisy_or"}:
        raise ValueError("poi_aggregation must be joint or noisy_or")
    if poi_aggregation == "noisy_or" and fusion_mode != "rdp_guard":
        raise ValueError("noisy_or POI aggregation requires rdp_guard fusion")
    if certificate_topology_policy not in {
        "strict_chain", "causal_path_cover"
    }:
        raise ValueError(
            "certificate_topology_policy must be strict_chain or "
            "causal_path_cover"
        )
    if not 0.0 < score_mass_target <= 1.0:
        raise ValueError("score_mass_target must be in (0, 1]")
    keep_ratios = tuple(float(value) for value in keep_ratios)
    if _rss_monitor is None:
        raise RuntimeError("run_experiment must own an RSS monitor")
    baseline_rss_bytes = _rss_monitor.baseline_bytes
    started = time.perf_counter()
    causal_search_config = causal_search_config or CausalSearchConfig()
    nodoze_model: NODOZEFrequencyModel | None = None
    candidate_paths: list[list[StoredEdge]] = []
    path_scores = []
    path_importance: dict[int, float] = {}
    protected_edge_ids: set[int] = set()
    effective_seeds: set[str] = set()
    matched_seed_events: set[str] = set()
    analysis_mode = "legacy_node_seed"
    frequency_cutoff_ns: int | None = None
    group_contexts: list[dict] = []
    cumulative_alert_search: list[dict] = []
    edge_cache = DirectionalEdgeCache(store)
    phase_started = time.perf_counter()
    phase_seconds: dict[str, float] = {}

    def progress(stage: str, **details: object) -> None:
        if progress_callback is not None:
            progress_callback({"stage": stage, **details})

    if annotations.seed_event_ids:
        alert_edges = [
            edge
            for event_id in annotations.seed_event_ids
            if (edge := store.get_edge_by_event_id(event_id)) is not None
        ]
        if alert_edges:
            frequency_cutoff_ns = min(edge.timestamp_ns for edge in alert_edges)
        snapshot = None
        if use_frequency_snapshot:
            cutoff_day = int(frequency_cutoff_ns or 0) // 86_400_000_000_000
            snapshot_path = default_snapshot_path(store.path, cutoff_day)
            if not snapshot_path.is_file():
                raise RuntimeError(
                    f"missing frequency snapshot {snapshot_path}; run "
                    f"compile-frequency-snapshot --before-timestamp-ns {frequency_cutoff_ns}"
                )
            snapshot = load_snapshot(snapshot_path)
            if snapshot.cutoff_day_exclusive != cutoff_day:
                raise RuntimeError("frequency snapshot cutoff does not match the POI day")
            nodoze_model = snapshot.nodoze
        else:
            nodoze_model = (
            NODOZEFrequencyModel.from_cache(
                store, before_timestamp_ns=frequency_cutoff_ns
            )
            if use_frequency_cache
            else NODOZEFrequencyModel.from_store(
                store, before_timestamp_ns=frequency_cutoff_ns
            )
        )
        phase_seconds["frequency_model_load"] = time.perf_counter() - phase_started
        progress("frequency_model_loaded", seconds=phase_seconds["frequency_model_load"])
        causal_started = time.perf_counter()
        groups = annotations.seed_event_groups or [set(annotations.seed_event_ids)]
        grouped_edges: dict[int, StoredEdge] = {}
        grouped_nodes = {}
        group_ids = annotations.seed_event_group_ids or [
            "all-alerts" if len(groups) == 1 else f"group-{index + 1}"
            for index in range(len(groups))
        ]
        group_sequences = (
            annotations.seed_event_sequences
            if len(annotations.seed_event_sequences) == len(groups)
            else [tuple(sorted(group)) for group in groups]
        )
        sequence_by_group = dict(zip(group_ids, group_sequences))
        if causal_search_config.seed_strategy in {
            "window_context", "window_context_expand"
        }:
            windows = []
            boundary_sources: dict[str, str] = {}
            for group_id, group in zip(group_ids, groups):
                group_alerts = [
                    edge for event_id in sequence_by_group[group_id]
                    if (edge := store.get_edge_by_event_id(event_id)) is not None
                ]
                explicit_window = annotations.investigation_windows.get(group_id)
                if explicit_window is not None:
                    lower, upper = explicit_window
                    boundary_source = "explicit_manifest"
                else:
                    try:
                        lower, upper = parse_kairos_window(group_id)
                        boundary_source = "kairos_window_name"
                    except ValueError:
                        lower = min(edge.timestamp_ns for edge in group_alerts)
                        upper = max(edge.timestamp_ns for edge in group_alerts)
                        boundary_source = "mapped_alert_extent_fallback"
                boundary_sources[group_id] = boundary_source
                windows.append(InvestigationWindow(
                    group_id, lower, upper,
                    tuple(edge.event_id for edge in group_alerts),
                ))
            limits = WindowSearchLimits(
                page_size=causal_search_config.window_page_size,
                max_candidate_events=(
                    causal_search_config.resource_max_edges or 250_000
                ),
                timeout_seconds=(
                    causal_search_config.resource_timeout_seconds or 120.0
                ),
                memory_limit_mb=causal_search_config.resource_memory_mb,
                cache_max_blocks=causal_search_config.cache_max_blocks,
            )
            window_result = build_window_context(store, windows, limits)
            if causal_search_config.seed_strategy == "window_context_expand":
                directions = (
                    ("backward", "forward")
                    if causal_search_config.expansion_direction == "both"
                    else (causal_search_config.expansion_direction,)
                )
                for direction in directions:
                    window_result = expand_window_context(
                        store, window_result, windows, direction=direction,
                        limits=limits,
                        completion_span_seconds=(
                            causal_search_config.completion_span_seconds
                        ),
                        block_seconds=causal_search_config.cache_block_seconds,
                        max_states=(
                            causal_search_config.resource_max_states or 100_000
                        ),
                    )
                    if window_result.diagnostics.incomplete:
                        break
            grouped_edges.update({
                edge.edge_id: edge for edge in window_result.graph.edges
            })
            grouped_nodes.update(window_result.graph.nodes)
            matched_seed_events.update(
                event_id for window in windows for event_id in window.alert_event_ids
            )
            effective_seeds.update(
                event_investigation_anchor(edge) for edge in alert_edges
            )
            for window in windows:
                local_edges = [
                    edge for edge in window_result.graph.edges
                    if window.start_ns <= edge.timestamp_ns <= window.end_ns
                ]
                local_graph = store.neighborhood_from_edges(local_edges)
                local_alert_edges = [
                    edge for event_id in window.alert_event_ids
                    if (edge := store.get_edge_by_event_id(event_id)) is not None
                ]
                group_contexts.append({
                    "group_id": window.group_id,
                    "seed_event_ids": set(window.alert_event_ids),
                    "ordered_seed_event_ids": tuple(window.alert_event_ids),
                    "alert_edges": local_alert_edges,
                    "graph": local_graph,
                    "seed_uuids": {
                        event_investigation_anchor(edge)
                        for edge in local_alert_edges
                    },
                    "paths": [],
                    "alert_event_ids": set(window.alert_event_ids),
                    "search_diagnostics": asdict(window_result.diagnostics),
                    "excluded_event_reasons": {},
                })
            cumulative_alert_search = [
                {
                    "group_id": window.group_id,
                    "alert_event_count": len(window.alert_event_ids),
                    "window_start_ns": window.start_ns,
                    "window_end_ns": window.end_ns,
                    "window_event_count": window_result.window_event_counts.get(
                        window.group_id, 0
                    ),
                    "boundary_source": boundary_sources[window.group_id],
                }
                for window in windows
            ]
            analysis_mode = causal_search_config.seed_strategy
            contexts = []
        elif causal_search_config.seed_strategy == "kairos_forward_cumulative":
            cumulative = build_cumulative_forward_contexts(
                store, list(zip(group_ids, groups)), nodoze_model,
                causal_search_config, edge_cache=edge_cache,
            )
            context_by_group = {
                step.group_id: step for step in cumulative.steps
            }
            contexts = [
                (group_id, group, cumulative.context, context_by_group.get(group_id))
                for group_id, group in zip(group_ids, groups)
                if group_id in context_by_group
            ]
            grouped_edges.update({
                edge.edge_id: edge for edge in cumulative.context.graph.edges
            })
            grouped_nodes.update(cumulative.context.graph.nodes)
            candidate_paths.extend(cumulative.context.paths)
            matched_seed_events.update(cumulative.context.alert_event_ids)
            cumulative_alert_search = [
                {
                    "group_id": step.group_id,
                    "alert_event_ids": list(step.alert_event_ids),
                    "alert_time_ns": step.alert_time_ns,
                    "local_event_count": len(step.graph.edges),
                    "new_event_count": step.new_event_count,
                    "overlap_event_count": step.overlap_event_count,
                    "cumulative_event_count": step.cumulative_event_count,
                    "complete_path_count": step.complete_path_count,
                    "truncated_path_count": step.truncated_path_count,
                    "termination_reasons": step.termination_reasons,
                }
                for step in cumulative.steps
            ]
            analysis_mode = "kairos_forward_cumulative"
        else:
            contexts = []
            globally_budgeted_edges: set[int] = set()
            for group_id, group in zip(group_ids, groups):
                group_search_config = causal_search_config
                if causal_search_config.resource_max_edges is not None:
                    remaining = max(
                        1,
                        causal_search_config.resource_max_edges
                        - len(globally_budgeted_edges),
                    )
                    group_search_config = replace(
                        causal_search_config, resource_max_edges=remaining
                    )
                context = build_alert_context(
                    store, group, nodoze_model, group_search_config,
                    edge_cache=edge_cache,
                )
                globally_budgeted_edges.update(
                    edge.edge_id for edge in context.graph.edges
                )
                contexts.append((group_id, group, context, None))

        for group_id, group, context, cumulative_step in contexts:
            context_graph = cumulative_step.graph if cumulative_step else context.graph
            grouped_edges.update({edge.edge_id: edge for edge in context.graph.edges})
            grouped_nodes.update(context.graph.nodes)
            if cumulative_step is None:
                candidate_paths.extend(context.paths)
                matched_seed_events.update(context.alert_event_ids)
            group_alert_edges = [
                edge
                for event_id in sequence_by_group[group_id]
                if (edge := store.get_edge_by_event_id(event_id)) is not None
            ]
            poi_seeds = {
                event_investigation_anchor(edge) for edge in group_alert_edges
            }
            effective_seeds.update(poi_seeds)
            group_contexts.append(
                {
                    "group_id": group_id,
                    "seed_event_ids": set(group),
                    "ordered_seed_event_ids": sequence_by_group[group_id],
                    "alert_edges": group_alert_edges,
                    "graph": context_graph,
                    "seed_uuids": poi_seeds,
                    "paths": list(context.paths),
                    "alert_event_ids": set(context.alert_event_ids),
                    "search_diagnostics": {
                        "complete_path_count": (
                            cumulative_step.complete_path_count if cumulative_step
                            else context.complete_path_count
                        ),
                        "truncated_path_count": (
                            cumulative_step.truncated_path_count if cumulative_step
                            else context.truncated_path_count
                        ),
                        "termination_reasons": (
                            cumulative_step.termination_reasons if cumulative_step
                            else context.termination_reasons
                        ),
                    },
                    "excluded_event_reasons": dict(context.excluded_event_reasons),
                }
            )
        graph = Neighborhood(grouped_nodes, list(grouped_edges.values()))
        if protect_alert_edges:
            protected_edge_ids = {
                edge.edge_id
                for edge in graph.edges
                if edge.event_id in matched_seed_events
            }
        nodoze_scoring_started = time.perf_counter()
        scoring = nodoze_model.score_paths(
            candidate_paths,
            decay=path_decay,
            excluded_event_ids=matched_seed_events,
        )
        path_scores = scoring.path_scores
        path_importance = scoring.edge_importance
        phase_seconds["nodoze_path_scoring"] = (
            time.perf_counter() - nodoze_scoring_started
        )
        if causal_search_config.seed_strategy == "poi_bidirectional":
            analysis_mode = "nodoze_hybrid"
        phase_seconds["causal_search_and_candidate_build"] = (
            time.perf_counter() - causal_started
        )
        progress(
            "candidate_graph_built", seconds=phase_seconds["causal_search_and_candidate_build"],
            candidate_events=len(graph.edges), candidate_nodes=len(graph.nodes),
        )
        if (
            causal_search_config.seed_strategy in {
                "window_context", "window_context_expand"
            }
            and window_result.diagnostics.incomplete
        ):
            return {
                "annotation_name": annotations.name,
                "analysis_mode": causal_search_config.seed_strategy,
                "incomplete": True,
                "completion_status": "candidate_construction_truncated",
                "candidate_construction": asdict(window_result.diagnostics),
                "candidate_event_ids": sorted(
                    edge.event_id for edge in graph.edges
                ),
                "candidate_edge_count": len(graph.edges),
                "candidate_node_count": len(graph.nodes),
                "scoring_and_pruning_skipped": True,
                "phase_seconds": phase_seconds,
            }
    else:
        raise ValueError(
            "suspicion-guided causal search requires seed_event_ids; "
            "node-only seeds have no event direction or timestamp"
        )

    rarity_started = time.perf_counter()
    model = snapshot.rarity if use_frequency_snapshot and snapshot is not None else (
        FrequencyModel.from_cache(store, before_timestamp_ns=frequency_cutoff_ns)
        if use_frequency_cache
        else FrequencyModel.from_store(store, before_timestamp_ns=frequency_cutoff_ns)
    )
    rarity = {edge.edge_id: model.edge_rarity(edge) for edge in graph.edges}
    phase_seconds["rarity_lookup"] = time.perf_counter() - rarity_started
    progress("rarity_scored", seconds=phase_seconds["rarity_lookup"])
    matched_poi_edges = [
        edge for edge in graph.edges if edge.event_id in matched_seed_events
    ]
    poi_edge_ids = {edge.edge_id for edge in matched_poi_edges}
    poi_edge_id_by_event = {
        edge.event_id: edge.edge_id for edge in matched_poi_edges
    }
    ordered_poi_edge_sequences = tuple(
        tuple(
            poi_edge_id_by_event[event_id]
            for event_id in item["ordered_seed_event_ids"]
            if event_id in poi_edge_id_by_event
        )
        for item in group_contexts
        if item["ordered_seed_event_ids"]
    )
    ordered_poi_edge_ids = (
        ordered_poi_edge_sequences[0]
        if len(ordered_poi_edge_sequences) == 1 else None
    )
    active_ordered_path_cover = (
        ordered_poi_edge_sequences
        if certificate_topology_policy == "causal_path_cover"
        else ((ordered_poi_edge_ids,) if ordered_poi_edge_ids else ())
    )
    score_override: dict[int, float] | None = None
    score_components_override: dict[int, dict[str, float]] | None = None
    score_provenance: dict[int, dict[str, object]] = {}
    aggregate_score_state: PrefixAggregateScores | None = None
    active_prefix_accumulator: PrefixScoreAccumulator | None = None
    poi_local_scoring: list[dict[str, object]] = []
    table8_method_node_scores: dict[str, dict[str, float]] = {}
    table7_depimpact_timings: dict[str, dict[str, float]] = {}
    if poi_aggregation == "noisy_or":
        active_prefix_accumulator = (
            prefix_score_accumulator or PrefixScoreAccumulator()
        )
        prefix_context_payload = {
            "schema": "prefix-score-context-v1",
            "candidate_graph_sha256": candidate_graph_digest(graph),
            "rarity_sha256": score_map_digest(rarity),
            "path_importance_sha256": score_map_digest(path_importance),
            "parameters": {
                "rarity_weight": rarity_weight,
                "path_weight": path_weight,
                "impact_weight": impact_weight,
                "behavior_weight": behavior_weight,
                "path_decay": path_decay,
                "damping": damping,
                "diffusion_mode": diffusion_mode,
                "fusion_mode": fusion_mode,
                "merge_threshold_seconds": merge_threshold_seconds,
                "data_flow_alpha": data_flow_alpha,
                "kmeans_restarts": kmeans_restarts,
                "depimpact_random_seed": depimpact_random_seed,
                "behavior_min_cluster_size": behavior_min_cluster_size,
                "behavior_fallback_gap_seconds": behavior_fallback_gap_seconds,
                "embedding_dimensions": embedding_dimensions,
                "minimum_token_frequency": minimum_token_frequency,
            },
        }
        prefix_context_digest = hashlib.sha256(
            json.dumps(
                prefix_context_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        active_prefix_accumulator.bind_context(prefix_context_digest)
        if (
            active_prefix_accumulator.edge_ids
            and active_prefix_accumulator.edge_ids != frozenset(rarity)
        ):
            raise ValueError("prefix score state does not match the candidate graph")
        declared_order = list(dict.fromkeys(
            event_id
            for sequence in annotations.seed_event_sequences
            for event_id in sequence
        ))
        ordered_local_pois = [
            next(edge for edge in matched_poi_edges if edge.event_id == event_id)
            for event_id in declared_order
            if event_id in poi_edge_id_by_event
        ]
        ordered_local_pois.extend(sorted(
            (
                edge for edge in matched_poi_edges
                if edge.event_id not in set(declared_order)
            ),
            key=lambda edge: (edge.timestamp_ns, edge.event_id),
        ))
        if not active_prefix_accumulator.poi_event_ids <= {
            edge.event_id for edge in ordered_local_pois
        }:
            raise ValueError("prefix score state contains a POI outside this prefix")
        impact_seconds = 0.0
        behavior_seconds = 0.0
        diffusion_seconds = 0.0
        impact_analysis = None
        behavior_analysis = None
        diffusion = None
        for poi_edge in ordered_local_pois:
            if poi_edge.event_id in active_prefix_accumulator.poi_event_ids:
                continue
            local_started = time.perf_counter()
            local_impact = compute_depimpact_relevance(
                graph,
                poi_edge_ids={poi_edge.edge_id},
                merge_threshold_seconds=merge_threshold_seconds,
                alpha=data_flow_alpha,
                kmeans_restarts=kmeans_restarts,
                random_seed=depimpact_random_seed,
            )
            impact_seconds += time.perf_counter() - local_started
            active_prefix_accumulator.add_auxiliary_node_scores(
                poi_edge.event_id, "depimpact", local_impact.node_impacts,
                local_impact.phase_seconds,
            )
            for method, feature_mask, projection_override in (
                ("temporal_only", (False, True, False), None),
                ("temporal_data", (True, True, False), None),
                ("fixed_projection", (True, True, True), (0.334, 0.333, 0.333)),
            ):
                baseline = compute_depimpact_relevance(
                    graph,
                    poi_edge_ids={poi_edge.edge_id},
                    merge_threshold_seconds=merge_threshold_seconds,
                    alpha=data_flow_alpha,
                    kmeans_restarts=kmeans_restarts,
                    random_seed=depimpact_random_seed,
                    feature_mask=feature_mask,
                    projection_override=projection_override,
                )
                active_prefix_accumulator.add_auxiliary_node_scores(
                    poi_edge.event_id, method, baseline.node_impacts,
                    baseline.phase_seconds,
                )
            local_started = time.perf_counter()
            local_behavior = analyze_behaviors(
                graph,
                poi_edge_ids={poi_edge.edge_id},
                min_cluster_size=behavior_min_cluster_size,
                fallback_gap_seconds=behavior_fallback_gap_seconds,
                embedding_dimensions=embedding_dimensions,
                minimum_token_frequency=minimum_token_frequency,
            )
            behavior_seconds += time.perf_counter() - local_started
            local_started = time.perf_counter()
            local_diffusion = diffuse_importance(
                graph,
                {event_investigation_anchor(poi_edge)},
                rarity,
                edge_affinity=local_impact.edge_importance,
                damping=damping,
                mode=diffusion_mode,
                seed_edges=[poi_edge],
            )
            diffusion_seconds += time.perf_counter() - local_started
            local_edge_diffusion = {
                edge.edge_id: (
                    local_diffusion.edge_scores.get(edge.edge_id, 0.0)
                    if local_diffusion.edge_scores
                    else max(
                        local_diffusion.scores.get(edge.src, 0.0),
                        local_diffusion.scores.get(edge.dst, 0.0),
                    )
                )
                for edge in graph.edges
            }
            local_fused = fuse_rarity_diffusion(
                rarity,
                rarity=rarity,
                diffusion=local_edge_diffusion,
                rarity_weight=rarity_weight,
                path=path_importance,
                path_weight=path_weight,
                impact=local_impact.edge_importance,
                impact_weight=impact_weight,
                behavior=local_behavior.edge_importance,
                behavior_weight=behavior_weight,
            )
            active_prefix_accumulator.add(poi_edge.event_id, local_fused)
            impact_analysis = local_impact
            behavior_analysis = local_behavior
            diffusion = local_diffusion
            poi_local_scoring.append({
                "poi_event_id": poi_edge.event_id,
                "poi_edge_id": poi_edge.edge_id,
                "score_digest": active_prefix_accumulator.local_score_digests[
                    poi_edge.event_id
                ],
                "nonzero_edge_count": sum(
                    value > 0.0 for value in local_fused.scores.values()
                ),
                "depimpact_projection": list(local_impact.projection),
                "depimpact_iterations": local_impact.propagation_iterations,
                "diffusion_iterations": local_diffusion.iterations,
                "diffusion_converged": local_diffusion.converged,
            })
            progress(
                "poi_local_score_complete",
                poi_event_id=poi_edge.event_id,
                nonzero_edges=poi_local_scoring[-1]["nonzero_edge_count"],
            )
        aggregate_score_state = active_prefix_accumulator.finalize()
        score_override = aggregate_score_state.scores
        score_components_override = aggregate_score_state.components
        score_provenance = aggregate_score_state.provenance
        # A sequential sweep always contributes one new POI. A caller that
        # reuses an already complete state must recompute lightweight display
        # diagnostics explicitly instead of silently showing stale metadata.
        if impact_analysis is None or behavior_analysis is None or diffusion is None:
            raise ValueError("prefix score state contains no new POI to score")
        phase_seconds["edge_merge_weight_and_backward_impact"] = impact_seconds
        phase_seconds["behavior_feature_extraction"] = behavior_seconds
        phase_seconds["poi_conditioned_diffusion"] = diffusion_seconds
        table8_method_node_scores = (
            active_prefix_accumulator.aggregate_auxiliary_node_scores()
        )
        table7_depimpact_timings = (
            active_prefix_accumulator.auxiliary_phase_seconds
        )
        effective_pruning_scope = "prefix_stable_noisy_or"
    else:
        impact_started = time.perf_counter()
        impact_analysis = compute_depimpact_relevance(
            graph,
            poi_edge_ids=poi_edge_ids,
            merge_threshold_seconds=merge_threshold_seconds,
            alpha=data_flow_alpha,
            kmeans_restarts=kmeans_restarts,
            random_seed=depimpact_random_seed,
        )
        phase_seconds["edge_merge_weight_and_backward_impact"] = (
            time.perf_counter() - impact_started
        )
        progress("depimpact_scored", seconds=phase_seconds["edge_merge_weight_and_backward_impact"])
        table8_method_node_scores["depimpact"] = impact_analysis.node_impacts
        table7_depimpact_timings["depimpact"] = impact_analysis.phase_seconds
        for method, feature_mask, projection_override in (
            ("temporal_only", (False, True, False), None),
            ("temporal_data", (True, True, False), None),
            ("fixed_projection", (True, True, True), (0.334, 0.333, 0.333)),
        ):
            baseline = compute_depimpact_relevance(
                graph,
                poi_edge_ids=poi_edge_ids,
                merge_threshold_seconds=merge_threshold_seconds,
                alpha=data_flow_alpha,
                kmeans_restarts=kmeans_restarts,
                random_seed=depimpact_random_seed,
                feature_mask=feature_mask,
                projection_override=projection_override,
            )
            table8_method_node_scores[method] = baseline.node_impacts
            table7_depimpact_timings[method] = baseline.phase_seconds
        behavior_started = time.perf_counter()
        behavior_analysis = analyze_behaviors(
            graph,
            poi_edge_ids=poi_edge_ids,
            min_cluster_size=behavior_min_cluster_size,
            fallback_gap_seconds=behavior_fallback_gap_seconds,
            embedding_dimensions=embedding_dimensions,
            minimum_token_frequency=minimum_token_frequency,
        )
        phase_seconds["behavior_feature_extraction"] = (
            time.perf_counter() - behavior_started
        )
        progress("behavior_scored", seconds=phase_seconds["behavior_feature_extraction"])
        diffusion_started = time.perf_counter()
        diffusion = diffuse_importance(
            graph,
            effective_seeds,
            rarity,
            edge_affinity=impact_analysis.edge_importance,
            damping=damping,
            mode=diffusion_mode,
            seed_edges=matched_poi_edges,
        )
        phase_seconds["poi_conditioned_diffusion"] = (
            time.perf_counter() - diffusion_started
        )
        progress("diffusion_complete", seconds=phase_seconds["poi_conditioned_diffusion"])
        effective_pruning_scope = (
            "merged_candidate_graph"
            if causal_search_config.seed_strategy in {
                "kairos_forward_cumulative", "window_context", "window_context_expand"
            }
            else
            "per_alert_group"
            if pruning_scope == "per-alert"
            or (pruning_scope == "auto" and len(group_contexts) > 1)
            else "merged_graph"
        )
    group_pruning_inputs = []
    per_poi_analysis_started = time.perf_counter()
    if effective_pruning_scope == "per_alert_group":
        for item in group_contexts:
            local_rarity = {
                edge.edge_id: rarity[edge.edge_id]
                for edge in item["graph"].edges
            }
            local_poi_ids = {
                edge.edge_id
                for edge in item["alert_edges"]
                if edge.edge_id in local_rarity
            }
            local_impact = compute_depimpact_relevance(
                item["graph"],
                poi_edge_ids=local_poi_ids,
                merge_threshold_seconds=merge_threshold_seconds,
                alpha=data_flow_alpha,
                kmeans_restarts=kmeans_restarts,
                random_seed=depimpact_random_seed,
            )
            local_diffusion = diffuse_importance(
                item["graph"],
                item["seed_uuids"],
                local_rarity,
                edge_affinity=local_impact.edge_importance,
                damping=damping,
                mode=diffusion_mode,
                seed_edges=item["alert_edges"],
            )
            local_behavior = analyze_behaviors(
                item["graph"],
                poi_edge_ids=local_poi_ids,
                min_cluster_size=behavior_min_cluster_size,
                fallback_gap_seconds=behavior_fallback_gap_seconds,
                embedding_dimensions=embedding_dimensions,
                minimum_token_frequency=minimum_token_frequency,
            )
            local_path_importance = {}
            if nodoze_model is not None:
                local_path_importance = nodoze_model.score_paths(
                    item["paths"],
                    decay=path_decay,
                    excluded_event_ids=item["alert_event_ids"],
                ).edge_importance
            local_protected = (
                {
                    edge.edge_id
                    for edge in item["graph"].edges
                    if edge.event_id in item["alert_event_ids"]
                }
                if protect_alert_edges
                else set()
            )
            group_pruning_inputs.append(
                {
                    **item,
                    "rarity": local_rarity,
                    "diffusion": local_diffusion,
                    "path_importance": local_path_importance,
                    "impact": local_impact,
                    "behavior": local_behavior,
                    "protected_edge_ids": local_protected,
                    "poi_edge_ids": local_poi_ids,
                    "ordered_poi_edge_ids": tuple(
                        poi_edge_id_by_event[event_id]
                        for event_id in item["ordered_seed_event_ids"]
                        if event_id in poi_edge_id_by_event
                    ),
                }
            )
    phase_seconds["per_poi_merge_features_impact_diffusion"] = (
        time.perf_counter() - per_poi_analysis_started
    )
    rows = []
    aligned_rows = []
    pruning_outputs: list[tuple[float, PruningResult, list[dict]]] = []
    ledger_scores: dict[int, float] | None = None
    ledger_components: dict[int, dict[str, float]] | None = None
    ledger_decisions: dict[str, dict[int, tuple[str, ...]]] = {}
    previous_kept_edge_ids = {
        edge.edge_id
        for edge in graph.edges
        if edge.event_id in set(previous_kept_event_ids or set())
    } if previous_kept_event_ids is not None else None
    pruning_started = time.perf_counter()
    for keep_ratio in keep_ratios:
        progress("pruning_started", keep_ratio=keep_ratio)
        group_pruning_rows = []
        if effective_pruning_scope == "per_alert_group":
            group_score_accumulator = PrefixScoreAccumulator(
                require_same_edge_ids=False
            )
            thresholds = []
            for item in group_pruning_inputs:
                local = adaptive_prune(
                    item["graph"],
                    item["rarity"],
                    item["diffusion"],
                    seeds=item["seed_uuids"],
                    keep_ratio=keep_ratio,
                    rarity_weight=rarity_weight,
                    path_importance=item["path_importance"],
                    path_weight=path_weight,
                    impact_importance=item["impact"].edge_importance,
                    impact_weight=impact_weight,
                    behavior_importance=item["behavior"].edge_importance,
                    behavior_weight=behavior_weight,
                    protected_edge_ids=item["protected_edge_ids"],
                    selection_mode=pruning_mode,
                    protect_seed_incident_edges=False,
                    atomic_edge_groups=item["impact"].merge_groups,
                    connectivity_target_edge_ids=(
                        item["poi_edge_ids"]
                        if connectivity_protection and not item["ordered_poi_edge_ids"]
                        else None
                    ),
                    ordered_connectivity_edge_ids=(
                        item["ordered_poi_edge_ids"]
                        if connectivity_protection else None
                    ),
                    certificate_poi_edge_ids=item["poi_edge_ids"],
                    certificate_expected_poi_count=len(item["seed_event_ids"]),
                    fusion_mode=fusion_mode,
                )
                group_score_accumulator.add(
                    str(item["group_id"]),
                    RDPGuardScores(
                        scores=local.edge_scores,
                        components=local.edge_score_components or {},
                    ),
                )
                thresholds.append(local.threshold)
                group_pruning_rows.append(
                    {
                        "group_id": item["group_id"],
                        "original_edges": len(item["graph"].edges),
                        "kept_edges": len(local.kept_edges),
                        "requested_keep_ratio": keep_ratio,
                        "actual_keep_ratio": local.actual_keep_ratio,
                        "threshold": local.threshold,
                        "diffusion_iterations": item["diffusion"].iterations,
                        "diffusion_converged": item["diffusion"].converged,
                        "depimpact_original_edges": item["impact"].original_edge_count,
                        "depimpact_merged_edges": item["impact"].merged_edge_count,
                        "data_size_coverage": item["impact"].data_size_coverage,
                        "behavior_cluster_count": item["behavior"].cluster_count,
                        "behavior_backend": item["behavior"].backend,
                        "search_diagnostics": item["search_diagnostics"],
                        "connectivity_added_edges": local.connectivity_added_edges,
                        "budget_edges": local.budget_edges,
                        "minimum_required_edges": local.minimum_required_edges,
                        "budget_feasible": local.budget_feasible,
                        "budget_overflow_edges": local.budget_overflow_edges,
                        "stage_pairs": local.stage_pairs,
                        "connected_stage_pairs": local.connected_stage_pairs,
                        "retained_stage_pairs": local.retained_stage_pairs,
                        "scoring_mode": local.scoring_mode,
                        "score_mass_retained": local.score_mass_retained,
                        "certificate_poi_edges": local.certificate_poi_edges,
                        "certificate_retained_poi_edges": (
                            local.certificate_retained_poi_edges
                        ),
                        "path_certificate_valid": local.path_certificate_valid,
                        "selection_candidate_edges_examined": (
                            local.selection_candidate_edges_examined
                        ),
                        "selection_stage": "local_proposal_before_global_budget",
                    }
                )
            group_aggregate = group_score_accumulator.finalize()
            combined_scores = group_aggregate.scores
            combined_components = group_aggregate.components
            score_provenance = group_aggregate.provenance
            # Per-POI proposals share events, so independent local rounding can
            # exceed the experiment's global raw-event budget. Consolidate the
            # proposals once on the union graph; local scores remain the signal,
            # while atomic groups and causal bridges are charged globally.
            consolidated = adaptive_prune(
                graph,
                combined_scores,
                diffusion,
                seeds=effective_seeds,
                keep_ratio=keep_ratio,
                rarity_weight=1.0,
                protected_edge_ids=protected_edge_ids,
                selection_mode=(
                    "rdp_guard" if pruning_mode == "rdp_guard" else "ratio"
                ),
                protect_seed_incident_edges=False,
                atomic_edge_groups=impact_analysis.merge_groups,
                connectivity_target_edge_ids=(
                    poi_edge_ids
                    if connectivity_protection and not active_ordered_path_cover
                    else None
                ),
                ordered_connectivity_edge_sequences=(
                    active_ordered_path_cover
                    if connectivity_protection else None
                ),
                certificate_poi_edge_ids=poi_edge_ids,
                certificate_expected_poi_count=len(annotations.seed_event_ids),
                previous_kept_edge_ids=previous_kept_edge_ids,
                churn_slack_ratio=churn_slack_ratio,
                positive_score_only=positive_score_only,
            )
            union_kept = consolidated.kept_edges
            pruned = PruningResult(
                kept_edges=union_kept,
                edge_scores=combined_scores,
                threshold=min(thresholds, default=1.0),
                requested_keep_ratio=keep_ratio,
                actual_keep_ratio=(
                    len(union_kept) / len(graph.edges) if graph.edges else 0.0
                ),
                selection_mode=pruning_mode,
                edge_score_components=combined_components,
                connectivity_added_edges=consolidated.connectivity_added_edges,
                budget_edges=consolidated.budget_edges,
                budget_rounding_policy=consolidated.budget_rounding_policy,
                minimum_required_edges=consolidated.minimum_required_edges,
                budget_feasible=consolidated.budget_feasible,
                budget_overflow_edges=consolidated.budget_overflow_edges,
                stage_pairs=consolidated.stage_pairs,
                connected_stage_pairs=consolidated.connected_stage_pairs,
                retained_stage_pairs=consolidated.retained_stage_pairs,
                selection_candidate_edges_examined=(
                    consolidated.selection_candidate_edges_examined
                ),
                scoring_mode=fusion_mode,
                score_mass_retained=consolidated.score_mass_retained,
                certificate_poi_edges=consolidated.certificate_poi_edges,
                certificate_retained_poi_edges=(
                    consolidated.certificate_retained_poi_edges
                ),
                path_certificate_valid=consolidated.path_certificate_valid,
                path_certificate_status=consolidated.path_certificate_status,
                strict_multistage_certificate_valid=(
                    consolidated.strict_multistage_certificate_valid
                ),
                causal_path_cover_certificate_valid=(
                    consolidated.causal_path_cover_certificate_valid
                ),
                certificate_topology=consolidated.certificate_topology,
                certificate_branch_count=consolidated.certificate_branch_count,
                candidate_disconnected_stage_pairs=(
                    consolidated.candidate_disconnected_stage_pairs
                ),
                stage_path_witnesses=consolidated.stage_path_witnesses,
                edge_selection_reasons=consolidated.edge_selection_reasons,
                previous_candidate_edges=consolidated.previous_candidate_edges,
                retained_previous_edges=consolidated.retained_previous_edges,
                added_edges=consolidated.added_edges,
                removed_previous_edges=consolidated.removed_previous_edges,
                declared_allowed_removed_previous_edges=(
                    consolidated.declared_allowed_removed_previous_edges
                ),
                allowed_removed_previous_edges=(
                    consolidated.allowed_removed_previous_edges
                ),
                budget_contraction_edges=consolidated.budget_contraction_edges,
                atomicity_churn_slack_edges=(
                    consolidated.atomicity_churn_slack_edges
                ),
                churn_bound_satisfied=consolidated.churn_bound_satisfied,
                churn_constraint_status=consolidated.churn_constraint_status,
                prefix_jaccard=consolidated.prefix_jaccard,
                unused_budget_edges=consolidated.unused_budget_edges,
                zero_score_fill_stopped=consolidated.zero_score_fill_stopped,
            )
        else:
            pruned = adaptive_prune(
                graph,
                rarity,
                diffusion,
                seeds=effective_seeds,
                keep_ratio=keep_ratio,
                rarity_weight=rarity_weight,
                path_importance=path_importance,
                path_weight=path_weight,
                impact_importance=impact_analysis.edge_importance,
                impact_weight=impact_weight,
                behavior_importance=behavior_analysis.edge_importance,
                behavior_weight=behavior_weight,
                protected_edge_ids=protected_edge_ids,
                selection_mode=pruning_mode,
                protect_seed_incident_edges=not bool(annotations.seed_event_ids),
                atomic_edge_groups=impact_analysis.merge_groups,
                connectivity_target_edge_ids=(
                    poi_edge_ids
                    if connectivity_protection and not active_ordered_path_cover
                    else None
                ),
                ordered_connectivity_edge_sequences=(
                    active_ordered_path_cover
                    if connectivity_protection else None
                ),
                certificate_poi_edge_ids=poi_edge_ids,
                certificate_expected_poi_count=len(annotations.seed_event_ids),
                fusion_mode=fusion_mode,
                edge_scores_override=score_override,
                edge_score_components_override=score_components_override,
                previous_kept_edge_ids=previous_kept_edge_ids,
                churn_slack_ratio=churn_slack_ratio,
                positive_score_only=positive_score_only,
            )
        pruning_outputs.append((keep_ratio, pruned, group_pruning_rows))
        if ledger_scores is None:
            ledger_scores = pruned.edge_scores
            ledger_components = pruned.edge_score_components or {}
        elif pruned.edge_scores != ledger_scores:
            raise RuntimeError("edge scores changed across raw-event budgets")
        budget_key = format(float(keep_ratio), ".12g")
        ledger_decisions[budget_key] = {
            edge.edge_id: tuple(
                (pruned.edge_selection_reasons or {}).get(edge.edge_id, ())
            )
            for edge in pruned.kept_edges
        }
        progress("pruning_complete", keep_ratio=keep_ratio, kept_edges=len(pruned.kept_edges))

    # Ground truth is an offline-only evaluation input.  All primary online
    # scores and pruning decisions are frozen before either its annotations are
    # dereferenced or its event IDs are looked up in SQLite.  This prevents
    # label leakage as well as ground-truth-dependent database cache warming.
    phase_seconds["online_pruning_selection"] = time.perf_counter() - pruning_started
    offline_evaluation_started = time.perf_counter()
    evaluation_truth = (
        groundtruth_annotations()
        if callable(groundtruth_annotations)
        else groundtruth_annotations or annotations
    )
    if not isinstance(evaluation_truth, AttackAnnotations):
        raise TypeError("groundtruth provider must return AttackAnnotations")
    effective_annotations = AttackAnnotations(
        name=annotations.name,
        seed_uuids=effective_seeds,
        attack_event_ids=evaluation_truth.attack_event_ids,
        attack_node_uuids=evaluation_truth.attack_node_uuids,
        seed_event_ids=annotations.seed_event_ids,
        seed_event_groups=annotations.seed_event_groups,
        seed_event_group_ids=annotations.seed_event_group_ids,
        seed_event_sequences=annotations.seed_event_sequences,
        investigation_windows=annotations.investigation_windows,
        attack_paths=evaluation_truth.attack_paths,
    )
    groundtruth_edges = [
        edge
        for event_id in evaluation_truth.attack_event_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    table8_entry_ranks = evaluate_entry_ranks(
        graph,
        method_node_scores=table8_method_node_scores,
        attack_entry_nodes=discover_attack_entries(
            graph, evaluation_truth.attack_node_uuids
        ),
        random_seed=depimpact_random_seed,
    )
    edge_event_ids = {edge.edge_id: edge.event_id for edge in graph.edges}
    candidate_edge_ids = set(edge_event_ids)

    for keep_ratio, pruned, group_pruning_rows in pruning_outputs:
        metrics = compute_metrics(graph, pruned.kept_edges, effective_annotations)
        row = asdict(metrics)
        reconstructed = reconstruct_retained_paths(
            candidate_paths,
            pruned.kept_edges,
            [score.anomaly for score in path_scores],
            max_paths=None,
        )
        row.update(
            {
                "requested_keep_ratio": keep_ratio,
                "actual_keep_ratio": pruned.actual_keep_ratio,
                "threshold": pruned.threshold,
                "selection_mode": pruned.selection_mode,
                "budget_edges": pruned.budget_edges,
                "budget_rounding_policy": pruned.budget_rounding_policy,
                "minimum_required_edges": pruned.minimum_required_edges,
                "budget_feasible": pruned.budget_feasible,
                "budget_overflow_edges": pruned.budget_overflow_edges,
                "stage_pairs": pruned.stage_pairs,
                "connected_stage_pairs": pruned.connected_stage_pairs,
                "retained_stage_pairs": pruned.retained_stage_pairs,
                "scoring_mode": pruned.scoring_mode,
                "score_mass_retained": pruned.score_mass_retained,
                "heuristic_utility_retained": pruned.score_mass_retained,
                "certificate_poi_edges": pruned.certificate_poi_edges,
                "certificate_retained_poi_edges": (
                    pruned.certificate_retained_poi_edges
                ),
                "path_certificate_valid": pruned.path_certificate_valid,
                "path_certificate_status": pruned.path_certificate_status,
                "strict_multistage_certificate_valid": (
                    pruned.strict_multistage_certificate_valid
                ),
                "causal_path_cover_certificate_valid": (
                    pruned.causal_path_cover_certificate_valid
                ),
                "certificate_topology": pruned.certificate_topology,
                "certificate_branch_count": pruned.certificate_branch_count,
                "candidate_disconnected_stage_pairs": (
                    pruned.candidate_disconnected_stage_pairs
                ),
                "stage_path_witnesses": pruned.stage_path_witnesses,
                "previous_candidate_edges": pruned.previous_candidate_edges,
                "retained_previous_edges": pruned.retained_previous_edges,
                "added_edges": pruned.added_edges,
                "removed_previous_edges": pruned.removed_previous_edges,
                "declared_allowed_removed_previous_edges": (
                    pruned.declared_allowed_removed_previous_edges
                ),
                "allowed_removed_previous_edges": (
                    pruned.allowed_removed_previous_edges
                ),
                "budget_contraction_edges": pruned.budget_contraction_edges,
                "atomicity_churn_slack_edges": (
                    pruned.atomicity_churn_slack_edges
                ),
                "churn_bound_satisfied": pruned.churn_bound_satisfied,
                "churn_constraint_status": pruned.churn_constraint_status,
                "prefix_jaccard": pruned.prefix_jaccard,
                "unused_budget_edges": pruned.unused_budget_edges,
                "zero_score_fill_stopped": pruned.zero_score_fill_stopped,
                "selection_candidate_edges_examined": (
                    pruned.selection_candidate_edges_examined
                ),
                "kept_event_ids": sorted(edge.event_id for edge in pruned.kept_edges),
                "reconstructed_path_count": len(reconstructed),
                "reconstructed_paths": reconstructed,
                "group_pruning": group_pruning_rows,
                "scored_edge_count": len(pruned.edge_scores),
                "all_candidate_edges_scored": (
                    len(pruned.edge_scores) == len(graph.edges)
                    and set(pruned.edge_scores) == candidate_edge_ids
                ),
                "edge_score_distribution": _score_distribution(
                    pruned.edge_scores.values()
                ),
                "top_edge_scores": [
                    {
                        "edge_id": edge_id,
                        "event_id": edge_event_ids[edge_id],
                        "score": pruned.edge_scores[edge_id],
                        "components": (pruned.edge_score_components or {}).get(
                            edge_id, {}
                        ),
                    }
                    for edge_id in sorted(
                        pruned.edge_scores,
                        key=lambda item: (-pruned.edge_scores[item], item),
                    )[:100]
                ],
            }
        )
        rows.append(row)
        if groundtruth_annotations is not None and group_contexts:
            alert_rows = []
            for item in group_contexts:
                association = associate_groundtruth_components(
                    group_id=item["group_id"],
                    alert_edges=item["alert_edges"],
                    groundtruth_edges=groundtruth_edges,
                    groundtruth_node_ids=evaluation_truth.attack_node_uuids,
                )
                if association["association_status"] != "none":
                    alert_row = evaluate_alert_context(
                        candidate_graph=item["graph"],
                        kept_edges=pruned.kept_edges,
                        association=association,
                        groundtruth_edges=groundtruth_edges,
                        groundtruth_paths=evaluation_truth.attack_paths,
                    )
                else:
                    local_edge_ids = {
                        edge.edge_id for edge in item["graph"].edges
                    }
                    local_kept = [
                        edge
                        for edge in pruned.kept_edges
                        if edge.edge_id in local_edge_ids
                    ]
                    alert_row = {
                        **association,
                        "candidate_nodes": len(item["graph"].nodes),
                        "candidate_edges": len(item["graph"].edges),
                        "kept_nodes": len(
                            {
                                endpoint
                                for edge in local_kept
                                for endpoint in (edge.src, edge.dst)
                            }
                        ),
                        "kept_edges": len(local_kept),
                    }
                alert_rows.append(alert_row)
            aggregate = aggregate_alert_metrics(alert_rows)
            aligned_rows.append(
                {
                    "requested_keep_ratio": keep_ratio,
                    "actual_keep_ratio": pruned.actual_keep_ratio,
                    "alerts": alert_rows,
                    "macro": aggregate["macro"],
                    "micro": aggregate["micro"],
                    "counts": aggregate["counts"],
                }
            )
    phase_seconds["offline_groundtruth_evaluation"] = (
        time.perf_counter() - offline_evaluation_started
    )
    aggregate_termination_reasons: Counter[str] = Counter()
    for item in group_contexts:
        aggregate_termination_reasons.update(
            item["search_diagnostics"]["termination_reasons"]
        )
    search_diagnostics = {
        "complete_path_count": sum(
            item["search_diagnostics"]["complete_path_count"]
            for item in group_contexts
        ),
        "truncated_path_count": sum(
            item["search_diagnostics"]["truncated_path_count"]
            for item in group_contexts
        ),
        "termination_reasons": dict(aggregate_termination_reasons),
    }
    candidate_miss_diagnostics = []
    causal_groundtruth_groups = []
    assigned_groups_by_event: dict[str, list[str]] = {}
    truth_by_event = {edge.event_id: edge for edge in groundtruth_edges}
    for item in group_contexts:
        association = associate_groundtruth_components(
            group_id=item["group_id"],
            alert_edges=item["alert_edges"],
            groundtruth_edges=groundtruth_edges,
            groundtruth_node_ids=evaluation_truth.attack_node_uuids,
        )
        candidate_ids = {edge.event_id for edge in item["graph"].edges}
        associated_truth = [
            edge for edge in groundtruth_edges
            if edge.event_id in association.get("attack_event_ids", [])
        ]
        causal_truth_ids = time_respecting_groundtruth_context(
            item["alert_edges"], associated_truth
        )
        causal_candidate_ids = candidate_ids & causal_truth_ids
        causal_groundtruth_groups.append({
            "group_id": item["group_id"],
            "legacy_groundtruth_edges": len(associated_truth),
            "time_respecting_groundtruth_edges": len(causal_truth_ids),
            "candidate_time_respecting_edges": len(causal_candidate_ids),
            "candidate_recall": (
                len(causal_candidate_ids) / len(causal_truth_ids)
                if causal_truth_ids else None
            ),
            "excluded_legacy_event_ids": sorted(
                {edge.event_id for edge in associated_truth} - causal_truth_ids
            ),
        })
        poi_time = min(
            (edge.timestamp_ns for edge in item["alert_edges"]), default=0
        )
        for event_id in association.get("attack_event_ids", []):
            assigned_groups_by_event.setdefault(event_id, []).append(item["group_id"])
            if event_id in candidate_ids:
                continue
            edge = truth_by_event.get(event_id)
            reason = item["excluded_event_reasons"].get(event_id)
            if edge is None:
                reason = "event_absent_from_database"
            elif reason is None and event_id not in causal_truth_ids:
                reason = "not_in_time_respecting_groundtruth_context"
            elif reason is None and edge.timestamp_ns > poi_time:
                reason = "future_event_not_reached_from_poi_effect_search"
            elif reason is None:
                reason = "not_reached_by_time_respecting_entity_state_search"
            candidate_miss_diagnostics.append({
                "group_id": item["group_id"],
                "event_id": event_id,
                "database_present": edge is not None,
                "relation": edge.relation if edge else None,
                "src": edge.src if edge else None,
                "dst": edge.dst if edge else None,
                "timestamp_ns": edge.timestamp_ns if edge else None,
                "delta_from_poi_seconds": (
                    (edge.timestamp_ns - poi_time) / 1_000_000_000 if edge else None
                ),
                "reason": reason,
            })
    duplicate_assignments = {
        event_id: groups for event_id, groups in assigned_groups_by_event.items()
        if len(groups) > 1
    }
    report = {
        "annotation_name": annotations.name,
        "alert_input_provenance": {
            "source": annotations.metadata.get("source"),
            "input_schema_version": annotations.metadata.get("input_schema_version"),
            "input_alert_edge_count": annotations.metadata.get("input_alert_edge_count"),
            "unique_alert_edge_count": annotations.metadata.get("unique_alert_edge_count"),
            "duplicate_alert_edge_count": annotations.metadata.get("duplicate_alert_edge_count"),
            "mapped_summary_event_count": annotations.metadata.get("matched_alert_edge_count"),
            "interpretation": (
                "mapped_events_from_KAIROS_alert_summary_graphs_not_all_window_events"
                if annotations.metadata.get("source") == "KAIROS" else None
            ),
            "association_rule": (
                "KAIROS-provided alert window membership"
                if annotations.metadata.get("source") == "KAIROS" else None
            ),
        },
        "analysis_mode": analysis_mode,
        "diffusion_mode": diffusion.mode,
        "seeds": sorted(effective_seeds),
        "annotated_seed_event_ids": sorted(annotations.seed_event_ids),
        "ordered_poi_event_sequences": [
            list(sequence) for sequence in annotations.seed_event_sequences
        ],
        "matched_seed_event_ids": sorted(matched_seed_events),
        "poi_events": [
            {
                "event_id": edge.event_id,
                "src": edge.src,
                "dst": edge.dst,
                "anchor": event_investigation_anchor(edge),
            }
            for edge in sorted(matched_poi_edges, key=lambda item: item.event_id)
        ],
        "causal_search_policy": (
            "kairos_time_ordered_forward_cumulative"
            if causal_search_config.seed_strategy == "kairos_forward_cumulative"
            else "adaptive_window_priority_frontier_relevance"
        ),
        "candidate_graph_has_path_limit": False,
        "evidence_path_policy": "one_covering_projection_per_natural_head_or_tail",
        "causal_search_config": asdict(causal_search_config),
        "search_diagnostics": search_diagnostics,
        "cumulative_alert_search": cumulative_alert_search,
        "candidate_construction": (
            asdict(window_result.diagnostics)
            if causal_search_config.seed_strategy in {
                "window_context", "window_context_expand"
            }
            else None
        ),
        "candidate_miss_diagnostics": candidate_miss_diagnostics,
        "groundtruth_assignment_diagnostics": {
            "legacy_rule": "undirected_connected_component_touched_by_POI",
            "per_group_assignment_count": sum(
                len(groups) for groups in assigned_groups_by_event.values()
            ),
            "unique_assigned_event_count": len(assigned_groups_by_event),
            "duplicate_event_assignment_count": len(duplicate_assignments),
            "duplicate_event_assignments": duplicate_assignments,
            "note": (
                "Legacy per-POI totals intentionally remain unchanged; "
                "scenario-wide metrics use unique event IDs."
            ),
        },
        "time_respecting_groundtruth_evaluation": {
            "role": "supplemental_offline_diagnostic_only",
            "online_search_uses_groundtruth": False,
            "definition": (
                "backward from the relation-aware POI investigation anchor "
                "and forward from the information-flow destination "
                "with monotonic event timestamps"
            ),
            "groups": causal_groundtruth_groups,
            "aligned_candidate_recall": (
                sum(item["candidate_time_respecting_edges"] for item in causal_groundtruth_groups)
                / sum(item["time_respecting_groundtruth_edges"] for item in causal_groundtruth_groups)
                if causal_groundtruth_groups else None
            ),
        },
        "seed_event_group_count": len(annotations.seed_event_groups) or (
            1 if annotations.seed_event_ids else 0
        ),
        "path_weight": path_weight,
        "impact_weight": impact_weight,
        "behavior_weight": behavior_weight,
        "path_decay": path_decay,
        "pruning_mode": pruning_mode,
        "fusion_mode": fusion_mode,
        "poi_aggregation": poi_aggregation,
        "poi_local_scoring": {
            "policy": (
                "immutable_per_poi_scores_aggregated_by_noisy_or"
                if poi_aggregation == "noisy_or" else "joint_poi_scoring"
            ),
            "newly_computed": poi_local_scoring,
            "local_score_digests": (
                aggregate_score_state.local_score_digests
                if aggregate_score_state is not None else {}
            ),
            "context_digest": (
                active_prefix_accumulator.context_digest
                if active_prefix_accumulator is not None else None
            ),
            "prefix_monotonicity_guarantee": poi_aggregation == "noisy_or",
            "score_semantics": "heuristic_importance_not_probability",
        },
        "score_mass_target": score_mass_target,
        "score_mass_semantics": (
            "legacy_name_for_retained_heuristic_utility_not_confidence"
        ),
        "pruning_scope": effective_pruning_scope,
        "protect_alert_edges": protect_alert_edges,
        "connectivity_protection": connectivity_protection,
        "certificate_topology_policy": certificate_topology_policy,
        "connectivity_policy": (
            "report_declared_causal_path_cover_with_minimum_cost_strict_time_"
            "respecting_bridges; edge_cost=1-final_score"
            if connectivity_protection else "disabled"
        ),
        "poi_seed_policy": (
            "kairos_alert_event_destination_forward_only"
            if causal_search_config.seed_strategy in {
                "kairos_forward_cumulative", "window_context", "window_context_expand"
            }
            else "relation_aware_investigation_anchor"
        ),
        "depimpact": {
            "merge_threshold_seconds": merge_threshold_seconds,
            "original_edges": impact_analysis.original_edge_count,
            "merged_edges": impact_analysis.merged_edge_count,
            "data_size_coverage": impact_analysis.data_size_coverage,
            "projection": list(impact_analysis.projection),
            "propagation_rule": "DEPIMPACT_equation_7_backward_until_delta",
            "propagation_tolerance": 1e-13,
            "propagation_iterations": impact_analysis.propagation_iterations,
            "propagation_converged": impact_analysis.converged,
            "convergence_delta": impact_analysis.convergence_delta,
            "propagation_diagnostics": impact_analysis.propagation_diagnostics,
            "implementation_label": (
                "adapted_DEPIMPACT"
                if impact_analysis.data_size_coverage > 0.0
                else "adapted_DEPIMPACT_without_data_flow_amount"
            ),
        },
        "depimpact_table7_runtime": {
            "schema_version": "depimpact-table7-runtime-v1",
            "measurement": "wall_clock_seconds_perf_counter",
            "scope": "identical_online_candidate_graph_and_selected_POI_prefix",
            "attack_causality_analysis_seconds": phase_seconds.get(
                "causal_search_and_candidate_build", 0.0
            ),
            "edge_merge_seconds": table7_depimpact_timings.get(
                "depimpact", {}
            ).get("edge_merge", 0.0),
            "dependency_weight_computation_seconds": {
                "depimpact": table7_depimpact_timings.get(
                    "depimpact", {}
                ).get("dependency_weight_computation", 0.0),
                "fixed_projection": table7_depimpact_timings.get(
                    "fixed_projection", {}
                ).get("dependency_weight_computation", 0.0),
            },
            "dependency_impact_propagation_seconds": {
                "depimpact": table7_depimpact_timings.get(
                    "depimpact", {}
                ).get("dependency_impact_propagation", 0.0),
                "fixed_projection": table7_depimpact_timings.get(
                    "fixed_projection", {}
                ).get("dependency_impact_propagation", 0.0),
            },
            "nodoze_seconds": (
                phase_seconds.get("frequency_model_load", 0.0)
                + phase_seconds.get("nodoze_path_scoring", 0.0)
            ),
            "method_phase_seconds": table7_depimpact_timings,
            "timing_not_used_for_selection": True,
        },
        "depimpact_table8_entry_ranks": table8_entry_ranks,
        "behavior": {
            "cluster_count": behavior_analysis.cluster_count,
            "backend": behavior_analysis.backend,
        },
        "frequency_cutoff_ns": frequency_cutoff_ns,
        "frequency_source": (
            "compiled_frequency_snapshot" if use_frequency_snapshot
            else "offline_daily_frequency_cache" if use_frequency_cache
            else "raw_event_scan"
        ),
        "frequency_cutoff_policy": (
            "completed_days_only" if use_frequency_cache else "exact_timestamp"
        ),
        "directional_edge_cache": {
            "database_queries": edge_cache.db_queries,
            "cache_hits": edge_cache.cache_hits,
            "cached_node_directions": len(edge_cache.values),
        },
        "original_nodes": len(graph.nodes),
        "original_edges": len(graph.edges),
        "candidate_path_count": len(candidate_paths),
        # Persist the complete candidate edge identity set so downstream
        # diagnostics and paper figures do not have to reconstruct the online
        # causal search (top_edge_scores is intentionally presentation-limited).
        "candidate_event_ids": sorted({edge.event_id for edge in graph.edges}),
        "top_candidate_paths": [
            asdict(score)
            for score in sorted(path_scores, key=lambda item: -item.anomaly)[:20]
        ],
        "diffusion_iterations": diffusion.iterations,
        "diffusion_converged": diffusion.converged,
        "diffusion_diagnostics": diffusion.diagnostics,
        "elapsed_seconds": time.perf_counter() - started,
        "runtime_breakdown_seconds": phase_seconds,
        "results": rows,
    }
    if fusion_mode == "rdp_guard":
        recommendation = recommend_operating_point(
            rows, score_mass_target=score_mass_target
        )
        recommendation["online_uses_groundtruth"] = False
        report["rdp_guard_recommendation"] = recommendation
    ablation_specs = {
        "rarity-only": (
            1.0, 0.0, 0.0, 0.0, "ratio", False, "additive"
        ),
        "diffusion-only": (
            0.0, 0.0, 0.0, 0.0, "ratio", False, "additive"
        ),
        "fixed-fusion": (
            rarity_weight, path_weight, impact_weight, behavior_weight,
            "ratio", False, "additive",
        ),
        "adaptive-fusion": (
            rarity_weight, path_weight, impact_weight, behavior_weight,
            "adaptive", False, "additive",
        ),
        "adaptive+connectivity": (
            rarity_weight, path_weight, impact_weight, behavior_weight,
            "adaptive", True, "additive",
        ),
        "rdp-guard": (
            rarity_weight, path_weight, impact_weight, behavior_weight,
            "rdp_guard", True, "rdp_guard",
        ),
    } if include_method_comparison else {}
    candidate_truth_events = {
        edge.event_id for edge in graph.edges
    } & evaluation_truth.attack_event_ids
    ablation_rows = []
    for method, (
        ab_rarity, ab_path, ab_impact, ab_behavior, ab_mode, ab_connectivity,
        ab_fusion,
    ) in ablation_specs.items():
        for keep_ratio in keep_ratios:
            ablation_started = time.perf_counter()
            progress(
                "ablation_started", method=method, keep_ratio=keep_ratio
            )
            ablated = adaptive_prune(
                graph,
                rarity,
                diffusion,
                seeds=effective_seeds,
                keep_ratio=keep_ratio,
                rarity_weight=ab_rarity,
                path_importance=path_importance,
                path_weight=ab_path,
                impact_importance=impact_analysis.edge_importance,
                impact_weight=ab_impact,
                behavior_importance=behavior_analysis.edge_importance,
                behavior_weight=ab_behavior,
                protected_edge_ids=protected_edge_ids,
                selection_mode=ab_mode,
                protect_seed_incident_edges=False,
                atomic_edge_groups=impact_analysis.merge_groups,
                connectivity_target_edge_ids=(
                    poi_edge_ids
                    if ab_connectivity and not active_ordered_path_cover else None
                ),
                ordered_connectivity_edge_sequences=(
                    active_ordered_path_cover if ab_connectivity else None
                ),
                certificate_poi_edge_ids=(
                    poi_edge_ids if ab_connectivity else None
                ),
                fusion_mode=ab_fusion,
            )
            kept_ids = {edge.event_id for edge in ablated.kept_edges}
            kept_truth = kept_ids & evaluation_truth.attack_event_ids
            complete_paths = sum(
                set(path) <= kept_ids for path in evaluation_truth.attack_paths
            )
            ablation_rows.append({
                "method": method,
                "requested_keep_ratio": keep_ratio,
                "actual_keep_ratio": ablated.actual_keep_ratio,
                "edge_compression": 1.0 - ablated.actual_keep_ratio,
                "gt_edge_recall": _optional_ratio(
                    len(kept_truth), len(evaluation_truth.attack_event_ids)
                ),
                "conditional_pruning_edge_recall": _optional_ratio(
                    len(kept_truth), len(candidate_truth_events)
                ),
                "complete_path_retention": _optional_ratio(
                    complete_paths, len(evaluation_truth.attack_paths)
                ),
                "connectivity_added_edges": ablated.connectivity_added_edges,
                "budget_edges": ablated.budget_edges,
                "budget_feasible": ablated.budget_feasible,
                "budget_overflow_edges": ablated.budget_overflow_edges,
                "scoring_mode": ablated.scoring_mode,
                "score_mass_retained": ablated.score_mass_retained,
                "path_certificate_valid": ablated.path_certificate_valid,
                "stage_pairs": ablated.stage_pairs,
                "connected_stage_pairs": ablated.connected_stage_pairs,
                "retained_stage_pairs": ablated.retained_stage_pairs,
                "kept_event_ids": sorted(kept_ids),
                "retained_event_count": len(kept_ids),
                "single_budget_pruning_seconds": time.perf_counter() - ablation_started,
                "protected_event_count": len(protected_edge_ids),
                "selection_candidate_edges_examined": (
                    ablated.selection_candidate_edges_examined
                ),
            })
            progress(
                "ablation_complete", method=method, keep_ratio=keep_ratio,
                kept_edges=len(ablated.kept_edges),
            )
    report["method_comparison"] = {
        "candidate_identity": "same in-memory candidate graph for every method",
        "budget_identity": "same requested raw-event budget; actual retention reported per row",
        "annotation_identity": "same fixed evaluation manifest",
        "hard_protection_rule": "alert edges are not score-protected; connectivity is enabled only for adaptive+connectivity",
        "hard_protected_event_count": len(protected_edge_ids),
        "scope": "merged_candidate_graph",
        "methods": list(ablation_specs),
        "curve": ablation_rows,
    }
    phase_seconds["pruning_connectivity_curves_and_ablations"] = (
        time.perf_counter() - pruning_started
    )
    if groundtruth_annotations is not None:
        first_alert_rows = aligned_rows[0]["alerts"] if aligned_rows else []
        associated = sum(item["associated"] for item in first_alert_rows)
        weakly_associated = sum(
            item.get("association_status") == "weak"
            for item in first_alert_rows
        )
        unassociated = sum(
            item.get("association_status") == "none"
            for item in first_alert_rows
        )
        report["scenario_wide_groundtruth_name"] = evaluation_truth.name
        report["alert_aligned_evaluation"] = {
            "detector_name": annotations.name,
            "groundtruth_name": evaluation_truth.name,
            "groundtruth_path_count": len(evaluation_truth.attack_paths),
            "groundtruth_scope_quality": (
                "explicit_paths_available"
                if evaluation_truth.attack_paths
                else "event_connected_component_proxy"
            ),
            "annotated_groundtruth_nodes": len(
                evaluation_truth.attack_node_uuids
            ),
            "matched_groundtruth_nodes": len(
                evaluation_truth.attack_node_uuids & set(graph.nodes)
            ),
            "annotated_groundtruth_edges": len(
                evaluation_truth.attack_event_ids
            ),
            "matched_groundtruth_edges": len(groundtruth_edges),
            "alert_group_count": len(group_contexts),
            "associated_alert_groups": associated,
            "weakly_associated_alert_groups": weakly_associated,
            "unassociated_alert_groups": unassociated,
            "association_rule": (
                "primary metrics use ground-truth connected components touched "
                "by a directly overlapping alert event ID"
            ),
            "weak_association_rule": (
                "alert endpoint overlaps a ground-truth node without event "
                "overlap; diagnostic only and excluded from aggregates"
            ),
            "context_metric_rule": (
                "context edge metrics exclude directly overlapping alert "
                "events from reconstruction credit"
            ),
            "results": aligned_rows,
        }
        report["stage_evaluation"] = {
            "search_stage": {
                "metric_denominator": "all associated ground-truth edges/nodes",
                "candidate_attack_node_recall": (
                    aligned_rows[0]["micro"]["candidate_attack_node_recall"]
                    if aligned_rows else None
                ),
                "candidate_attack_edge_recall": (
                    aligned_rows[0]["micro"]["candidate_attack_edge_recall"]
                    if aligned_rows else None
                ),
            },
            "pruning_stage": [
                {
                    "requested_keep_ratio": item["requested_keep_ratio"],
                    "actual_keep_ratio": item["actual_keep_ratio"],
                    "gt_edge_recall": item["micro"]["pruned_attack_edge_recall"],
                    "conditional_pruning_edge_recall": item["micro"]["conditional_pruning_edge_recall"],
                    "critical_edge_recall": item["micro"].get("critical_edge_recall"),
                    "entry_to_poi_reachability": item["micro"].get("entry_to_poi_reachability"),
                    "complete_path_retention": item["micro"].get("complete_path_retention"),
                }
                for item in aligned_rows
            ],
            "conditional_pruning_formula": "|E_out intersect E_GT| / |E_candidate intersect E_GT|",
        }
        report["compression_recall_curve"] = report["stage_evaluation"]["pruning_stage"]
        end_to_end_seconds = time.perf_counter() - started
        peak_memory_mb = _rss_monitor.peak_bytes / (1024 * 1024)
        truth_event_ids = set(evaluation_truth.attack_event_ids)
        candidate_event_ids = {edge.event_id for edge in graph.edges}
        candidate_recall = (
            len(candidate_event_ids & truth_event_ids) / len(truth_event_ids)
            if truth_event_ids else None
        )
        paper_rows = []
        method_name = (
            "ps_rdp_prefix_stable"
            if poi_aggregation == "noisy_or" else
            "rdp_guard" if fusion_mode == "rdp_guard" else
            "adaptive_fusion_connectivity"
            if connectivity_protection else "adaptive_fusion"
        )
        for result_row, aligned in zip(rows, aligned_rows):
            kept_event_ids = set(result_row["kept_event_ids"])
            labeled_kept = kept_event_ids & truth_event_ids
            paper_rows.append({
                "requested_keep_ratio": result_row["requested_keep_ratio"],
                **build_paper_main_result(
                    scenario=evaluation_truth.name,
                    method=method_name,
                    nodes_before=result_row["original_nodes"],
                    nodes_after=result_row["kept_nodes"],
                    events_before=result_row["original_edges"],
                    events_after=result_row["kept_edges"],
                    attack_event_recall=(
                        len(labeled_kept) / len(truth_event_ids)
                        if truth_event_ids else None
                    ),
                    complete_path_retention=(
                        sum(
                            set(path) <= kept_event_ids
                            for path in evaluation_truth.attack_paths
                        ) / len(evaluation_truth.attack_paths)
                        if evaluation_truth.attack_paths else None
                    ),
                    latency_seconds=end_to_end_seconds,
                ),
            })
        report["paper_main_results"] = {
            "available": True,
            "groundtruth_name": evaluation_truth.name,
            "event_scope": "scenario_unique_event_ids",
            "complete_path_rule": (
                "A ground-truth path is retained only when every annotated event "
                "ID in that path remains in the output graph. Null means that no "
                "explicit ground-truth paths were supplied."
            ),
            "rows": paper_rows,
        }
    if score_ledger_dir is not None and ledger_scores is not None:
        ledger_started = time.perf_counter()
        progress("score_ledger_started", candidate_edges=len(graph.edges))
        ledger_manifest = write_score_ledger(
            score_ledger_dir,
            graph=graph,
            scores=ledger_scores,
            components=ledger_components or {},
            rarity_evidence=model.edge_rarity_evidence,
            decisions=ledger_decisions,
            score_provenance=score_provenance,
            local_score_contributions=(
                aggregate_score_state.local_score_contributions
                if aggregate_score_state is not None else None
            ),
            absolute_threshold=high_score_threshold,
            high_score_quantile=high_score_quantile,
            context={
                "annotation_name": annotations.name,
                "poi_aggregation": poi_aggregation,
                "poi_event_ids": [
                    edge.event_id
                    for edge in sorted(
                        matched_poi_edges,
                        key=lambda item: (item.timestamp_ns, item.event_id),
                    )
                ],
                "local_score_digests": (
                    aggregate_score_state.local_score_digests
                    if aggregate_score_state is not None else {}
                ),
                "frequency_cutoff_ns": frequency_cutoff_ns,
                "candidate_graph_sha256": candidate_graph_digest(graph),
                "prefix_score_context_sha256": (
                    active_prefix_accumulator.context_digest
                    if active_prefix_accumulator is not None else None
                ),
                "scoring_parameters": {
                    "rarity_weight": rarity_weight,
                    "path_weight": path_weight,
                    "impact_weight": impact_weight,
                    "behavior_weight": behavior_weight,
                    "path_decay": path_decay,
                    "damping": damping,
                    "diffusion_mode": diffusion_mode,
                    "fusion_mode": fusion_mode,
                    "poi_aggregation": poi_aggregation,
                    "edge_score_aggregation": (
                        "noisy_or"
                        if effective_pruning_scope in {
                            "per_alert_group",
                            "prefix_stable_noisy_or",
                        }
                        else "joint"
                    ),
                    "merge_threshold_seconds": merge_threshold_seconds,
                    "data_flow_alpha": data_flow_alpha,
                    "kmeans_restarts": kmeans_restarts,
                    "depimpact_random_seed": depimpact_random_seed,
                    "behavior_min_cluster_size": behavior_min_cluster_size,
                    "behavior_fallback_gap_seconds": (
                        behavior_fallback_gap_seconds
                    ),
                    "embedding_dimensions": embedding_dimensions,
                    "minimum_token_frequency": minimum_token_frequency,
                },
                "pruning_parameters": {
                    "keep_ratios": [float(value) for value in keep_ratios],
                    "selection_mode": pruning_mode,
                    "connectivity_protection": connectivity_protection,
                    "protect_alert_edges": protect_alert_edges,
                    "churn_slack_ratio": churn_slack_ratio,
                    "positive_score_only": positive_score_only,
                    "budget_rounding_policy": "floor_hard_cap_minimum_one",
                    "certificate_topology_policy": certificate_topology_policy,
                    "ordered_poi_event_sequences": [
                        list(sequence)
                        for sequence in annotations.seed_event_sequences
                    ],
                },
                "online_uses_groundtruth": False,
            },
        )
        ledger_verification = verify_score_ledger(score_ledger_dir)
        if not ledger_verification["valid"]:
            raise RuntimeError(
                "score ledger failed post-write verification: "
                + "; ".join(ledger_verification.get("validation_errors", []))
            )
        phase_seconds["score_ledger_write"] = time.perf_counter() - ledger_started
        report["score_ledger"] = {
            "directory": str(Path(score_ledger_dir).resolve()),
            "manifest": str((Path(score_ledger_dir) / "manifest.json").resolve()),
            "verification": ledger_verification,
            **ledger_manifest,
        }
        progress(
            "score_ledger_complete",
            rows=ledger_manifest["ledger_row_count"],
            high_scores=ledger_manifest["high_score_count"],
            verified=True,
        )
    else:
        report["score_ledger"] = {
            "enabled": False,
            "reason": "score_ledger_dir_not_supplied",
        }

    report["runtime_breakdown_seconds"] = dict(phase_seconds)
    end_to_end_seconds = time.perf_counter() - started
    _rss_monitor.sample_now()
    peak_rss_bytes = _rss_monitor.peak_bytes
    report["elapsed_seconds"] = end_to_end_seconds
    report["resource_usage"] = {
        "end_to_end_latency_seconds": end_to_end_seconds,
        "baseline_rss_mb": baseline_rss_bytes / (1024 * 1024),
        "peak_rss_mb": peak_rss_bytes / (1024 * 1024),
        "peak_rss_increment_mb": max(0, peak_rss_bytes - baseline_rss_bytes) / (1024 * 1024),
        "peak_memory_measurement": "process_peak_rss_sampled_every_10ms",
        "measurement_scope": "entire run_experiment call including all budgets and method comparisons",
    }
    report["metric_protocol_version"] = "tc-pruning-evaluation-v2.0"
    for paper_row in report.get("paper_main_results", {}).get("rows", []):
        paper_row["single_run_latency_seconds"] = end_to_end_seconds
    if "paper_main_results" not in report:
        report["paper_main_results"] = {
            "available": False,
            "reason": "groundtruth_annotations_required",
            "rows": [],
        }

    # Publish one unambiguous metric schema. Internal legacy calculations are
    # still used above to derive path-aware values, but are not serialized.
    for legacy_section in (
        "alert_aligned_evaluation",
        "stage_evaluation",
        "compression_recall_curve",
        "time_respecting_groundtruth_evaluation",
    ):
        report.pop(legacy_section, None)
    legacy_result_fields = set(EvaluationMetrics.__dataclass_fields__)
    for result_row in report["results"]:
        for field_name in legacy_result_fields:
            result_row.pop(field_name, None)
    if include_internal_state:
        report["_online_state"] = {
            "prefix_score_accumulator": active_prefix_accumulator,
            "edge_scores": ledger_scores or {},
            "kept_event_ids": set(rows[-1]["kept_event_ids"]) if rows else set(),
        }
    return report


def run_experiment(*args: object, **kwargs: object) -> dict:
    """Run an experiment while always terminating its RSS sampler."""
    with _PeakRSSMonitor() as monitor:
        return _run_experiment_core(*args, _rss_monitor=monitor, **kwargs)


__all__ = [
    "AttackAnnotations",
    "EvaluationMetrics",
    "build_paper_main_result",
    "compute_metrics",
    "run_experiment",
]
