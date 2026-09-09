from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import heapq
import itertools
import math
import time
from typing import Literal

from .cdm import event_backward_anchor, event_forward_anchor
from .models import Neighborhood, StoredEdge
from .nodoze import NODOZEFrequencyModel
from .store import ProvenanceStore

PROCESS_LINEAGE_RELATIONS = frozenset({"EVENT_CLONE", "EVENT_EXECUTE", "EVENT_FORK"})


@dataclass(frozen=True, slots=True)
class CausalSearchConfig:
    """Suspicion policy plus optional, disabled-by-default resource guards."""

    seed_strategy: str = "poi_bidirectional"
    window_page_size: int = 5000
    resource_memory_mb: float = 4096.0
    cache_max_blocks: int = 256
    completion_span_seconds: float = 900.0
    cache_block_seconds: float = 60.0
    expansion_direction: str = "both"
    topology: str = "path"
    eligibility_mode: str = "hard_threshold"
    soft_priority_max_fanout: int = 20
    min_edge_suspicion: float = 0.55
    min_path_suspicion: float = 0.45
    suspicion_momentum: float = 0.8
    branch_suspicion_quantile: float = 0.9
    initial_window_seconds: float = 900.0
    window_growth_factor: float = 2.0
    window_boundary_fraction: float = 0.1
    temporal_half_life_seconds: float = 900.0
    rarity_priority_weight: float = 0.6
    temporal_priority_weight: float = 0.25
    fanout_priority_weight: float = 0.15
    path_relevance_decay: float = 0.95
    min_frontier_relevance: float = 0.45
    high_frequency_degree: int = 1000
    high_frequency_partition_seconds: float = 60.0
    resource_max_edges: int | None = None
    resource_max_states: int | None = None
    resource_max_hops: int | None = None
    resource_timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.seed_strategy not in {
            "poi_bidirectional", "kairos_forward_cumulative",
            "window_context", "window_context_expand",
        }:
            raise ValueError(
                "unsupported seed_strategy"
            )
        if self.window_page_size <= 0 or self.cache_max_blocks <= 0:
            raise ValueError("window page and cache settings must be positive")
        if self.resource_memory_mb <= 0 or self.completion_span_seconds < 0:
            raise ValueError("window resource settings are invalid")
        if self.cache_block_seconds <= 0:
            raise ValueError("cache_block_seconds must be positive")
        if self.expansion_direction not in {"forward", "backward", "both"}:
            raise ValueError("expansion_direction must be forward, backward, or both")
        if self.topology not in {"path", "ancestral_cone"}:
            raise ValueError("topology must be path or ancestral_cone")
        if self.eligibility_mode not in {"hard_threshold", "soft_priority"}:
            raise ValueError("eligibility_mode must be hard_threshold or soft_priority")
        if self.soft_priority_max_fanout <= 0:
            raise ValueError("soft_priority_max_fanout must be positive")
        for name in (
            "min_edge_suspicion",
            "min_path_suspicion",
            "branch_suspicion_quantile",
            "window_boundary_fraction",
            "rarity_priority_weight",
            "temporal_priority_weight",
            "fanout_priority_weight",
            "path_relevance_decay",
            "min_frontier_relevance",
        ):
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if not 0.0 <= self.suspicion_momentum < 1.0:
            raise ValueError("suspicion_momentum must be in [0, 1)")
        if self.initial_window_seconds <= 0 or self.temporal_half_life_seconds <= 0:
            raise ValueError("search time settings must be positive")
        if self.window_growth_factor <= 1.0:
            raise ValueError("window_growth_factor must be greater than 1")
        if self.high_frequency_degree <= 0 or self.high_frequency_partition_seconds <= 0:
            raise ValueError("high-frequency partition settings must be positive")
        if not math.isclose(
            self.rarity_priority_weight + self.temporal_priority_weight
            + self.fanout_priority_weight, 1.0, abs_tol=1e-9
        ):
            raise ValueError("search priority weights must sum to 1")
        for name in ("resource_max_edges", "resource_max_states", "resource_max_hops"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be positive or null")
        if self.resource_timeout_seconds is not None and self.resource_timeout_seconds <= 0:
            raise ValueError("resource_timeout_seconds must be positive or null")


@dataclass(slots=True)
class AlertContext:
    graph: Neighborhood
    paths: list[list[StoredEdge]]
    backward_paths: list[list[StoredEdge]] = field(default_factory=list)
    forward_paths: list[list[StoredEdge]] = field(default_factory=list)
    alert_event_ids: set[str] = field(default_factory=set)
    seed_uuids: set[str] = field(default_factory=set)
    complete_path_count: int = 0
    truncated_path_count: int = 0
    termination_reasons: dict[str, int] = field(default_factory=dict)
    excluded_event_reasons: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CumulativeForwardStep:
    group_id: str
    alert_event_ids: tuple[str, ...]
    alert_time_ns: int
    graph: Neighborhood
    new_event_count: int
    overlap_event_count: int
    cumulative_event_count: int
    complete_path_count: int
    truncated_path_count: int
    termination_reasons: dict[str, int]


@dataclass(slots=True)
class CumulativeForwardResult:
    context: AlertContext
    steps: list[CumulativeForwardStep]


@dataclass(slots=True)
class DirectionalEdgeCache:
    """Load a node's indexed incoming/outgoing events once and filter in memory."""

    store: ProvenanceStore
    values: dict[tuple[str, str], list[StoredEdge]] = field(default_factory=dict)
    anchors: dict[tuple[str, str], int] = field(default_factory=dict)
    db_queries: int = 0
    cache_hits: int = 0

    def get_window(
        self, node_uuid: str, direction: Literal["backward", "forward"],
        anchor: int, window_ns: int,
    ) -> list[StoredEdge]:
        """Return one bounded causal window without materializing node history."""
        lower = anchor - window_ns if direction == "backward" else anchor
        upper = anchor if direction == "backward" else anchor + window_ns
        key = (node_uuid, f"{direction}:{lower}:{upper}")
        if key in self.values:
            self.cache_hits += 1
            return self.values[key]
        result = self.store.get_directional_edges(
            node_uuid, direction=direction,
            minimum_time_ns=lower, maximum_time_ns=upper,
        )
        self.values[key] = result
        self.db_queries += 1
        return result

    def peek(self, node_uuid: str, direction: Literal["backward", "forward"], anchor: int) -> list[StoredEdge]:
        """Use the directional index to find the closest event across a dormant gap."""
        key = (node_uuid, f"{direction}:peek:{anchor}")
        if key in self.values:
            self.cache_hits += 1
            return self.values[key]
        result = self.store.get_directional_edges(
            node_uuid, direction=direction,
            minimum_time_ns=anchor if direction == "forward" else None,
            maximum_time_ns=anchor if direction == "backward" else None,
            scan_limit=1,
        )
        self.values[key] = result
        self.db_queries += 1
        return result

    def dependency_instances(self, edge: StoredEdge) -> list[StoredEdge]:
        """Return events represented by the same dependency at the POI time."""
        key = (edge.src, f"dependency:{edge.dst}:{edge.relation}:{edge.timestamp_ns}")
        if key in self.values:
            self.cache_hits += 1
            return self.values[key]
        result = [
            item for item in self.store.get_directional_edges(
                edge.src, direction="forward",
                minimum_time_ns=edge.timestamp_ns,
                maximum_time_ns=edge.timestamp_ns,
            )
            if item.dst == edge.dst and item.relation == edge.relation
        ]
        self.values[key] = result
        self.db_queries += 1
        return result

    def get(
        self, node_uuid: str, direction: Literal["backward", "forward"], anchor: int
    ) -> list[StoredEdge]:
        key = (node_uuid, direction)
        if key not in self.values:
            self.values[key] = self.store.get_directional_edges(
                node_uuid,
                direction=direction,
                minimum_time_ns=anchor if direction == "forward" else None,
                maximum_time_ns=anchor if direction == "backward" else None,
            )
            self.anchors[key] = anchor
            self.db_queries += 1
        else:
            self.cache_hits += 1
            cached_anchor = self.anchors[key]
            needs_extension = (
                direction == "backward" and anchor > cached_anchor
            ) or (
                direction == "forward" and anchor < cached_anchor
            )
            if needs_extension:
                extra = self.store.get_directional_edges(
                    node_uuid,
                    direction=direction,
                    minimum_time_ns=(
                        anchor if direction == "forward" else cached_anchor + 1
                    ),
                    maximum_time_ns=(
                        cached_anchor - 1 if direction == "forward" else anchor
                    ),
                )
                by_id = {edge.edge_id: edge for edge in self.values[key]}
                by_id.update({edge.edge_id: edge for edge in extra})
                reverse = direction == "backward"
                self.values[key] = sorted(
                    by_id.values(),
                    key=lambda edge: (edge.timestamp_ns, edge.edge_id),
                    reverse=reverse,
                )
                self.anchors[key] = anchor
                self.db_queries += 1
        if direction == "backward":
            return [edge for edge in self.values[key] if edge.timestamp_ns <= anchor]
        return [edge for edge in self.values[key] if edge.timestamp_ns >= anchor]


def _is_simple_causal_path(path: list[StoredEdge]) -> bool:
    if not path or len({edge.edge_id for edge in path}) != len(path):
        return False
    if any(left.dst != right.src for left, right in zip(path, path[1:])):
        return False
    nodes = [path[0].src, *(edge.dst for edge in path)]
    return len(nodes) == len(set(nodes))


def _ordered_candidates(
    store: ProvenanceStore,
    model: NODOZEFrequencyModel,
    node_uuid: str,
    anchor_time: int,
    direction: Literal["backward", "forward"],
    edge_cache: DirectionalEdgeCache | None = None,
    window_ns: int | None = None,
) -> tuple[list[StoredEdge], dict[int, list[StoredEdge]]]:
    candidates = (
        edge_cache.get_window(node_uuid, direction, anchor_time, window_ns)
        if edge_cache is not None and window_ns is not None
        else edge_cache.get(node_uuid, direction, anchor_time)
        if edge_cache is not None
        else store.get_directional_edges(
            node_uuid,
            direction=direction,
            minimum_time_ns=(anchor_time - window_ns if direction == "backward" and window_ns is not None else anchor_time if direction == "forward" else None),
            maximum_time_ns=(anchor_time + window_ns if direction == "forward" and window_ns is not None else anchor_time if direction == "backward" else None),
        )
    )
    instances_by_dependency: dict[tuple[str, str, str], list[StoredEdge]] = {}
    representative_by_dependency: dict[tuple[str, str, str], StoredEdge] = {}
    for edge in candidates:
        key = (edge.src, edge.dst, edge.relation)
        instances_by_dependency.setdefault(key, []).append(edge)
        current = representative_by_dependency.get(key)
        rank = (-model.edge_anomaly(edge), abs(edge.timestamp_ns - anchor_time), edge.edge_id)
        if current is None or rank < (
            -model.edge_anomaly(current),
            abs(current.timestamp_ns - anchor_time),
            current.edge_id,
        ):
            representative_by_dependency[key] = edge
    representatives = sorted(
        representative_by_dependency.values(),
        key=lambda edge: (-model.edge_anomaly(edge), abs(edge.timestamp_ns - anchor_time), edge.edge_id),
    )
    return representatives, {
        representative.edge_id: instances_by_dependency[key]
        for key, representative in representative_by_dependency.items()
    }


@dataclass(slots=True)
class _ExpansionResult:
    complete_paths: list[list[StoredEdge]]
    truncated_path_count: int
    termination_reasons: Counter[str]
    excluded_event_reasons: dict[str, str]


def _next_suspicion(current: float | None, edge: float, momentum: float) -> float:
    return edge if current is None else momentum * current + (1.0 - momentum) * edge


def _search_priority(
    rarity: float, delta_ns: int, fanout: int, config: CausalSearchConfig
) -> float:
    temporal = math.exp(
        -max(0, delta_ns) / (config.temporal_half_life_seconds * 1_000_000_000)
    )
    fanout_score = 1.0 / (1.0 + math.log1p(max(0, fanout - 1)))
    return (
        config.rarity_priority_weight * rarity
        + config.temporal_priority_weight * temporal
        + config.fanout_priority_weight * fanout_score
    )


def _expand_graph(
    store: ProvenanceStore,
    model: NODOZEFrequencyModel,
    *,
    start_node: str,
    alert_time: int,
    direction: Literal["backward", "forward"],
    config: CausalSearchConfig,
    selected_edges: dict[int, StoredEdge],
    edge_cache: DirectionalEdgeCache | None = None,
    blocked_edge_ids: set[int] | None = None,
) -> _ExpansionResult:
    """Expand the finite causal graph; evidence paths never gate membership."""

    sequence = itertools.count()
    queue = [(-1.0, next(sequence), start_node, alert_time, [], frozenset({start_node}), None, 0)]
    expanded_representatives: set[int] = set()
    complete: list[list[StoredEdge]] = []
    reasons: Counter[str] = Counter()
    truncated = 0
    processed_states = 0
    excluded_event_reasons: dict[str, str] = {}
    started = time.perf_counter()
    blocked_edge_ids = blocked_edge_ids or set()

    while queue:
        if (
            config.eligibility_mode == "hard_threshold"
            and -queue[0][0] < config.min_frontier_relevance
        ):
            reasons["frontier_below_relevance"] += len(queue)
            complete.extend(item[4] for item in queue)
            break
        if (config.resource_timeout_seconds is not None
                and time.perf_counter() - started >= config.resource_timeout_seconds):
            reasons["timeout_resource_limit"] += len(queue)
            truncated += len(queue)
            break
        if config.resource_max_states is not None and processed_states >= config.resource_max_states:
            reasons["state_resource_limit"] += len(queue)
            truncated += len(queue)
            break
        _, _, node, anchor, path, visited, path_suspicion, hops = heapq.heappop(queue)
        processed_states += 1
        if config.resource_max_hops is not None and hops >= config.resource_max_hops:
            reasons["hop_resource_limit"] += 1
            truncated += 1
            continue
        window_ns = int(config.initial_window_seconds * 1_000_000_000)
        while True:
            candidates, instances_by_representative = _ordered_candidates(
                store, model, node, anchor, direction, edge_cache, window_ns
            )
            boundary = window_ns * (1.0 - config.window_boundary_fraction)
            boundary_relevant = any(
                abs(edge.timestamp_ns - anchor) >= boundary
                and (
                    model.edge_anomaly(edge) >= config.min_edge_suspicion
                )
                for edge in candidates
            )
            if not candidates:
                nearest = (
                    edge_cache.peek(node, direction, anchor)
                    if edge_cache is not None
                    else store.get_directional_edges(
                        node, direction=direction,
                        minimum_time_ns=anchor if direction == "forward" else None,
                        maximum_time_ns=anchor if direction == "backward" else None,
                        scan_limit=1,
                    )
                )
                if nearest and model.edge_anomaly(nearest[0]) >= config.min_edge_suspicion:
                    distance = abs(nearest[0].timestamp_ns - anchor)
                    window_ns = max(window_ns + 1, int(distance * config.window_growth_factor))
                    reasons["adaptive_window_gap_jump"] += 1
                    continue
            if not boundary_relevant:
                break
            window_ns = int(window_ns * config.window_growth_factor)
            reasons["adaptive_window_expansion"] += 1
        scored = [(model.edge_anomaly(edge), edge) for edge in candidates]
        relative_cutoff = 0.0
        if scored:
            ordered = sorted(score for score, _ in scored)
            rank = max(0, math.ceil(config.branch_suspicion_quantile * len(ordered)) - 1)
            relative_cutoff = ordered[rank]

        extended = False
        resource_limited = False
        fanout = len(scored)
        partition_sizes: dict[int, int] = {}
        edge_partition: dict[int, int] = {}
        if fanout >= config.high_frequency_degree:
            partition_ns = int(config.high_frequency_partition_seconds * 1_000_000_000)
            for _, edge in scored:
                bucket = abs(edge.timestamp_ns - anchor) // partition_ns
                edge_partition[edge.edge_id] = bucket
                partition_sizes[bucket] = partition_sizes.get(bucket, 0) + 1
            reasons["high_frequency_time_partitions"] += len(partition_sizes)

        def local_fanout(edge: StoredEdge) -> int:
            return partition_sizes.get(edge_partition.get(edge.edge_id, -1), fanout)

        scored.sort(key=lambda item: -_search_priority(
            item[0], abs(item[1].timestamp_ns - anchor), local_fanout(item[1]), config
        ))
        for edge_suspicion, edge in scored:
            if edge.edge_id in blocked_edge_ids:
                continue
            neighbor = edge.src if direction == "backward" else edge.dst
            edge_priority = _search_priority(
                edge_suspicion, abs(edge.timestamp_ns - anchor),
                local_fanout(edge), config,
            )
            successor_suspicion = _next_suspicion(
                path_suspicion, edge_priority, config.suspicion_momentum
            ) * config.path_relevance_decay
            if edge.edge_id in expanded_representatives:
                continue
            # The quantile affects scheduling through the priority ordering; it
            # must not delete a time-valid dependency before graph scoring.
            soft_eligible = (
                config.eligibility_mode == "soft_priority"
                and fanout <= config.soft_priority_max_fanout
            )
            if (
                config.eligibility_mode == "hard_threshold"
                or not soft_eligible
            ) and (
                edge_suspicion < config.min_edge_suspicion
                and edge_priority < config.min_edge_suspicion
                and successor_suspicion < config.min_path_suspicion
            ):
                reasons["search_priority_below_threshold"] += 1
                for instance in instances_by_representative[edge.edge_id]:
                    excluded_event_reasons[instance.event_id] = (
                        "search_priority_below_threshold"
                    )
                continue
            new_instances = [
                item
                for item in instances_by_representative[edge.edge_id]
                if item.edge_id not in selected_edges
            ]
            if config.resource_max_edges is not None:
                remaining = config.resource_max_edges - len(selected_edges)
                if remaining <= 0:
                    resource_limited = True
                    continue
                if len(new_instances) > remaining:
                    new_instances = new_instances[:remaining]
                    resource_limited = True
            for instance in new_instances:
                selected_edges[instance.edge_id] = instance
            if edge.edge_id not in selected_edges:
                resource_limited = True
                continue
            expanded_representatives.add(edge.edge_id)
            heapq.heappush(
                queue,
                (
                    -(successor_suspicion * edge_priority),
                    next(sequence),
                    neighbor,
                    edge.timestamp_ns,
                    path + [edge],
                    visited | {neighbor},
                    successor_suspicion,
                    hops + 1,
                ),
            )
            extended = True

        if resource_limited:
            reasons["edge_resource_limit"] += 1
        if not extended:
            if resource_limited:
                truncated += 1
            else:
                complete.append(path)
                reasons["natural_head" if direction == "backward" else "natural_tail"] += 1

    if direction == "backward":
        complete = [list(reversed(path)) for path in complete]
    return _ExpansionResult(complete, truncated, reasons, excluded_event_reasons)


def _combine_evidence_paths(
    backward: list[list[StoredEdge]], alert: StoredEdge, forward: list[list[StoredEdge]]
) -> list[list[StoredEdge]]:
    # Cover every natural endpoint without the head x tail Cartesian explosion.
    before = backward or [[]]
    after = forward or [[]]
    pairs = [(path, after[0]) for path in before]
    pairs.extend((before[0], path) for path in after[1:])
    result = []
    for left, right in pairs:
        combined = left + [alert] + right
        if _is_simple_causal_path(combined):
            result.append(combined)
    return result


def build_alert_context(
    store: ProvenanceStore,
    alert_event_ids: list[str] | set[str] | tuple[str, ...],
    model: NODOZEFrequencyModel,
    config: CausalSearchConfig | None = None,
    edge_cache: DirectionalEdgeCache | None = None,
) -> AlertContext:
    config = config or CausalSearchConfig()
    selected_edges: dict[int, StoredEdge] = {}
    all_paths: list[list[StoredEdge]] = []
    all_backward: list[list[StoredEdge]] = []
    all_forward: list[list[StoredEdge]] = []
    active_alerts: set[str] = set()
    seeds: set[str] = set()
    reasons: Counter[str] = Counter()
    truncated = 0
    excluded_event_reasons: dict[str, str] = {}

    alerts = [
        edge
        for event_id in sorted(set(alert_event_ids))
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    for alert in alerts:
        active_alerts.add(alert.event_id)
        seeds.update((alert.src, alert.dst))
        selected_edges[alert.edge_id] = alert
        dependency_instances = (
            edge_cache.dependency_instances(alert)
            if edge_cache is not None
            else [
                item for item in store.get_directional_edges(
                    alert.src, direction="forward",
                    minimum_time_ns=alert.timestamp_ns,
                    maximum_time_ns=alert.timestamp_ns,
                )
                if item.dst == alert.dst and item.relation == alert.relation
            ]
        )
        for instance in dependency_instances:
            selected_edges[instance.edge_id] = instance
        alert_dependency_edge_ids = {
            instance.edge_id for instance in dependency_instances
        }
        backward = (
            _expand_graph(
                store, model,
                start_node=event_backward_anchor(alert),
                alert_time=alert.timestamp_ns,
                direction="backward", config=config,
                selected_edges=selected_edges, edge_cache=edge_cache,
                blocked_edge_ids=alert_dependency_edge_ids,
            )
            if config.expansion_direction in {"backward", "both"}
            else _ExpansionResult([], 0, Counter(), {})
        )
        cone_forward_results: list[_ExpansionResult] = []
        if config.topology == "ancestral_cone":
            branch_points = {
                (edge.dst, edge.timestamp_ns)
                for path in backward.complete_paths
                for edge in path
                if edge.relation.upper() in PROCESS_LINEAGE_RELATIONS
                and edge.dst_type == "process"
            }
            for branch_node, branch_time in sorted(branch_points):
                cone_forward_results.append(
                    _expand_graph(
                        store, model,
                        start_node=branch_node,
                        alert_time=branch_time,
                        direction="forward",
                        config=config,
                        selected_edges=selected_edges,
                        edge_cache=edge_cache,
                        blocked_edge_ids=alert_dependency_edge_ids,
                    )
                )
        forward = (
            _expand_graph(
                store, model, start_node=event_forward_anchor(alert),
                alert_time=alert.timestamp_ns,
                direction="forward", config=config,
                selected_edges=selected_edges, edge_cache=edge_cache,
                blocked_edge_ids=alert_dependency_edge_ids,
            )
            if config.expansion_direction in {"forward", "both"}
            else _ExpansionResult([], 0, Counter(), {})
        )
        all_backward.extend(backward.complete_paths)
        all_forward.extend(forward.complete_paths)
        for cone_forward in cone_forward_results:
            all_forward.extend(cone_forward.complete_paths)
            reasons.update(cone_forward.termination_reasons)
            excluded_event_reasons.update(cone_forward.excluded_event_reasons)
            truncated += cone_forward.truncated_path_count
        if not backward.truncated_path_count and not forward.truncated_path_count:
            all_paths.extend(
                _combine_evidence_paths(
                    backward.complete_paths, alert, forward.complete_paths
                )
            )
        reasons.update(backward.termination_reasons)
        reasons.update(forward.termination_reasons)
        excluded_event_reasons.update(backward.excluded_event_reasons)
        excluded_event_reasons.update(forward.excluded_event_reasons)
        truncated += backward.truncated_path_count + forward.truncated_path_count

    return AlertContext(
        graph=store.neighborhood_from_edges(selected_edges.values()),
        paths=all_paths,
        backward_paths=all_backward,
        forward_paths=all_forward,
        alert_event_ids=active_alerts,
        seed_uuids=seeds,
        complete_path_count=len(all_paths),
        truncated_path_count=truncated,
        termination_reasons=dict(reasons),
        excluded_event_reasons=excluded_event_reasons,
    )


def build_cumulative_forward_contexts(
    store: ProvenanceStore,
    alert_groups: list[tuple[str, set[str]]],
    model: NODOZEFrequencyModel,
    config: CausalSearchConfig | None = None,
    edge_cache: DirectionalEdgeCache | None = None,
) -> CumulativeForwardResult:
    """Trace KAIROS alert groups forward, accumulating and updating one graph."""
    config = config or CausalSearchConfig()
    edge_cache = edge_cache or DirectionalEdgeCache(store)
    materialized = []
    for group_id, event_ids in alert_groups:
        alerts = [
            edge for event_id in sorted(event_ids)
            if (edge := store.get_edge_by_event_id(event_id)) is not None
        ]
        if alerts:
            materialized.append((min(edge.timestamp_ns for edge in alerts), group_id, alerts))
    materialized.sort(key=lambda item: (item[0], item[1]))

    cumulative: dict[int, StoredEdge] = {}
    cumulative_nodes = {}
    all_paths: list[list[StoredEdge]] = []
    all_forward: list[list[StoredEdge]] = []
    active_alerts: set[str] = set()
    seeds: set[str] = set()
    all_reasons: Counter[str] = Counter()
    all_excluded: dict[str, str] = {}
    total_truncated = 0
    steps: list[CumulativeForwardStep] = []

    for alert_time, group_id, alerts in materialized:
        local: dict[int, StoredEdge] = {}
        local_paths: list[list[StoredEdge]] = []
        local_reasons: Counter[str] = Counter()
        local_excluded: dict[str, str] = {}
        local_truncated = 0
        for alert in sorted(alerts, key=lambda edge: (edge.timestamp_ns, edge.edge_id)):
            active_alerts.add(alert.event_id)
            seeds.add(alert.dst)
            local[alert.edge_id] = alert
            for instance in edge_cache.dependency_instances(alert):
                local[instance.edge_id] = instance
            forward = _expand_graph(
                store, model, start_node=alert.dst, alert_time=alert.timestamp_ns,
                direction="forward", config=config, selected_edges=local,
                edge_cache=edge_cache,
            )
            paths = [
                [alert, *path] for path in forward.complete_paths
                if _is_simple_causal_path([alert, *path])
            ]
            local_paths.extend(paths)
            all_forward.extend(forward.complete_paths)
            local_reasons.update(forward.termination_reasons)
            local_excluded.update(forward.excluded_event_reasons)
            local_truncated += forward.truncated_path_count

        previous_ids = set(cumulative)
        overlap = len(previous_ids & set(local))
        cumulative.update(local)
        local_graph = store.neighborhood_from_edges(local.values())
        cumulative_nodes.update(local_graph.nodes)
        steps.append(CumulativeForwardStep(
            group_id=group_id,
            alert_event_ids=tuple(edge.event_id for edge in alerts),
            alert_time_ns=alert_time,
            graph=local_graph,
            new_event_count=len(set(local) - previous_ids),
            overlap_event_count=overlap,
            cumulative_event_count=len(cumulative),
            complete_path_count=len(local_paths),
            truncated_path_count=local_truncated,
            termination_reasons=dict(local_reasons),
        ))
        all_paths.extend(local_paths)
        all_reasons.update(local_reasons)
        all_excluded.update(local_excluded)
        total_truncated += local_truncated

    context = AlertContext(
        graph=Neighborhood(cumulative_nodes, list(cumulative.values())),
        paths=all_paths,
        forward_paths=all_forward,
        alert_event_ids=active_alerts,
        seed_uuids=seeds,
        complete_path_count=len(all_paths),
        truncated_path_count=total_truncated,
        termination_reasons=dict(all_reasons),
        excluded_event_reasons=all_excluded,
    )
    return CumulativeForwardResult(context=context, steps=steps)


__all__ = [
    "AlertContext", "CausalSearchConfig", "CumulativeForwardResult",
    "CumulativeForwardStep", "DirectionalEdgeCache", "build_alert_context",
    "build_cumulative_forward_contexts",
]
