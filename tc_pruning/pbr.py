"""Label-free POI Bridge Rescue layered after the unchanged A_rasp selector."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import heapq
import json
import math
import resource
import time
from typing import Any, Iterable, Mapping, Sequence

from .benchmark_contract import EdgeProjection
from .detector_seed_benchmark import _causal
from .models import StoredEdge


@dataclass(frozen=True, slots=True)
class PBRConfig:
    k_paths: int = 3
    max_states: int = 20_000
    max_path_events: int = 12
    max_gate_path_events: int = 4
    fixed_extra_raw: int = 1_000
    rescue_ratio: float = 0.10
    base_cost: float = 1.0
    normality_weight: float = 0.30
    fanout_weight: float = 0.20
    relation_weight: float = 0.10
    relevance_bonus: float = 0.30
    rarity_bonus: float = 0.20
    compatibility_bonus: float = 0.30
    minimum_edge_cost: float = 0.01

    def __post_init__(self) -> None:
        if self.k_paths <= 0 or self.max_states <= 0:
            raise ValueError("k_paths and max_states must be positive")
        if self.max_path_events <= 0 or self.max_gate_path_events <= 0:
            raise ValueError("path limits must be positive")
        if self.fixed_extra_raw < 0 or self.rescue_ratio < 0:
            raise ValueError("rescue budget must be non-negative")
        if self.minimum_edge_cost <= 0:
            raise ValueError("minimum edge cost must be positive")


@dataclass(frozen=True, slots=True)
class BridgeDemand:
    demand_id: str
    src_poi: str
    dst_poi: str
    gate_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BridgeBundle:
    demand_id: str
    raw_event_ids: tuple[str, ...]
    projected_edges: tuple[str, ...]
    src_poi: str
    dst_poi: str
    relation_sequence: tuple[str, ...]
    timestamps: tuple[int, ...]
    raw_cost: int
    projected_cost: int
    base_path_cost: float
    pair_compatibility: float
    compatibility_components: Mapping[str, float]
    counterfactual_essentiality: float
    alternative_path_count: int
    replay_witness: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PBRResult:
    selected_raw_event_ids: tuple[str, ...]
    added_raw_event_ids: tuple[str, ...]
    cleanup_removed_event_ids: tuple[str, ...]
    demands: tuple[BridgeDemand, ...]
    considered_bundles: tuple[BridgeBundle, ...]
    selected_bundles: tuple[BridgeBundle, ...]
    rescued_demands: tuple[str, ...]
    metrics: Mapping[str, int | float]
    decision_sha256: str


@dataclass(frozen=True, slots=True)
class _CausalEdge:
    edge: StoredEdge
    source: str
    target: str


@dataclass(frozen=True, slots=True)
class _Path:
    edges: tuple[_CausalEdge, ...]
    cost: float


def _clip(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _canonical_sha(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def _index(edges: Sequence[StoredEdge]) -> tuple[dict[str, tuple[_CausalEdge, ...]], dict[str, _CausalEdge]]:
    outgoing: dict[str, list[_CausalEdge]] = {}
    by_event: dict[str, _CausalEdge] = {}
    for edge in edges:
        try:
            source, target = _causal(edge)
        except ValueError:
            continue
        causal = _CausalEdge(edge, source, target)
        outgoing.setdefault(source, []).append(causal)
        by_event[edge.event_id] = causal
    return (
        {
            node: tuple(sorted(rows, key=lambda row: (row.edge.timestamp_ns, row.edge.event_id)))
            for node, rows in outgoing.items()
        },
        by_event,
    )


def _strict_paths(
    outgoing: Mapping[str, Sequence[_CausalEdge]],
    source: str,
    target: str,
    *,
    costs: Mapping[str, float],
    k: int,
    max_events: int,
    max_states: int,
    allowed: frozenset[str] | None = None,
    banned: frozenset[str] = frozenset(),
) -> tuple[_Path, ...]:
    heap: list[tuple[float, int, str, int, tuple[_CausalEdge, ...], frozenset[str]]] = []
    heapq.heappush(heap, (0.0, 0, source, -(2**63), (), frozenset({source})))
    serial = states = 0
    found: list[_Path] = []
    while heap and len(found) < k and states < max_states:
        cost, _, node, last_time, path, visited = heapq.heappop(heap)
        states += 1
        if node == target and path:
            found.append(_Path(path, cost))
            continue
        if len(path) >= max_events:
            continue
        for causal in outgoing.get(node, ()):
            event_id = causal.edge.event_id
            if event_id in banned or (allowed is not None and event_id not in allowed):
                continue
            if causal.edge.timestamp_ns <= last_time or causal.target in visited:
                continue
            serial += 1
            heapq.heappush(
                heap,
                (
                    cost + max(0.0, float(costs.get(event_id, 1.0))),
                    serial,
                    causal.target,
                    causal.edge.timestamp_ns,
                    path + (causal,),
                    visited | {causal.target},
                ),
            )
    return tuple(found)


def _is_reachable(
    outgoing: Mapping[str, Sequence[_CausalEdge]], source: str, target: str,
    selected: frozenset[str], max_events: int, max_states: int,
) -> bool:
    return bool(_strict_paths(
        outgoing, source, target, costs={}, k=1, max_events=max_events,
        max_states=max_states, allowed=selected,
    ))


def _pair_features(
    path: _Path,
    demand: BridgeDemand,
    relevance: Mapping[str, float],
    branch_provenance: Mapping[str, tuple[str, ...]],
) -> tuple[float, dict[str, float]]:
    relations = {row.edge.relation.upper() for row in path.edges}
    flow = _clip(len(relations & {
        "EVENT_READ", "EVENT_WRITE", "EVENT_EXECUTE", "EVENT_FORK",
        "EVENT_CLONE", "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_CONNECT",
    }) / max(1, len(relations)))
    endpoint = _clip(sum(
        row.source == demand.src_poi or row.target == demand.dst_poi for row in path.edges
    ) / len(path.edges))
    relevance_value = sum(_clip(relevance.get(row.edge.event_id, 0.0)) for row in path.edges) / len(path.edges)
    branches = [set(branch_provenance.get(row.edge.event_id, ())) for row in path.edges]
    branch = 1.0 if branches and set.intersection(*branches) else 0.0
    semantics = {
        value for row in path.edges for value in (row.edge.src_semantic, row.edge.dst_semantic)
        if value
    }
    shared_resource = 1.0 if len(semantics) < len(path.edges) * 2 and semantics else 0.0
    temporal_position = 1.0 / len(path.edges)
    components = {
        "relation_compatibility": flow,
        "process_lineage": endpoint,
        "shared_resource_semantics": shared_resource,
        "branch_support": branch,
        "historical_interaction": endpoint,
        "temporal_position": temporal_position,
        "a_rasp_relevance": relevance_value,
    }
    return sum(components.values()) / len(components), components


def rescue_poi_bridges(
    *,
    candidate_edges: Sequence[StoredEdge],
    base_selected_event_ids: frozenset[str],
    poi_node_ids: frozenset[str],
    mandatory_event_ids: frozenset[str],
    projection: EdgeProjection,
    relevance: Mapping[str, float] | None = None,
    rarity: Mapping[str, float] | None = None,
    branch_provenance: Mapping[str, tuple[str, ...]] | None = None,
    proxy_groups: Mapping[str, str] | None = None,
    demand_pairs: frozenset[tuple[str, str]] | None = None,
    config: PBRConfig = PBRConfig(),
) -> PBRResult:
    """Rescue gated disconnected POI pairs without reselecting A_rasp output."""
    started = time.perf_counter()
    relevance = relevance or {}
    rarity = rarity or {}
    provenance = branch_provenance or {}
    proxy_groups = proxy_groups or {}
    outgoing, by_event = _index(candidate_edges)
    max_degree = max((len(rows) for rows in outgoing.values()), default=1)
    edge_costs: dict[str, float] = {}

    # Pair-independent normalized cost terms. Pair compatibility is applied
    # after path discovery and remains visible in each bundle.
    for event_id, row in by_event.items():
        rel = row.edge.relation.upper()
        relation_penalty = 0.0 if rel in {
            "EVENT_READ", "EVENT_WRITE", "EVENT_EXECUTE", "EVENT_FORK", "EVENT_CLONE"
        } else 1.0
        fanout = len(outgoing.get(row.source, ())) / max_degree
        rare = _clip(rarity.get(event_id, 0.0))
        relevant = _clip(relevance.get(event_id, 0.0))
        edge_costs[event_id] = max(
            config.minimum_edge_cost,
            config.base_cost
            + config.normality_weight * (1.0 - rare)
            + config.fanout_weight * fanout
            + config.relation_weight * relation_penalty
            - config.relevance_bonus * relevant
            - config.rarity_bonus * rare,
        )

    shortest_calls = counterfactual_calls = already_reachable = 0
    demands: list[BridgeDemand] = []
    paths_by_demand: dict[str, tuple[_Path, ...]] = {}
    pois = sorted(poi_node_ids)
    pairs = (
        tuple((source, target) for source in pois for target in pois if source != target)
        if demand_pairs is None else
        tuple(sorted(
            (str(source), str(target))
            for source, target in demand_pairs
            if source != target and source in poi_node_ids and target in poi_node_ids
        ))
    )
    for source, target in pairs:
        if _is_reachable(
            outgoing, source, target, base_selected_event_ids,
            config.max_path_events, config.max_states,
        ):
            already_reachable += 1
            continue
        shortest_calls += 1
        paths = _strict_paths(
            outgoing, source, target, costs=edge_costs, k=config.k_paths,
            max_events=config.max_path_events, max_states=config.max_states,
        )
        if not paths:
            continue
        reasons: list[str] = []
        if proxy_groups.get(source) and proxy_groups.get(source) == proxy_groups.get(target):
            reasons.append("SHARED_PROXY_GROUP")
        branch_sets = [
            set(provenance.get(row.edge.event_id, ())) for row in paths[0].edges
        ]
        if branch_sets and set.intersection(*branch_sets):
            reasons.append("SHARED_BRANCH_SUPPORT")
        if len(paths[0].edges) <= config.max_gate_path_events:
            reasons.append("SHORT_STRICT_CANDIDATE_PATH")
        if not reasons:
            continue
        demand = BridgeDemand(f"{source}->{target}", source, target, tuple(reasons))
        demands.append(demand)
        paths_by_demand[demand.demand_id] = paths

    bundles: list[BridgeBundle] = []
    for demand in demands:
        paths = paths_by_demand[demand.demand_id]
        best_cost = paths[0].cost
        for path_index, path in enumerate(paths):
            compatibility, components = _pair_features(path, demand, relevance, provenance)
            adjusted_cost = max(
                config.minimum_edge_cost,
                path.cost - config.compatibility_bonus * compatibility,
            )
            event_ids = tuple(row.edge.event_id for row in path.edges)
            counterfactual_calls += 1
            alternate = _strict_paths(
                outgoing, demand.src_poi, demand.dst_poi, costs=edge_costs, k=1,
                max_events=config.max_path_events, max_states=config.max_states,
                banned=frozenset(event_ids),
            )
            if not alternate:
                essentiality = 1.0
            else:
                without = alternate[0].cost
                essentiality = _clip((without - best_cost) / (without + 1e-12))
            path_edges = tuple(row.edge for row in path.edges)
            raw_ids = tuple(dict.fromkeys(event_ids))
            projected = tuple(sorted(projection.keys(path_edges)))
            bundles.append(BridgeBundle(
                demand.demand_id, raw_ids, projected, demand.src_poi, demand.dst_poi,
                tuple(row.edge.relation.upper() for row in path.edges),
                tuple(row.edge.timestamp_ns for row in path.edges), len(raw_ids),
                len(projected), adjusted_cost, compatibility, components,
                essentiality, len(paths) - 1,
                {
                    "path_rank": path_index,
                    "strict_timestamp_witness": [row.edge.timestamp_ns for row in path.edges],
                    "causal_nodes": [demand.src_poi] + [row.target for row in path.edges],
                },
            ))

    allowance = min(
        config.fixed_extra_raw,
        int(math.floor(config.rescue_ratio * len(base_selected_event_ids))),
    )
    selected = set(base_selected_event_ids)
    selected_bundles: list[BridgeBundle] = []
    rescued: set[str] = set()
    by_demand: dict[str, list[BridgeBundle]] = {}
    for bundle in bundles:
        by_demand.setdefault(bundle.demand_id, []).append(bundle)
    # Lexicographic policy: demand gain is enforced by at most one bundle per
    # demand; quality, cost and redundancy are compared without a lambda sum.
    ordered_demands = sorted(
        demands,
        key=lambda demand: (
            -max((bundle.counterfactual_essentiality for bundle in by_demand[demand.demand_id]), default=0.0),
            demand.demand_id,
        ),
    )
    for demand in ordered_demands:
        choices = sorted(
            by_demand[demand.demand_id],
            key=lambda bundle: (
                -bundle.counterfactual_essentiality,
                -bundle.pair_compatibility,
                bundle.projected_cost,
                bundle.raw_cost,
                len(set(bundle.raw_event_ids) & selected),
                bundle.base_path_cost,
                bundle.raw_event_ids,
            ),
        )
        for bundle in choices:
            additions = set(bundle.raw_event_ids) - selected
            if len((selected - set(base_selected_event_ids)) | additions) > allowance:
                continue
            selected.update(additions)
            selected_bundles.append(bundle)
            rescued.add(demand.demand_id)
            break

    added = set(selected) - set(base_selected_event_ids)
    removed: list[str] = []
    demand_map = {demand.demand_id: demand for demand in demands}
    for event_id in sorted(added, reverse=True):
        if event_id in mandatory_event_ids:
            continue
        trial = frozenset(selected - {event_id})
        if all(_is_reachable(
            outgoing, demand_map[demand_id].src_poi,
            demand_map[demand_id].dst_poi, trial,
            config.max_path_events, config.max_states,
        ) for demand_id in rescued):
            selected.remove(event_id)
            removed.append(event_id)
    rescued = {
        demand_id for demand_id in rescued
        if _is_reachable(
            outgoing, demand_map[demand_id].src_poi, demand_map[demand_id].dst_poi,
            frozenset(selected), config.max_path_events, config.max_states,
        )
    }
    added_ids = tuple(sorted(selected - set(base_selected_event_ids)))
    selected_ids = tuple(sorted(selected))
    elapsed = time.perf_counter() - started
    metrics: dict[str, int | float] = {
        "demand_count": len(pairs),
        "theoretical_all_pair_count": len(pois) * max(0, len(pois) - 1),
        "gated_demand_count": len(demands),
        "already_reachable_count": already_reachable,
        "shortest_path_calls": shortest_calls,
        "counterfactual_recomputes": counterfactual_calls,
        "bundle_count": len(bundles),
        "selected_bundle_count": len(selected_bundles),
        "added_raw_events": len(added_ids),
        "added_projected_edges": projection.count(
            by_event[event_id].edge for event_id in selected_ids if event_id in by_event
        ) - projection.count(
            by_event[event_id].edge for event_id in base_selected_event_ids if event_id in by_event
        ),
        "rescued_reachability_count": len(rescued),
        "rescue_allowance_raw": allowance,
        "pbr_seconds": elapsed,
        "peak_rss_kb": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
    }
    decision = {
        "selected_raw_event_ids": selected_ids,
        "added_raw_event_ids": added_ids,
        "demands": [asdict(row) for row in demands],
        "selected_bundles": [asdict(row) for row in selected_bundles],
        "config": asdict(config),
    }
    return PBRResult(
        selected_ids, added_ids, tuple(sorted(removed)), tuple(demands),
        tuple(bundles), tuple(selected_bundles), tuple(sorted(rescued)), metrics,
        _canonical_sha(decision),
    )


__all__ = [
    "BridgeBundle", "BridgeDemand", "PBRConfig", "PBRResult",
    "rescue_poi_bridges",
]
