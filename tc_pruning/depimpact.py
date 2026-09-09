from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import math
import time

import numpy as np

from .models import Neighborhood, StoredEdge


@dataclass(slots=True)
class EdgeMergeResult:
    edges: list[StoredEdge]
    groups: dict[int, tuple[int, ...]]
    original_edge_count: int
    merged_edge_count: int


@dataclass(slots=True)
class DependencyImpactAnalysis:
    edge_importance: dict[int, float]
    normalized_edge_weights: dict[int, float]
    features: dict[int, tuple[float | None, float, float]]
    projection: tuple[float, float, float]
    original_edge_count: int
    merged_edge_count: int
    data_size_coverage: float
    node_impacts: dict[str, float]
    converged: bool
    propagation_iterations: int
    convergence_delta: float
    merge_groups: dict[int, tuple[int, ...]]
    propagation_diagnostics: list[dict[str, float | int]]
    feature_mask: tuple[bool, bool, bool]
    phase_seconds: dict[str, float]


@dataclass(slots=True)
class DependencyImpactPropagation:
    node_impacts: dict[str, float]
    edge_impacts: dict[int, float]
    iterations: int
    converged: bool
    delta: float
    diagnostics: list[dict[str, float | int]]


def backpropagate_dependency_impact(
    graph: Neighborhood,
    *,
    poi_edge_ids: set[int],
    edge_weights: dict[int, float],
    tolerance: float = 1e-13,
    max_iterations: int | None = None,
) -> DependencyImpactPropagation:
    """Implement DEPIMPACT Equation 7 with fixed POI endpoint scores."""
    if tolerance <= 0.0:
        raise ValueError("tolerance must be positive")
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    poi_nodes = {
        endpoint
        for edge_id in poi_edge_ids
        if (edge := edge_by_id.get(edge_id)) is not None
        for endpoint in (edge.src, edge.dst)
    }
    nodes = set(graph.nodes) | {
        endpoint for edge in graph.edges for endpoint in (edge.src, edge.dst)
    }
    outgoing: dict[str, list[StoredEdge]] = defaultdict(list)
    incoming: dict[str, list[StoredEdge]] = defaultdict(list)
    reverse_hops = {node: 0 for node in poi_nodes}
    hop_frontier = list(poi_nodes)
    for edge in graph.edges:
        outgoing[edge.src].append(edge)
        incoming[edge.dst].append(edge)
    hop_frontier = deque(hop_frontier)
    while hop_frontier:
        destination = hop_frontier.popleft()
        for edge in incoming.get(destination, []):
            if edge.src not in reverse_hops:
                reverse_hops[edge.src] = reverse_hops[destination] + 1
                hop_frontier.append(edge.src)
    scores = {node: (1.0 if node in poi_nodes else 0.0) for node in nodes}
    converged = False
    delta = math.inf
    iterations = 0
    diagnostics: list[dict[str, float | int]] = []
    while True:
        iteration = iterations + 1
        updated = dict(scores)
        delta = 0.0
        max_delta = 0.0
        for node in nodes:
            if node in poi_nodes:
                updated[node] = 1.0
                continue
            value = sum(
                scores.get(edge.dst, 0.0) * max(0.0, edge_weights.get(edge.edge_id, 0.0))
                for edge in outgoing.get(node, [])
            )
            value = min(1.0, max(0.0, value))
            change = abs(scores[node] - value)
            delta += change
            max_delta = max(max_delta, change)
            updated[node] = value
        active = {node for node, value in updated.items() if value > 0.0}
        diagnostics.append({
            "iteration": iteration,
            "nonzero_nodes": len(active),
            "max_reached_hop": max(
                (reverse_hops[node] for node in active if node in reverse_hops),
                default=0,
            ),
            "sum_score": sum(updated.values()),
            "l1_delta": delta,
            "max_delta": max_delta,
        })
        scores = updated
        iterations = iteration
        if delta < tolerance:
            converged = True
            break
        if max_iterations is not None and iteration >= max_iterations:
            break
    edge_impacts = {
        edge.edge_id: (
            1.0
            if edge.edge_id in poi_edge_ids
            else min(
                1.0,
                max(0.0, scores.get(edge.dst, 0.0))
                * max(0.0, edge_weights.get(edge.edge_id, 0.0)),
            )
        )
        for edge in graph.edges
    }
    return DependencyImpactPropagation(
        scores, edge_impacts, iterations, converged, delta, diagnostics
    )


def merge_parallel_edges(
    graph: Neighborhood, *, threshold_seconds: float = 10.0
) -> EdgeMergeResult:
    if threshold_seconds < 0.0:
        raise ValueError("threshold_seconds must be non-negative")
    threshold_ns = int(threshold_seconds * 1_000_000_000)
    by_dependency: dict[tuple[str, str, str], list[StoredEdge]] = defaultdict(list)
    for edge in graph.edges:
        by_dependency[(edge.src, edge.dst, edge.relation)].append(edge)

    merged: list[StoredEdge] = []
    groups: dict[int, tuple[int, ...]] = {}
    for edges in by_dependency.values():
        ordered = sorted(edges, key=lambda item: (item.timestamp_ns, item.edge_id))
        current: list[StoredEdge] = []
        for edge in ordered:
            if current and edge.timestamp_ns - current[-1].timestamp_ns > threshold_ns:
                _append_merge_group(current, merged, groups)
                current = []
            current.append(edge)
        if current:
            _append_merge_group(current, merged, groups)
    merged.sort(key=lambda edge: (edge.timestamp_ns, edge.edge_id))
    return EdgeMergeResult(
        edges=merged,
        groups=groups,
        original_edge_count=len(graph.edges),
        merged_edge_count=len(merged),
    )


def _append_merge_group(
    members: list[StoredEdge],
    output: list[StoredEdge],
    groups: dict[int, tuple[int, ...]],
) -> None:
    representative = members[0]
    known_sizes = [edge.data_size for edge in members if edge.data_size is not None]
    merged_size = sum(known_sizes) if known_sizes else None
    end = members[-1]
    output.append(
        StoredEdge(
            edge_id=representative.edge_id,
            event_id=representative.event_id,
            src=representative.src,
            dst=representative.dst,
            relation=representative.relation,
            timestamp_ns=end.timestamp_ns,
            host=representative.host,
            src_type=representative.src_type,
            dst_type=representative.dst_type,
            src_semantic=representative.src_semantic,
            dst_semantic=representative.dst_semantic,
            data_size=merged_size,
        )
    )
    groups[representative.edge_id] = tuple(edge.edge_id for edge in members)


def data_flow_relevance(
    edge_size: int | None, poi_size: int | None, *, alpha: float = 1e-4
) -> float | None:
    if alpha <= 0.0:
        raise ValueError("alpha must be positive")
    if edge_size is None or poi_size is None:
        return None
    return 1.0 / (abs(float(edge_size) - float(poi_size)) + alpha)


def temporal_relevance(
    edge_time_ns: int, poi_time_ns: int, *, zero_delta_seconds: float = 1e-10
) -> float:
    if zero_delta_seconds <= 0.0:
        raise ValueError("zero_delta_seconds must be positive")
    delta = abs(int(edge_time_ns) - int(poi_time_ns)) / 1_000_000_000
    return math.log1p(1.0 / max(delta, zero_delta_seconds))


def concentration_ratio(graph: Neighborhood, edge: StoredEdge) -> float:
    incoming = sum(candidate.dst == edge.dst for candidate in graph.edges)
    outgoing = sum(candidate.src == edge.dst for candidate in graph.edges)
    return outgoing / max(1, incoming)


def _minmax_features(raw: list[tuple[float | None, float, float]]) -> np.ndarray:
    matrix = np.asarray(
        [[np.nan if value is None else float(value) for value in row] for row in raw],
        dtype=float,
    )
    for column in range(matrix.shape[1]):
        values = matrix[:, column]
        known = values[~np.isnan(values)]
        fill = float(np.median(known)) if known.size else 0.0
        values[np.isnan(values)] = fill
        minimum, maximum = float(values.min()), float(values.max())
        matrix[:, column] = (
            (values - minimum) / (maximum - minimum)
            if maximum > minimum
            else 0.5
        )
    return matrix


def _two_means(
    matrix: np.ndarray, *, restarts: int, random_seed: int
) -> np.ndarray | None:
    if len(matrix) < 2 or np.allclose(matrix, matrix[0]):
        return None
    rng = np.random.default_rng(random_seed)
    best_labels: np.ndarray | None = None
    best_inertia = math.inf
    for _ in range(max(1, restarts)):
        first = int(rng.integers(0, len(matrix)))
        distances = np.sum((matrix - matrix[first]) ** 2, axis=1)
        if float(distances.sum()) <= 0.0:
            continue
        second = int(rng.choice(len(matrix), p=distances / distances.sum()))
        centers = np.asarray([matrix[first], matrix[second]], dtype=float)
        labels = np.zeros(len(matrix), dtype=int)
        for _iteration in range(100):
            new_labels = np.argmin(
                np.sum((matrix[:, None, :] - centers[None, :, :]) ** 2, axis=2),
                axis=1,
            )
            if _iteration and np.array_equal(new_labels, labels):
                break
            labels = new_labels
            if len(set(labels.tolist())) < 2:
                break
            centers = np.asarray([matrix[labels == label].mean(axis=0) for label in (0, 1)])
        if len(set(labels.tolist())) < 2:
            continue
        inertia = float(sum(np.sum((matrix[labels == label] - centers[label]) ** 2) for label in (0, 1)))
        if inertia < best_inertia:
            best_inertia = inertia
            best_labels = labels.copy()
    return best_labels


def _projection(
    matrix: np.ndarray, *, restarts: int, random_seed: int
) -> np.ndarray:
    active = np.ptp(matrix, axis=0) > 1e-12
    if not np.all(active):
        result = np.zeros(matrix.shape[1], dtype=float)
        if np.any(active):
            result[active] = _projection(
                matrix[:, active], restarts=restarts, random_seed=random_seed
            )
        return result
    labels = _two_means(matrix, restarts=restarts, random_seed=random_seed)
    if labels is None:
        return np.full(matrix.shape[1], 1.0 / matrix.shape[1])
    groups = [matrix[labels == label] for label in (0, 1)]
    counts = [len(group) for group in groups]
    if counts[0] != counts[1]:
        critical = 0 if counts[0] < counts[1] else 1
    else:
        critical = 0 if groups[0].mean(axis=0).sum() >= groups[1].mean(axis=0).sum() else 1
    other = 1 - critical
    within = np.zeros((matrix.shape[1], matrix.shape[1]), dtype=float)
    for group in groups:
        centered = group - group.mean(axis=0)
        within += centered.T @ centered
    direction = np.linalg.pinv(within + np.eye(matrix.shape[1]) * 1e-6) @ (
        groups[critical].mean(axis=0) - groups[other].mean(axis=0)
    )
    norm = float(np.linalg.norm(direction))
    return direction / norm if norm > 0.0 else np.full(matrix.shape[1], 1.0 / matrix.shape[1])


def compute_depimpact_relevance(
    graph: Neighborhood,
    *,
    poi_edge_ids: set[int],
    merge_threshold_seconds: float = 10.0,
    alpha: float = 1e-4,
    kmeans_restarts: int = 20,
    random_seed: int = 0,
    projection_override: tuple[float, float, float] | None = None,
    feature_mask: tuple[bool, bool, bool] = (True, True, True),
) -> DependencyImpactAnalysis:
    if len(feature_mask) != 3 or not any(feature_mask):
        raise ValueError("feature_mask must enable at least one of three features")
    if projection_override is not None:
        if len(projection_override) != 3 or not all(
            math.isfinite(float(value)) for value in projection_override
        ):
            raise ValueError("projection_override must contain three finite values")
    total_started = time.perf_counter()
    merge_started = time.perf_counter()
    merge = merge_parallel_edges(graph, threshold_seconds=merge_threshold_seconds)
    merge_seconds = time.perf_counter() - merge_started
    if not merge.edges:
        return DependencyImpactAnalysis(
            {}, {}, {}, (1 / 3, 1 / 3, 1 / 3), 0, 0, 0.0, {}, True, 0,
            0.0, {}, [], feature_mask,
            {
                "edge_merge": merge_seconds,
                "dependency_weight_computation": 0.0,
                "dependency_impact_propagation": 0.0,
                "total": time.perf_counter() - total_started,
            },
        )
    weight_started = time.perf_counter()
    member_to_representative = {
        member: representative
        for representative, members in merge.groups.items()
        for member in members
    }
    poi_representatives = {
        member_to_representative[edge_id]
        for edge_id in poi_edge_ids
        if edge_id in member_to_representative
    }
    poi_edges = [edge for edge in merge.edges if edge.edge_id in poi_representatives]
    if not poi_edges:
        raise ValueError("none of the POI edges exist in the candidate graph")
    merged_graph = Neighborhood(graph.nodes, merge.edges)
    indegree: dict[str, int] = defaultdict(int)
    outdegree: dict[str, int] = defaultdict(int)
    for candidate in merge.edges:
        indegree[candidate.dst] += 1
        outdegree[candidate.src] += 1
    raw_by_edge: dict[int, tuple[float | None, float, float]] = {}
    for edge in merge.edges:
        concentration = outdegree[edge.dst] / max(1, indegree[edge.dst])
        per_poi = [
            (
                data_flow_relevance(edge.data_size, poi.data_size, alpha=alpha),
                temporal_relevance(edge.timestamp_ns, poi.timestamp_ns),
                concentration,
            )
            for poi in poi_edges
        ]
        raw_by_edge[edge.edge_id] = max(
            per_poi,
            key=lambda row: sum(value for value in row if value is not None),
        )
    ordered_ids = [edge.edge_id for edge in merge.edges]
    matrix = _minmax_features([raw_by_edge[edge_id] for edge_id in ordered_ids])
    active = np.asarray(feature_mask, dtype=bool)
    matrix[:, ~active] = 0.0
    if projection_override is not None:
        projection = np.asarray(projection_override, dtype=float)
    elif int(active.sum()) == 1:
        projection = active.astype(float)
    else:
        projection = _projection(
            matrix, restarts=kmeans_restarts, random_seed=random_seed
        )
    projection = projection.copy()
    projection[~active] = 0.0
    projected = matrix @ projection
    minimum, maximum = float(projected.min()), float(projected.max())
    relevance = (
        (projected - minimum) / (maximum - minimum)
        if maximum > minimum
        else np.ones(len(projected), dtype=float)
    )
    relevance = relevance + 1e-12
    by_source: dict[str, list[int]] = defaultdict(list)
    for index, edge in enumerate(merge.edges):
        by_source[edge.src].append(index)
    for indexes in by_source.values():
        total = float(sum(relevance[index] for index in indexes))
        for index in indexes:
            relevance[index] = (
                relevance[index] / total * 0.99
                if total > 0.0 else 0.99 / len(indexes)
            )

    representative_scores = {
        edge_id: float(relevance[index]) for index, edge_id in enumerate(ordered_ids)
    }
    expanded_weights = {
        member: representative_scores[representative]
        for representative, members in merge.groups.items()
        for member in members
    }
    known_sizes = sum(edge.data_size is not None for edge in graph.edges)
    weight_seconds = time.perf_counter() - weight_started
    propagation_started = time.perf_counter()
    propagation = backpropagate_dependency_impact(
        merged_graph,
        poi_edge_ids=poi_representatives,
        edge_weights=representative_scores,
    )
    propagation_seconds = time.perf_counter() - propagation_started
    expanded_impacts = {
        member: propagation.edge_impacts[representative]
        for representative, members in merge.groups.items()
        for member in members
    }
    return DependencyImpactAnalysis(
        edge_importance=expanded_impacts,
        normalized_edge_weights=expanded_weights,
        features=raw_by_edge,
        projection=tuple(float(value) for value in projection),
        original_edge_count=merge.original_edge_count,
        merged_edge_count=merge.merged_edge_count,
        data_size_coverage=known_sizes / len(graph.edges),
        node_impacts=propagation.node_impacts,
        converged=propagation.converged,
        propagation_iterations=propagation.iterations,
        convergence_delta=propagation.delta,
        merge_groups=merge.groups,
        propagation_diagnostics=propagation.diagnostics,
        feature_mask=feature_mask,
        phase_seconds={
            "edge_merge": merge_seconds,
            "dependency_weight_computation": weight_seconds,
            "dependency_impact_propagation": propagation_seconds,
            "total": time.perf_counter() - total_started,
        },
    )


__all__ = [
    "DependencyImpactAnalysis",
    "DependencyImpactPropagation",
    "EdgeMergeResult",
    "compute_depimpact_relevance",
    "backpropagate_dependency_impact",
    "concentration_ratio",
    "data_flow_relevance",
    "merge_parallel_edges",
    "temporal_relevance",
]
