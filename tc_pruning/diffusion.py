from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from collections import deque

from .cdm import event_investigation_anchor
from .models import Neighborhood, StoredEdge


@dataclass(slots=True)
class DiffusionResult:
    scores: dict[str, float]
    predecessors: dict[str, int]
    iterations: int
    converged: bool
    diagnostics: list[dict[str, float | int]]
    edge_scores: dict[int, float] = field(default_factory=dict)
    mode: str = "undirected_ppr"


def _hop_distances(
    adjacency: dict[str, list[tuple[str, int, float]]], seeds: set[str]
) -> dict[str, int]:
    distances = {seed: 0 for seed in seeds if seed in adjacency}
    queue = deque(distances)
    while queue:
        node = queue.popleft()
        for neighbor, _, _ in adjacency.get(node, []):
            if neighbor not in distances:
                distances[neighbor] = distances[node] + 1
                queue.append(neighbor)
    return distances


def _adjacency(
    graph: Neighborhood,
    edge_rarity: dict[int, float],
    edge_affinity: dict[int, float] | None = None,
) -> dict[str, list[tuple[str, int, float]]]:
    adjacency: dict[str, list[tuple[str, int, float]]] = {
        uuid: [] for uuid in graph.nodes
    }
    edge_affinity = edge_affinity or {}
    for edge in graph.edges:
        rarity = min(1.0, max(0.0, edge_rarity.get(edge.edge_id, 0.0)))
        affinity = min(1.0, max(0.0, edge_affinity.get(edge.edge_id, rarity)))
        # DEPIMPACT affinity receives more weight than rarity so a common edge
        # on the causal route to a POI can outrank a disconnected rare event.
        transmission = 0.05 + 0.95 * (
            0.35 * rarity + 0.65 * affinity
        )
        adjacency.setdefault(edge.src, []).append(
            (edge.dst, edge.edge_id, transmission)
        )
        adjacency.setdefault(edge.dst, []).append(
            (edge.src, edge.edge_id, transmission)
        )
    return adjacency


def _maximum_transmission_predecessors(
    adjacency: dict[str, list[tuple[str, int, float]]], seeds: set[str]
) -> dict[str, int]:
    best = {seed: 1.0 for seed in seeds if seed in adjacency}
    predecessors: dict[str, int] = {}
    queue = [(-1.0, seed) for seed in best]
    heapq.heapify(queue)
    while queue:
        negative_score, node = heapq.heappop(queue)
        score = -negative_score
        if score < best.get(node, 0.0):
            continue
        for neighbor, edge_id, transmission in adjacency.get(node, []):
            candidate = score * transmission
            if candidate > best.get(neighbor, -1.0):
                best[neighbor] = candidate
                predecessors[neighbor] = edge_id
                heapq.heappush(queue, (-candidate, neighbor))
    return predecessors


def _transmission(
    edge: StoredEdge,
    edge_rarity: dict[int, float],
    edge_affinity: dict[int, float],
) -> float:
    rarity = min(1.0, max(0.0, edge_rarity.get(edge.edge_id, 0.0)))
    affinity = min(
        1.0, max(0.0, edge_affinity.get(edge.edge_id, rarity))
    )
    return 0.05 + 0.95 * (0.35 * rarity + 0.65 * affinity)


def _causal_endpoints(edge: StoredEdge) -> tuple[str, str]:
    # CDM read-like events are normalized object -> process at ingest time.
    # EXECUTE remains process -> executable in the raw schema even though the
    # executable supplies information to the process, so reverse it here.
    if edge.relation.upper() == "EVENT_EXECUTE":
        return edge.dst, edge.src
    return edge.src, edge.dst


def _time_respecting_bidirectional_diffusion(
    graph: Neighborhood,
    seeds: set[str],
    edge_rarity: dict[int, float],
    *,
    edge_affinity: dict[int, float] | None,
    damping: float,
    seed_edges: list[StoredEdge],
) -> DiffusionResult:
    if not graph.edges:
        return DiffusionResult({}, {}, 0, True, [], {}, "time_respecting_bidir")
    affinity = edge_affinity or {}
    causal = {
        edge.edge_id: _causal_endpoints(edge) for edge in graph.edges
    }
    outgoing_degree: dict[str, int] = {}
    incoming_degree: dict[str, int] = {}
    for source, target in causal.values():
        outgoing_degree[source] = outgoing_degree.get(source, 0) + 1
        incoming_degree[target] = incoming_degree.get(target, 0) + 1

    seed_points = [
        (event_investigation_anchor(edge), edge.timestamp_ns)
        for edge in seed_edges
    ]
    if not seed_points:
        incident_times: dict[str, list[int]] = {seed: [] for seed in seeds}
        for edge in graph.edges:
            for seed in seeds & {edge.src, edge.dst}:
                incident_times[seed].append(edge.timestamp_ns)
        seed_points = [
            (seed, min(times))
            for seed, times in incident_times.items()
            if times
        ]
    if not seed_points:
        seed_points = [
            (node, min(edge.timestamp_ns for edge in graph.edges))
            for node in seeds
        ]

    forward_scores: dict[str, float] = {}
    backward_scores: dict[str, float] = {}
    forward_edges: dict[int, float] = {}
    backward_edges: dict[int, float] = {}
    predecessors: dict[str, int] = {}

    forward_seeds = sorted(seed_points, key=lambda item: item[1])
    seed_index = 0
    for edge in sorted(graph.edges, key=lambda item: (item.timestamp_ns, item.edge_id)):
        while seed_index < len(forward_seeds) and forward_seeds[seed_index][1] <= edge.timestamp_ns:
            node, _ = forward_seeds[seed_index]
            forward_scores[node] = max(1.0, forward_scores.get(node, 0.0))
            seed_index += 1
        source, target = causal[edge.edge_id]
        source_score = forward_scores.get(source, 0.0)
        if source_score <= 0.0:
            continue
        candidate = (
            damping
            * source_score
            * _transmission(edge, edge_rarity, affinity)
            / math.sqrt(max(1, outgoing_degree.get(source, 1)))
        )
        forward_edges[edge.edge_id] = max(
            candidate, forward_edges.get(edge.edge_id, 0.0)
        )
        if candidate > forward_scores.get(target, 0.0):
            forward_scores[target] = candidate
            predecessors[target] = edge.edge_id

    backward_seeds = sorted(seed_points, key=lambda item: item[1], reverse=True)
    seed_index = 0
    for edge in sorted(
        graph.edges, key=lambda item: (item.timestamp_ns, item.edge_id), reverse=True
    ):
        while seed_index < len(backward_seeds) and backward_seeds[seed_index][1] >= edge.timestamp_ns:
            node, _ = backward_seeds[seed_index]
            backward_scores[node] = max(1.0, backward_scores.get(node, 0.0))
            seed_index += 1
        source, target = causal[edge.edge_id]
        target_score = backward_scores.get(target, 0.0)
        if target_score <= 0.0:
            continue
        candidate = (
            damping
            * target_score
            * _transmission(edge, edge_rarity, affinity)
            / math.sqrt(max(1, incoming_degree.get(target, 1)))
        )
        backward_edges[edge.edge_id] = max(
            candidate, backward_edges.get(edge.edge_id, 0.0)
        )
        if candidate > backward_scores.get(source, 0.0):
            backward_scores[source] = candidate
            predecessors[source] = edge.edge_id

    edge_scores = {
        edge.edge_id: max(
            forward_edges.get(edge.edge_id, 0.0),
            backward_edges.get(edge.edge_id, 0.0),
            1.0 if edge in seed_edges else 0.0,
        )
        for edge in graph.edges
    }
    node_scores = {
        node: max(forward_scores.get(node, 0.0), backward_scores.get(node, 0.0))
        for node in {
            *graph.nodes,
            *(edge.src for edge in graph.edges),
            *(edge.dst for edge in graph.edges),
        }
    }
    max_edge = max(edge_scores.values(), default=0.0)
    max_node = max(node_scores.values(), default=0.0)
    if max_edge > 0.0:
        edge_scores = {edge_id: score / max_edge for edge_id, score in edge_scores.items()}
    if max_node > 0.0:
        node_scores = {node: score / max_node for node, score in node_scores.items()}
    diagnostics = [{
        "iteration": 1,
        "nonzero_nodes": sum(score > 0.0 for score in node_scores.values()),
        "max_reached_hop": 0,
        "sum_score": sum(node_scores.values()),
        "l1_delta": 0.0,
        "max_delta": 0.0,
        "forward_nonzero_edges": sum(score > 0.0 for score in forward_edges.values()),
        "backward_nonzero_edges": sum(score > 0.0 for score in backward_edges.values()),
    }]
    return DiffusionResult(
        node_scores, predecessors, 1, True, diagnostics,
        edge_scores, "time_respecting_bidir",
    )


def diffuse_importance(
    graph: Neighborhood,
    seeds: set[str],
    edge_rarity: dict[int, float],
    *,
    edge_affinity: dict[int, float] | None = None,
    damping: float = 0.85,
    tolerance: float = 1e-8,
    max_iterations: int = 200,
    mode: str = "undirected_ppr",
    seed_edges: list[StoredEdge] | None = None,
) -> DiffusionResult:
    """Run POI-affinity and rarity weighted personalized graph diffusion."""
    if not 0.0 <= damping < 1.0:
        raise ValueError("damping must be in [0, 1)")
    if mode not in {"undirected_ppr", "time_respecting_bidir"}:
        raise ValueError("mode must be undirected_ppr or time_respecting_bidir")
    if mode == "time_respecting_bidir":
        return _time_respecting_bidirectional_diffusion(
            graph, seeds, edge_rarity, edge_affinity=edge_affinity,
            damping=damping, seed_edges=list(seed_edges or []),
        )
    nodes = set(graph.nodes)
    for edge in graph.edges:
        nodes.add(edge.src)
        nodes.add(edge.dst)
    if not nodes:
        return DiffusionResult({}, {}, 0, True, [])

    active_seeds = seeds & nodes
    if not active_seeds:
        active_seeds = set(nodes)
    personalization = {
        node: (1.0 / len(active_seeds) if node in active_seeds else 0.0)
        for node in nodes
    }
    scores = dict(personalization)
    adjacency = _adjacency(graph, edge_rarity, edge_affinity)
    hop_distances = _hop_distances(adjacency, active_seeds)
    outgoing_weight = {
        node: sum(weight for _, _, weight in neighbors)
        for node, neighbors in adjacency.items()
    }

    converged = False
    iterations = 0
    diagnostics: list[dict[str, float | int]] = []
    for iteration in range(1, max_iterations + 1):
        updated = {
            node: (1.0 - damping) * personalization[node] for node in nodes
        }
        dangling_mass = 0.0
        for node, score in scores.items():
            total = outgoing_weight.get(node, 0.0)
            if total <= 0:
                dangling_mass += score
                continue
            for neighbor, _, weight in adjacency.get(node, []):
                updated[neighbor] += damping * score * weight / total
        if dangling_mass:
            for node in nodes:
                updated[node] += damping * dangling_mass * personalization[node]
        norm = sum(updated.values())
        if norm > 0:
            updated = {node: value / norm for node, value in updated.items()}
        changes = [abs(updated[node] - scores.get(node, 0.0)) for node in nodes]
        delta = sum(changes)
        active_nodes = {node for node, value in updated.items() if value > 0.0}
        diagnostics.append({
            "iteration": iteration,
            "nonzero_nodes": len(active_nodes),
            "max_reached_hop": max(
                (hop_distances[node] for node in active_nodes if node in hop_distances),
                default=0,
            ),
            "sum_score": sum(updated.values()),
            "l1_delta": delta,
            "max_delta": max(changes, default=0.0),
        })
        scores = updated
        iterations = iteration
        if delta <= tolerance:
            converged = True
            break

    predecessors = _maximum_transmission_predecessors(adjacency, active_seeds)
    return DiffusionResult(
        scores, predecessors, iterations, converged, diagnostics,
        mode="undirected_ppr",
    )


__all__ = ["DiffusionResult", "diffuse_importance"]
