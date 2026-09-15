from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import math
import random
from statistics import mean
import time
from typing import Mapping

from .graph_views import InvestigationGraphs, PropagationEdge


@dataclass(frozen=True, slots=True)
class ReverseReachabilityConfig:
    samples: int = 128
    seed: int = 0
    max_hops: int = 12
    max_sketch_size: int = 64
    exhaustive: bool = False
    beta_relation: float = 0.25
    beta_anchor: float = 0.5
    stability_seeds: tuple[int, ...] = ()
    stability_top_k: int = 10
    minimum_stability: float = 0.5

    def __post_init__(self) -> None:
        if self.samples < 1 or self.max_hops < 1 or self.max_sketch_size < 1:
            raise ValueError("reverse reachability budgets must be positive")


@dataclass(frozen=True, slots=True)
class ReverseSketch:
    anchor_id: str
    node_ids: tuple[str, ...]
    reverse_event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RootCandidate:
    node_id: str
    source_support: float
    relation_diversity: float
    path_diversity: int
    anchor_support: float
    root_score: float
    minimum_hops: int
    witness_event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReverseReachabilityResult:
    sketches: tuple[ReverseSketch, ...]
    roots: tuple[RootCandidate, ...]
    number_of_sketches: int
    mean_sketch_size: float
    p95_sketch_size: float
    unique_root_candidates: int
    root_support_distribution: tuple[float, ...]
    sampling_seed: int
    reverse_seconds: float
    stability: float | None
    fallback_mode: str | None


class TemporalReverseReachability:
    def __init__(self, config: ReverseReachabilityConfig) -> None:
        self.config = config

    @staticmethod
    def _percentile(values: list[int], fraction: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        position = (len(ordered) - 1) * fraction
        low = math.floor(position)
        high = math.ceil(position)
        if low == high:
            return float(ordered[low])
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)

    def _index(self, graphs: InvestigationGraphs) -> dict[str, tuple[PropagationEdge, ...]]:
        predecessors: dict[str, list[PropagationEdge]] = defaultdict(list)
        for edge in graphs.propagation_edges:
            predecessors[edge.causal_target].append(edge)
        return {
            node: tuple(sorted(edges, key=lambda edge: (-edge.timestamp_ns, edge.edge_id)))
            for node, edges in predecessors.items()
        }

    def _exhaustive(
        self,
        predecessors: Mapping[str, tuple[PropagationEdge, ...]],
        anchors: Mapping[str, int],
    ) -> tuple[ReverseSketch, ...]:
        sketches = []
        for anchor, anchor_time in sorted(anchors.items()):
            queue = deque([(anchor, anchor_time, (anchor,), ())])
            best_depth: dict[tuple[str, int], int] = {}
            while queue:
                node, current_time, nodes, events = queue.popleft()
                eligible = [
                    edge for edge in predecessors.get(node, ())
                    if edge.timestamp_ns < current_time and edge.causal_source not in nodes
                ]
                if not eligible or len(events) >= self.config.max_hops:
                    sketches.append(ReverseSketch(anchor, nodes, events))
                    continue
                expanded = False
                for edge in eligible:
                    state = (edge.causal_source, edge.timestamp_ns)
                    depth = len(events) + 1
                    if best_depth.get(state, self.config.max_hops + 1) <= depth:
                        continue
                    best_depth[state] = depth
                    expanded = True
                    queue.append((
                        edge.causal_source,
                        edge.timestamp_ns,
                        nodes + (edge.causal_source,),
                        events + (edge.raw_event_id,),
                    ))
                if not expanded:
                    sketches.append(ReverseSketch(anchor, nodes, events))
        return tuple(sketches)

    def _sample(
        self,
        predecessors: Mapping[str, tuple[PropagationEdge, ...]],
        anchors: Mapping[str, int],
        seed: int,
    ) -> tuple[ReverseSketch, ...]:
        rng = random.Random(seed)
        sketches = []
        for anchor, anchor_time in sorted(anchors.items()):
            for _ in range(self.config.samples):
                node = anchor
                current_time = anchor_time
                nodes = [anchor]
                events: list[str] = []
                while len(events) < self.config.max_hops and len(nodes) < self.config.max_sketch_size:
                    eligible = [
                        edge for edge in predecessors.get(node, ())
                        if edge.timestamp_ns < current_time and edge.causal_source not in nodes
                    ]
                    if not eligible:
                        break
                    weights = [max(edge.raw_weight, 1e-300) for edge in eligible]
                    edge = rng.choices(eligible, weights=weights, k=1)[0]
                    node = edge.causal_source
                    current_time = edge.timestamp_ns
                    nodes.append(node)
                    events.append(edge.raw_event_id)
                sketches.append(ReverseSketch(anchor, tuple(nodes), tuple(events)))
        return tuple(sketches)

    def _rank(
        self,
        sketches: tuple[ReverseSketch, ...],
        graphs: InvestigationGraphs,
        anchors: set[str],
    ) -> tuple[RootCandidate, ...]:
        hits = Counter()
        anchor_hits: dict[str, set[str]] = defaultdict(set)
        paths: dict[str, set[tuple[str, ...]]] = defaultdict(set)
        witness: dict[str, tuple[str, ...]] = {}
        minimum_hops: dict[str, int] = {}
        event_family = {edge.raw_event_id: edge.relation_family for edge in graphs.propagation_edges}
        relation_sets: dict[str, set[str]] = defaultdict(set)
        for sketch in sketches:
            for index, node in enumerate(sketch.node_ids[1:], start=1):
                hits[node] += 1
                anchor_hits[node].add(sketch.anchor_id)
                prefix = sketch.reverse_event_ids[:index]
                paths[node].add(prefix)
                relation_sets[node].update(event_family[event] for event in prefix)
                forward_witness = tuple(reversed(prefix))
                if index < minimum_hops.get(node, self.config.max_hops + 1):
                    minimum_hops[node] = index
                    witness[node] = forward_witness
        denominator = max(1, len(sketches))
        anchor_denominator = max(1, len(anchors))
        rows = []
        for node in sorted(set(hits) - anchors):
            support = hits[node] / denominator
            relation_diversity = len(relation_sets[node]) / 7.0
            anchor_support = len(anchor_hits[node]) / anchor_denominator
            raw_score = support * (1 + self.config.beta_relation * relation_diversity) * (1 + self.config.beta_anchor * anchor_support)
            rows.append((node, support, relation_diversity, len(paths[node]), anchor_support, raw_score))
        maximum = max((row[-1] for row in rows), default=1.0) or 1.0
        ranked = [
            RootCandidate(
                node, support, diversity, path_count, anchor_support,
                raw_score / maximum, minimum_hops[node], witness[node],
            )
            for node, support, diversity, path_count, anchor_support, raw_score in rows
        ]
        return tuple(sorted(ranked, key=lambda row: (-row.root_score, -row.minimum_hops, row.node_id)))

    def run(
        self, graphs: InvestigationGraphs, anchors: Mapping[str, int]
    ) -> ReverseReachabilityResult:
        started = time.perf_counter()
        predecessors = self._index(graphs)
        sketches = (
            self._exhaustive(predecessors, anchors)
            if self.config.exhaustive
            else self._sample(predecessors, anchors, self.config.seed)
        )
        roots = self._rank(sketches, graphs, set(anchors))
        stability = None
        fallback = None
        if not self.config.exhaustive and self.config.stability_seeds:
            reference = {row.node_id for row in roots[: self.config.stability_top_k]}
            overlaps = []
            for seed in self.config.stability_seeds:
                other = self._rank(self._sample(predecessors, anchors, seed), graphs, set(anchors))
                candidate = {row.node_id for row in other[: self.config.stability_top_k]}
                union = reference | candidate
                overlaps.append(len(reference & candidate) / len(union) if union else 1.0)
            stability = mean(overlaps)
            if stability < self.config.minimum_stability:
                sketches = self._exhaustive(predecessors, anchors)
                roots = self._rank(sketches, graphs, set(anchors))
                fallback = "deterministic_exhaustive"
        sizes = [len(sketch.node_ids) for sketch in sketches]
        return ReverseReachabilityResult(
            sketches,
            roots,
            len(sketches),
            mean(sizes) if sizes else 0.0,
            self._percentile(sizes, 0.95),
            len(roots),
            tuple(sorted((root.source_support for root in roots), reverse=True)),
            self.config.seed,
            time.perf_counter() - started,
            stability,
            fallback,
        )


__all__ = [
    "ReverseReachabilityConfig", "ReverseReachabilityResult", "ReverseSketch",
    "RootCandidate", "TemporalReverseReachability",
]
