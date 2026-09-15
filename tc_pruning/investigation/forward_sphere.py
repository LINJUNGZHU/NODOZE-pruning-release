from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
import math
from typing import Mapping

from .graph_views import InvestigationGraphs, PropagationEdge


def harmonic_verification(backward_support: float, forward_support: float) -> float:
    backward = max(0.0, float(backward_support))
    forward = max(0.0, float(forward_support))
    if backward == 0.0 or forward == 0.0:
        return 0.0
    return 2.0 * backward * forward / (backward + forward + 1e-12)


@dataclass(frozen=True, slots=True)
class ForwardSphereConfig:
    max_rounds: int = 12
    max_events: int = 2_000
    min_marginal_gain: float = 0.01
    low_gain_patience: int = 2

    def __post_init__(self) -> None:
        if self.max_rounds < 1 or self.max_events < 1 or self.low_gain_patience < 1:
            raise ValueError("forward sphere bounds must be positive")


@dataclass(frozen=True, slots=True)
class OnlineForwardSignals:
    anchor_ids: frozenset[str] = frozenset()
    normalized_relevance: Mapping[str, float] = field(default_factory=dict)
    rare_event_ids: frozenset[str] = frozenset()
    rare_executable_event_ids: frozenset[str] = frozenset()
    rare_network_event_ids: frozenset[str] = frozenset()
    motif_event_ids: frozenset[str] = frozenset()
    verified_terminal_ids: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ForwardSphereRound:
    round_index: int
    new_nodes: tuple[str, ...]
    new_events: tuple[str, ...]
    marginal_gain: float
    stop_reason: str | None


@dataclass(frozen=True, slots=True)
class ForwardSphere:
    sphere_id: str
    root_id: str
    node_ids: tuple[str, ...]
    raw_event_ids: tuple[str, ...]
    rounds: tuple[ForwardSphereRound, ...]
    backward_support: float
    forward_support: float
    verification_score: float
    stop_reason: str


class ForwardCausalSphereBuilder:
    def __init__(self, config: ForwardSphereConfig) -> None:
        self.config = config

    @staticmethod
    def _edge_gain(
        edge: PropagationEdge,
        signals: OnlineForwardSignals,
        future_fanout: Mapping[str, int],
    ) -> float:
        gain = max(0.0, min(1.0, float(signals.normalized_relevance.get(edge.raw_event_id, 0.0))))
        if edge.causal_target in signals.anchor_ids:
            gain += 1.0
        if edge.raw_event_id in signals.rare_event_ids:
            gain += 0.6
        if edge.raw_event_id in signals.rare_executable_event_ids:
            gain += 0.8
        if edge.raw_event_id in signals.rare_network_event_ids:
            gain += 0.8
        if edge.raw_event_id in signals.motif_event_ids:
            gain += 0.8
        if edge.causal_target in signals.verified_terminal_ids:
            gain += 0.8
        if future_fanout.get(edge.causal_target, 0) >= 2:
            gain += 0.2
        return gain

    def build(
        self,
        root_id: str,
        graphs: InvestigationGraphs,
        signals: OnlineForwardSignals,
        *,
        backward_support: float,
    ) -> ForwardSphere:
        successors: dict[str, list[PropagationEdge]] = defaultdict(list)
        for edge in graphs.propagation_edges:
            successors[edge.causal_source].append(edge)
        for edges in successors.values():
            edges.sort(key=lambda edge: (edge.timestamp_ns, edge.edge_id))
        fanout = Counter(edge.causal_source for edge in graphs.propagation_edges)
        frontier = [(root_id, -1)]
        nodes = {root_id}
        selected: list[str] = []
        seen_events: set[str] = set()
        rounds = []
        low_rounds = 0
        total_signal = 0.0
        stop_reason = "MAX_ROUNDS"
        for round_index in range(1, self.config.max_rounds + 1):
            candidates = {}
            for node, after_time in frontier:
                for edge in successors.get(node, ()):
                    if edge.timestamp_ns <= after_time or edge.raw_event_id in seen_events:
                        continue
                    gain = self._edge_gain(edge, signals, fanout)
                    candidates[edge.raw_event_id] = (edge, gain)
            if not candidates:
                stop_reason = "FRONTIER_EXHAUSTED"
                break
            ordered = sorted(
                candidates.values(),
                key=lambda item: (-item[1], item[0].timestamp_ns, item[0].edge_id),
            )
            remaining = self.config.max_events - len(selected)
            chosen = ordered[:remaining]
            resource_stop = len(chosen) < len(ordered) or remaining <= len(chosen)
            new_frontier = []
            new_nodes = set()
            gain_sum = 0.0
            for edge, gain in chosen:
                seen_events.add(edge.raw_event_id)
                selected.append(edge.raw_event_id)
                nodes.add(edge.causal_target)
                new_nodes.add(edge.causal_target)
                new_frontier.append((edge.causal_target, edge.timestamp_ns))
                gain_sum += gain
            marginal = gain_sum / max(1, len(chosen))
            total_signal += gain_sum
            low_rounds = low_rounds + 1 if marginal < self.config.min_marginal_gain else 0
            round_stop = None
            if resource_stop and len(selected) >= self.config.max_events:
                stop_reason = round_stop = "RESOURCE_CAP"
            elif low_rounds >= self.config.low_gain_patience:
                stop_reason = round_stop = "LOW_MARGINAL_GAIN"
            rounds.append(ForwardSphereRound(
                round_index,
                tuple(sorted(new_nodes)),
                tuple(edge.raw_event_id for edge, _ in chosen),
                marginal,
                round_stop,
            ))
            frontier = new_frontier
            if round_stop:
                break
        forward_support = 1.0 - math.exp(-total_signal) if total_signal else 0.0
        digest = hashlib.sha256(json.dumps(
            {"root": root_id, "events": selected}, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()[:20]
        return ForwardSphere(
            f"sphere:{digest}", root_id, tuple(sorted(nodes)), tuple(selected), tuple(rounds),
            backward_support, forward_support,
            harmonic_verification(backward_support, forward_support), stop_reason,
        )


__all__ = [
    "ForwardCausalSphereBuilder", "ForwardSphere", "ForwardSphereConfig",
    "ForwardSphereRound", "OnlineForwardSignals", "harmonic_verification",
]
