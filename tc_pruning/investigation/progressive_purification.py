from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Callable, Mapping

from .graph_views import InvestigationGraphs


@dataclass(frozen=True, slots=True)
class PurificationConfig:
    rounds: int = 3
    frequency_threshold: int = 100
    fanout_threshold: int = 50
    interference_multiplier: float = 0.5
    support_threshold: float = 0.1
    minimum_stability: float = 0.7

    def __post_init__(self):
        if not 1 <= self.rounds <= 4 or not 0 < self.interference_multiplier <= 1:
            raise ValueError("invalid purification configuration")


@dataclass(frozen=True, slots=True)
class PurificationRound:
    round_index: int
    downweighted_event_ids: tuple[str, ...]
    top_stability: float


@dataclass(frozen=True, slots=True)
class PurificationResult:
    graph: InvestigationGraphs
    rounds: tuple[PurificationRound, ...]
    stop_reason: str


class ProgressivePurification:
    def __init__(self, config: PurificationConfig = PurificationConfig()) -> None:
        self.config = config

    @staticmethod
    def _jaccard(left, right):
        union = set(left) | set(right)
        return len(set(left) & set(right)) / len(union) if union else 1.0

    def run(self, graph: InvestigationGraphs, *, frequency: Mapping[str, int],
            fanout: Mapping[str, int], kairos_support: Mapping[str, float],
            target_support: Mapping[str, float], unique_coverage: set[str],
            ranking: Callable[[InvestigationGraphs], frozenset[str]] | None = None) -> PurificationResult:
        rank = ranking or (lambda current: frozenset(
            edge.raw_event_id for edge in sorted(
                current.propagation_edges, key=lambda edge: (-edge.raw_weight, edge.raw_event_id)
            )[:20]
        ))
        current = graph
        previous_top = rank(current)
        rounds = []
        stop = "MAX_ROUNDS"
        for round_index in range(1, self.config.rounds + 1):
            changed = []
            edges = []
            for edge in current.propagation_edges:
                event = edge.raw_event_id
                supported = max(float(kairos_support.get(event, 0.0)), float(target_support.get(event, 0.0)))
                interference = (
                    frequency.get(event, 0) >= self.config.frequency_threshold
                    and fanout.get(event, 0) >= self.config.fanout_threshold
                    and supported < self.config.support_threshold
                    and event not in unique_coverage
                )
                if interference:
                    edge = replace(edge, raw_weight=edge.raw_weight * self.config.interference_multiplier,
                                   transition_weight=edge.transition_weight * self.config.interference_multiplier)
                    changed.append(event)
                edges.append(edge)
            current = InvestigationGraphs(
                graph.full_edges, tuple(edges), graph.output_event_ids,
                MappingProxyType({**dict(graph.telemetry), "purification_round": round_index}),
            )
            next_top = rank(current)
            stability = self._jaccard(previous_top, next_top)
            rounds.append(PurificationRound(round_index, tuple(sorted(changed)), stability))
            if stability < self.config.minimum_stability:
                stop = "RANKING_INSTABILITY"
                break
            if not changed:
                stop = "SATURATED"
                break
            previous_top = next_top
        return PurificationResult(current, tuple(rounds), stop)


__all__ = ["ProgressivePurification", "PurificationConfig", "PurificationResult", "PurificationRound"]
