from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Mapping

from ..models import StoredEdge


_FAMILIES = ("CONTROL", "FILE_READ", "FILE_WRITE", "EXECUTION", "NETWORK_IN", "NETWORK_OUT", "OTHER")


def _ones() -> dict[str, float]:
    return {family: 1.0 for family in _FAMILIES}


def _taus() -> dict[str, float]:
    return {family: 3_600_000_000_000.0 for family in _FAMILIES}


@dataclass(frozen=True, slots=True)
class CleanPropagationConfig:
    relation_weights: Mapping[str, float] = field(default_factory=_ones)
    tau_ns: Mapping[str, float] = field(default_factory=_taus)
    alpha: float = 0.5
    gamma: float = 0.5
    progressive_clean: bool = False
    progressive_rounds: int = 0
    interference_multiplier: float = 0.25

    def __post_init__(self) -> None:
        if self.alpha < 0 or self.gamma < 0:
            raise ValueError("alpha and gamma must be non-negative")
        if any(float(self.tau_ns.get(family, 0)) <= 0 for family in _FAMILIES):
            raise ValueError("every relation family requires positive tau_ns")
        if any(float(self.relation_weights.get(family, -1)) < 0 for family in _FAMILIES):
            raise ValueError("every relation family requires non-negative weight")


@dataclass(frozen=True, slots=True)
class PropagationEdge:
    edge_id: int
    raw_event_id: str
    causal_source: str
    causal_target: str
    relation: str
    relation_family: str
    timestamp_ns: int
    raw_weight: float
    transition_weight: float


@dataclass(frozen=True, slots=True)
class InvestigationGraphs:
    full_edges: tuple[StoredEdge, ...]
    propagation_edges: tuple[PropagationEdge, ...]
    output_event_ids: frozenset[str] = frozenset()
    telemetry: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def with_output(self, event_ids: set[str] | frozenset[str]) -> "InvestigationGraphs":
        available = {edge.event_id for edge in self.full_edges}
        chosen = frozenset(str(value) for value in event_ids)
        if not chosen <= available:
            raise ValueError("G_output must be a subset of G_full")
        return replace(self, output_event_ids=chosen)


__all__ = ["CleanPropagationConfig", "InvestigationGraphs", "PropagationEdge"]
