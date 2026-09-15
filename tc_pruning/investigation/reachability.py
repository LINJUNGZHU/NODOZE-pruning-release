from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import heapq
from typing import Iterable, Mapping

from ..models import StoredEdge
from .semantics import InvestigationSemanticsRegistry


@dataclass(frozen=True, slots=True)
class TemporalDemandPair:
    demand_id: str
    source: str
    target: str
    demand_type: str
    supporting_anchor: str
    creation_reason: str
    temporal_bounds: tuple[int, int]
    confidence: float


@dataclass(frozen=True, slots=True)
class ReachabilityPreserverResult:
    event_ids: tuple[str, ...]
    demand_pair_count: int
    preserved_demand_count: int
    reachability_preservation_rate: float
    preserver_raw_event_cost: int
    preserver_fraction_of_budget: float
    budget_feasible: bool
    budget_overflow_events: int
    demand_witnesses: Mapping[str, tuple[str, ...]]


class TemporalReachabilityPreserver:
    def __init__(self, registry: InvestigationSemanticsRegistry) -> None:
        self.registry = registry

    def _index(self, edges: Iterable[StoredEdge]):
        result = defaultdict(list)
        for edge in edges:
            try:
                source, target = self.registry.causal_endpoints(edge)
            except ValueError:
                continue
            result[source].append((edge, target))
        for values in result.values():
            values.sort(key=lambda item: (item[0].timestamp_ns, item[0].edge_id))
        return result

    def _path(self, index, demand, costs, allowed=None):
        low, high = demand.temporal_bounds
        heap = [(0.0, 0, demand.source, low - 1, ())]
        serial = 1
        best = {}
        while heap:
            cost, _, node, last_time, path = heapq.heappop(heap)
            if node == demand.target:
                return path
            state = (node, last_time)
            if best.get(state, float("inf")) <= cost:
                continue
            best[state] = cost
            for edge, target in index.get(node, ()):
                if allowed is not None and edge.event_id not in allowed:
                    continue
                if edge.timestamp_ns <= last_time or edge.timestamp_ns < low or edge.timestamp_ns > high:
                    continue
                edge_cost = max(0.0, float(costs.get(edge.event_id, 1.0)))
                heapq.heappush(heap, (cost + edge_cost, serial, target, edge.timestamp_ns, path + (edge.event_id,)))
                serial += 1
        return None

    def preserve(self, edges, demands, edge_costs, *, budget):
        edge_tuple = tuple(edges)
        demand_tuple = tuple(demands)
        index = self._index(edge_tuple)
        witnesses = {}
        mandatory = set()
        for demand in demand_tuple:
            path = self._path(index, demand, edge_costs)
            if path is not None:
                witnesses[demand.demand_id] = path
                mandatory.update(path)
        # Deterministically remove an edge only when every declared demand remains reachable.
        for event_id in sorted(mandatory, reverse=True):
            trial = mandatory - {event_id}
            if all(self._path(index, demand, edge_costs, trial) is not None for demand in demand_tuple):
                mandatory = trial
        preserved = sum(self._path(index, demand, edge_costs, mandatory) is not None for demand in demand_tuple)
        count = len(mandatory)
        return ReachabilityPreserverResult(
            tuple(edge.event_id for edge in edge_tuple if edge.event_id in mandatory),
            len(demand_tuple), preserved, preserved / len(demand_tuple) if demand_tuple else 1.0,
            count, count / budget if budget else (0.0 if count == 0 else float("inf")),
            count <= budget, max(0, count - budget), witnesses,
        )


__all__ = ["ReachabilityPreserverResult", "TemporalDemandPair", "TemporalReachabilityPreserver"]
