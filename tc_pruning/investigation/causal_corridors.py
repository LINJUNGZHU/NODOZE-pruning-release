from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import heapq
from typing import Mapping

from .graph_views import InvestigationGraphs
from .kairos_components import KairosAnchorComponent


@dataclass(frozen=True, slots=True)
class CorridorConfig:
    k_paths: int = 3
    max_states: int = 20_000
    max_events: int = 24


@dataclass(frozen=True, slots=True)
class PathBundle:
    demand_id: str
    raw_event_ids: tuple[str, ...]
    projected_edges: tuple[str, ...]
    source: str
    target: str
    temporal_witness: tuple[int, ...]
    relation_sequence: tuple[str, ...]
    path_cost: float
    prize: float
    branch_ids: tuple[str, ...]
    proof_features: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CausalCorridor:
    src_component: str
    dst_component: str
    raw_event_ids: tuple[str, ...]
    temporal_witness: tuple[int, ...]
    relation_sequence: tuple[str, ...]
    path_cost: float
    kairos_support: float
    target_match: float
    long_gap_support: float
    path_bundle: PathBundle


class CausalCorridorBuilder:
    def __init__(self, config: CorridorConfig = CorridorConfig()) -> None:
        self.config = config

    def between(self, graphs: InvestigationGraphs, source: KairosAnchorComponent,
                target: KairosAnchorComponent, *, edge_costs: Mapping[str, float] | None = None,
                target_match: float = 0.0, long_gap_support: float = 0.0) -> tuple[CausalCorridor, ...]:
        if source.end_time_ns >= target.start_time_ns:
            return ()
        outgoing = defaultdict(list)
        for edge in graphs.propagation_edges:
            outgoing[edge.causal_source].append(edge)
        for rows in outgoing.values():
            rows.sort(key=lambda edge: (edge.timestamp_ns, edge.raw_event_id))
        costs = edge_costs or {}
        heap = []
        serial = 0
        for node in source.nodes:
            heapq.heappush(heap, (0.0, serial, node, source.end_time_ns, (), (), (), (node,)))
            serial += 1
        found = []
        states = 0
        targets = set(target.nodes)
        while heap and len(found) < self.config.k_paths and states < self.config.max_states:
            cost, _, node, last, events, times, relations, visited = heapq.heappop(heap)
            states += 1
            if node in targets and events:
                proof = []
                if "EVENT_WRITE" in relations and "EVENT_READ" in relations: proof.append("FILE_TRANSFER")
                if "EVENT_WRITE" in relations and "EVENT_EXECUTE" in relations: proof.append("DROP_EXEC")
                demand_id = f"{source.component_id}->{target.component_id}"
                bundle = PathBundle(demand_id, events, events, visited[0], node, times, relations,
                                    cost, source.loss_mass + target.loss_mass,
                                    (source.component_id, target.component_id), tuple(proof))
                found.append(CausalCorridor(source.component_id, target.component_id, events, times,
                                            relations, cost, 1.0, target_match, long_gap_support, bundle))
                continue
            if len(events) >= self.config.max_events:
                continue
            for edge in outgoing.get(node, ()):
                if edge.timestamp_ns <= last or edge.timestamp_ns > target.start_time_ns:
                    continue
                if edge.causal_target in visited:
                    continue
                edge_cost = max(0.0, float(costs.get(edge.raw_event_id, 1.0)))
                heapq.heappush(heap, (cost + edge_cost, serial, edge.causal_target,
                                     edge.timestamp_ns, events + (edge.raw_event_id,),
                                     times + (edge.timestamp_ns,), relations + (edge.relation,),
                                     visited + (edge.causal_target,)))
                serial += 1
        return tuple(found)


__all__ = ["CausalCorridor", "CausalCorridorBuilder", "CorridorConfig", "PathBundle"]
