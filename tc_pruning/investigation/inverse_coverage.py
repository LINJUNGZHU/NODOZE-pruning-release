from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from .graph_views import InvestigationGraphs
from .kairos_components import KairosAnchorComponent


@dataclass(frozen=True, slots=True)
class InverseCoverageConfig:
    max_states: int = 20_000
    minimum_gain: float = 0.0


@dataclass(frozen=True, slots=True)
class InverseRoot:
    node_id: str
    explained_components: tuple[str, ...]
    witness_event_ids: tuple[str, ...]
    relation_diversity: int
    path_diversity: int
    anchor_support: float
    root_score: float


class SourceAwareInverseCoverage:
    def __init__(self, config: InverseCoverageConfig = InverseCoverageConfig()) -> None:
        if config.max_states < 1:
            raise ValueError("max states must be positive")
        self.config = config

    def explain(self, graphs: InvestigationGraphs,
                components: tuple[KairosAnchorComponent, ...]) -> tuple[InverseRoot, ...]:
        incoming = defaultdict(list)
        for edge in graphs.propagation_edges:
            incoming[edge.causal_target].append(edge)
        for rows in incoming.values():
            rows.sort(key=lambda edge: (-edge.timestamp_ns, edge.raw_event_id))
        support = defaultdict(set)
        witnesses = defaultdict(set)
        relations = defaultdict(set)
        paths = defaultdict(set)
        mass = {component.component_id: component.loss_mass for component in components}
        total_mass = sum(mass.values()) or 1.0
        states = 0
        for component in components:
            for target in component.nodes:
                queue = deque([(target, component.start_time_ns + 1, ())])
                best = {}
                while queue and states < self.config.max_states:
                    node, latest, path = queue.popleft()
                    states += 1
                    for edge in incoming.get(node, ()):
                        if edge.timestamp_ns >= latest or edge.causal_source in path:
                            continue
                        previous = best.get(edge.causal_source)
                        if previous is not None and previous >= edge.timestamp_ns:
                            continue
                        best[edge.causal_source] = edge.timestamp_ns
                        new_path = (edge.causal_source, *path)
                        support[edge.causal_source].add(component.component_id)
                        witnesses[edge.causal_source].add(edge.raw_event_id)
                        relations[edge.causal_source].add(edge.relation_family)
                        paths[edge.causal_source].add(tuple(new_path))
                        queue.append((edge.causal_source, edge.timestamp_ns, new_path))
        result = []
        for node, explained in support.items():
            weighted = sum(mass[name] for name in explained) / total_mass
            if weighted < self.config.minimum_gain:
                continue
            diversity = len(relations[node]) / max(1, len(graphs.propagation_edges))
            score = weighted + min(1.0, diversity)
            result.append(InverseRoot(
                node, tuple(sorted(explained)), tuple(sorted(witnesses[node])),
                len(relations[node]), len(paths[node]), len(explained) / max(1, len(components)), score,
            ))
        return tuple(sorted(result, key=lambda root: (-root.root_score, root.node_id)))


__all__ = ["InverseCoverageConfig", "InverseRoot", "SourceAwareInverseCoverage"]
