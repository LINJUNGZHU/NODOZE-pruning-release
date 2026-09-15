from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from typing import Iterable

from ..detectors.kairos_adapter import KairosEvidence


@dataclass(frozen=True, slots=True)
class KairosAnchorComponent:
    component_id: str
    event_ids: tuple[str, ...]
    nodes: tuple[str, ...]
    queues: tuple[str, ...]
    summary_components: tuple[str, ...]
    loss_mass: float
    start_time_ns: int
    end_time_ns: int
    hosts: tuple[str, ...]
    relation_profile: dict[str, int]


class KairosAnchorComponentBuilder:
    def build(self, evidence: Iterable[KairosEvidence]) -> tuple[KairosAnchorComponent, ...]:
        rows = tuple(sorted(evidence, key=lambda row: (row.timestamp_ns, row.raw_event_id)))
        parent = list(range(len(rows)))

        def find(index):
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left, right):
            left, right = find(left), find(right)
            if left != right:
                parent[max(left, right)] = min(left, right)

        queue_representative = {}
        summary_representative = {}
        node_state = {}
        for index, row in enumerate(rows):
            for queue in row.queue_ids:
                if queue in queue_representative:
                    union(index, queue_representative[queue])
                else:
                    queue_representative[queue] = index
            if row.summary_component is not None:
                if row.summary_component in summary_representative:
                    union(index, summary_representative[row.summary_component])
                else:
                    summary_representative[row.summary_component] = index
            for node in {row.src, row.dst}:
                state = node_state.get(node)
                if state is None:
                    node_state[node] = {
                        "first_time": row.timestamp_ns,
                        "pending": [index],
                        "connected_representative": None,
                    }
                elif state["connected_representative"] is not None:
                    union(index, state["connected_representative"])
                elif row.timestamp_ns == state["first_time"]:
                    state["pending"].append(index)
                else:
                    representative = state["pending"][0]
                    union(index, representative)
                    for pending in state["pending"][1:]:
                        union(pending, index)
                    state["pending"] = []
                    state["connected_representative"] = representative
        groups = {}
        for index, row in enumerate(rows):
            groups.setdefault(find(index), []).append(row)
        result = []
        for group in groups.values():
            event_ids = tuple(sorted({row.raw_event_id for row in group}))
            digest = hashlib.sha256("\0".join(event_ids).encode()).hexdigest()[:16]
            result.append(KairosAnchorComponent(
                f"kairos-component:{digest}", event_ids,
                tuple(sorted({node for row in group for node in (row.src, row.dst)})),
                tuple(sorted({queue for row in group for queue in row.queue_ids})),
                tuple(sorted({row.summary_component for row in group if row.summary_component})),
                sum(row.raw_loss for row in group), min(row.timestamp_ns for row in group),
                max(row.timestamp_ns for row in group), (),
                dict(sorted(Counter(row.relation for row in group).items())),
            ))
        return tuple(sorted(result, key=lambda item: (item.start_time_ns, item.component_id)))


__all__ = ["KairosAnchorComponent", "KairosAnchorComponentBuilder"]
