from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from ..models import StoredEdge


class ProjectionMode(str, Enum):
    RAW_EVENT = "RAW_EVENT"
    DEPIMPACT_COMPATIBLE = "DEPIMPACT_COMPATIBLE"


@dataclass(frozen=True, slots=True)
class ProjectedEdge:
    edge_key: str
    src: str
    dst: str
    normalized_relation: str
    temporal_merge_group: int
    raw_event_ids: tuple[str, ...]


class EvaluationEdgeProjection:
    def __init__(self, mode: ProjectionMode, *, merge_window_ns: int) -> None:
        if merge_window_ns < 1:
            raise ValueError("merge window must be positive")
        self.mode = ProjectionMode(mode)
        self.merge_window_ns = merge_window_ns

    def project(self, edges: Iterable[StoredEdge]) -> tuple[ProjectedEdge, ...]:
        groups: dict[tuple[str, str, str, int, str], list[str]] = {}
        for edge in edges:
            relation = edge.relation.upper()
            temporal = edge.timestamp_ns // self.merge_window_ns
            discriminator = edge.event_id if self.mode is ProjectionMode.RAW_EVENT else ""
            key = (edge.src, edge.dst, relation, temporal, discriminator)
            groups.setdefault(key, []).append(edge.event_id)
        result = []
        for (src, dst, relation, temporal, discriminator), event_ids in sorted(groups.items()):
            raw_ids = tuple(sorted(set(event_ids)))
            identity = discriminator or f"{src}|{dst}|{relation}|{temporal}"
            result.append(ProjectedEdge(identity, src, dst, relation, temporal, raw_ids))
        return tuple(result)


__all__ = ["EvaluationEdgeProjection", "ProjectedEdge", "ProjectionMode"]
