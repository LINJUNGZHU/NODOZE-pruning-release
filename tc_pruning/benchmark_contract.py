"""Label-free benchmark contracts shared by online and offline code."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from .models import StoredEdge


class ProjectionMode(str, Enum):
    RAW_EVENT = "RAW_EVENT"
    DEPIMPACT_COMPATIBLE = "DEPIMPACT_COMPATIBLE"


@dataclass(frozen=True, slots=True)
class EdgeProjection:
    mode: ProjectionMode | str
    merge_window_ns: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", ProjectionMode(self.mode))
        if self.merge_window_ns <= 0:
            raise ValueError("merge_window_ns must be positive")

    def keys(self, edges: Iterable[StoredEdge]) -> frozenset[str]:
        return frozenset(
            edge.event_id if self.mode is ProjectionMode.RAW_EVENT else "|".join((edge.src, edge.dst, edge.relation.upper(), str(edge.timestamp_ns // self.merge_window_ns)))
            for edge in edges
        )

    def count(self, edges: Iterable[StoredEdge]) -> int:
        return len(self.keys(edges))


def performance_fields(*, inference_seconds: float | None, adapter_seconds: float | None, candidate_seconds: float | None, a_rasp_seconds: float | None, branch_fair_seconds: float | None, peak_rss_kb: int | None) -> Mapping[str, int | float | None]:
    values = (inference_seconds, adapter_seconds, candidate_seconds, a_rasp_seconds, branch_fair_seconds, peak_rss_kb)
    if any(item is not None and item < 0 for item in values):
        raise ValueError("durations must be non-negative")
    measured = (adapter_seconds or 0.0) + (candidate_seconds or 0.0) + (a_rasp_seconds or 0.0) + (branch_fair_seconds or 0.0)
    return {"detector_inference_seconds": inference_seconds, "adapter_seconds": adapter_seconds, "candidate_seconds": candidate_seconds,
            "A_rasp_seconds": a_rasp_seconds, "C_branch_fair_seconds": branch_fair_seconds,
            "total_post_alert_seconds": measured, "peak_rss_kb": peak_rss_kb}


__all__ = ["EdgeProjection", "ProjectionMode", "performance_fields"]
