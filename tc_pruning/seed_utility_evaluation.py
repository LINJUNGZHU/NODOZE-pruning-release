"""Offline-only partial-positive seed-utility accounting and comparisons."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from .evidence_candidate_builder import CandidateSearchConfig
from .models import StoredEdge


class ProjectionMode(str, Enum):
    RAW_EVENT = "RAW_EVENT"
    DEPIMPACT_COMPATIBLE = "DEPIMPACT_COMPATIBLE"


@dataclass(frozen=True, slots=True)
class EdgeProjection:
    """A small, reproducible raw-event projection used by every detector run."""

    mode: ProjectionMode | str
    merge_window_ns: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", ProjectionMode(self.mode))
        if self.merge_window_ns <= 0:
            raise ValueError("merge_window_ns must be positive")

    def keys(self, edges: Iterable[StoredEdge]) -> frozenset[str]:
        keys: set[str] = set()
        for edge in edges:
            if self.mode is ProjectionMode.RAW_EVENT:
                keys.add(edge.event_id)
            else:
                keys.add("|".join((
                    edge.src, edge.dst, edge.relation.upper(),
                    str(edge.timestamp_ns // self.merge_window_ns),
                )))
        return frozenset(keys)

    def count(self, edges: Iterable[StoredEdge]) -> int:
        return len(self.keys(edges))


@dataclass(frozen=True, slots=True)
class CandidateStageIds:
    """Raw event identities at each funnel boundary, supplied only offline."""

    raw_database: frozenset[str]
    preprocessing: frozenset[str]
    inference: frozenset[str]
    scored: frozenset[str]
    native_threshold: frozenset[str]
    evidence: frozenset[str]
    candidate: frozenset[str]
    final: frozenset[str]

    def __post_init__(self) -> None:
        for name in (
            "raw_database", "preprocessing", "inference", "scored", "native_threshold",
            "evidence", "candidate", "final",
        ):
            object.__setattr__(self, name, frozenset(getattr(self, name)))


@dataclass(frozen=True, slots=True)
class DetectorRunContract:
    detector_id: str
    candidate_config: CandidateSearchConfig
    projection: EdgeProjection
    budget: int
    selectors: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.detector_id:
            raise ValueError("detector_id is required")
        if self.budget <= 0:
            raise ValueError("budget must be positive")
        object.__setattr__(self, "selectors", tuple(self.selectors))
        if not self.selectors:
            raise ValueError("at least one selector is required")


def partial_positive_metrics(
    output_event_ids: Iterable[str], known_critical_event_ids: Iterable[str],
) -> dict[str, int | float]:
    output = set(output_event_ids)
    known = set(known_critical_event_ids)
    known_tp = len(output & known)
    known_fn = len(known - output)
    return {
        "known_TP": known_tp,
        "known_FN": known_fn,
        "known_recall": known_tp / len(known) if known else 1.0,
        "unlabeled_output_edges": len(output - known),
    }


def evaluate_coverage_funnel(
    *, known_critical_event_ids: Iterable[str], stages: CandidateStageIds,
) -> dict[str, object]:
    """Account known positives at every boundary; no negative-class claims are made."""
    known = frozenset(known_critical_event_ids)
    ordered = (
        ("raw_database", stages.raw_database),
        ("preprocessing", stages.preprocessing),
        ("inference", stages.inference),
        ("scored", stages.scored),
        ("native_threshold", stages.native_threshold),
        ("evidence", stages.evidence),
        ("candidate", stages.candidate),
        ("final", stages.final),
    )
    result: dict[str, object] = {
        name: partial_positive_metrics(event_ids, known) for name, event_ids in ordered
    }
    # Attribute a known miss to the first boundary at which it disappears.
    result["candidate_ceiling_decomposition"] = {
        "unmapped": sorted(known - stages.raw_database),
        "preprocess": sorted((known & stages.raw_database) - stages.preprocessing),
        "inference": sorted((known & stages.preprocessing) - stages.inference),
        "score": sorted((known & stages.inference) - stages.native_threshold),
        "evidence": sorted((known & stages.native_threshold) - stages.evidence),
        "search": sorted((known & stages.evidence) - stages.candidate),
    }
    result["per_known_critical_edge"] = {
        event_id: {name: event_id in event_ids for name, event_ids in ordered}
        for event_id in sorted(known)
    }
    return result


def pairwise_candidate_delta(
    left_edges: Iterable[StoredEdge], right_edges: Iterable[StoredEdge], *,
    known_critical_event_ids: Iterable[str], known_attack_node_ids: Iterable[str], projection: EdgeProjection,
) -> dict[str, object]:
    """Candidate-level complementarity, with raw and projected deltas separated."""
    left = {edge.event_id: edge for edge in left_edges}
    right = {edge.event_id: edge for edge in right_edges}
    added = set(right) - set(left)
    critical = set(known_critical_event_ids)
    attack_nodes = set(known_attack_node_ids)
    left_nodes = {node for edge in left.values() for node in (edge.src, edge.dst)}
    right_nodes = {node for edge in right.values() for node in (edge.src, edge.dst)}
    return {
        "new_critical_edges": sorted(added & critical),
        "new_attack_nodes": sorted((right_nodes - left_nodes) & attack_nodes),
        "projected_edge_delta": projection.count(right.values()) - projection.count(left.values()),
        "raw_event_delta": len(added),
    }


def enforce_common_configuration(runs: Iterable[DetectorRunContract]) -> None:
    """Reject comparisons whose search, projection, budget, or selectors differ."""
    rows = tuple(runs)
    if not rows:
        raise ValueError("at least one detector run is required")
    reference = rows[0]
    signature = (
        reference.candidate_config, reference.projection, reference.budget, reference.selectors,
    )
    for row in rows[1:]:
        if (row.candidate_config, row.projection, row.budget, row.selectors) != signature:
            raise ValueError("detector comparison requires one common configuration, projection, budget, and selectors")


def performance_fields(
    *, inference_seconds: float | None, candidate_seconds: float, final_seconds: float | None,
    peak_rss_kb: int | None, candidate_edges: int, final_edges: int | None,
) -> Mapping[str, int | float | None]:
    """Keep detector inference separate from post-alert reconstruction and selection."""
    if candidate_seconds < 0 or (inference_seconds is not None and inference_seconds < 0):
        raise ValueError("durations must be non-negative")
    return {
        "detector_inference_seconds": inference_seconds,
        "candidate_reconstruction_seconds": candidate_seconds,
        "final_selection_seconds": final_seconds,
        "peak_rss_kb": peak_rss_kb,
        "candidate_raw_event_count": candidate_edges,
        "final_raw_event_count": final_edges,
    }


__all__ = [
    "CandidateStageIds", "DetectorRunContract", "EdgeProjection", "ProjectionMode",
    "enforce_common_configuration", "evaluate_coverage_funnel", "pairwise_candidate_delta",
    "partial_positive_metrics", "performance_fields",
]
