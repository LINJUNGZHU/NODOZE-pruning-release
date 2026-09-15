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


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """An independently produced candidate set, including seed-only nodes."""

    edges: tuple[StoredEdge, ...]
    node_ids: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "edges", tuple(self.edges))
        object.__setattr__(self, "node_ids", frozenset(self.node_ids))


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
    # Stage sets are auditable snapshots, not assumed to be monotone.
    result["candidate_ceiling_decomposition"] = {
        "unmapped": sorted(known - stages.raw_database),
        "preprocess": sorted((known & stages.raw_database) - stages.preprocessing),
        "inference": sorted((known & stages.preprocessing) - stages.inference),
        "unscored": sorted((known & stages.inference) - stages.scored),
        "below_native_threshold": sorted((known & stages.scored) - stages.native_threshold),
        "evidence": sorted((known & stages.native_threshold) - stages.evidence),
        "search": sorted((known & stages.evidence) - stages.candidate),
    }
    direct = known & stages.evidence
    candidate = known & stages.candidate
    direct_miss = known - stages.evidence
    result["direct_evidence_hits"] = sorted(direct)
    result["direct_evidence_misses"] = sorted(direct_miss)
    result["direct_miss_recovered_by_reconstruction"] = sorted((candidate - direct))
    result["reconstruction_miss"] = sorted(known - stages.candidate)
    result["per_known_critical_edge"] = {
        event_id: {name: event_id in event_ids for name, event_ids in ordered}
        for event_id in sorted(known)
    }
    return result


def pairwise_candidate_delta(
    left: CandidateSnapshot, right: CandidateSnapshot, *,
    known_critical_event_ids: Iterable[str], known_attack_node_ids: Iterable[str], projection: EdgeProjection,
) -> dict[str, object]:
    """Candidate-level complementarity, with raw and projected deltas separated."""
    left_edges = {edge.event_id: edge for edge in left.edges}
    right_edges = {edge.event_id: edge for edge in right.edges}
    union_edges = {**left_edges, **right_edges}
    added = set(union_edges) - set(left_edges)
    critical = set(known_critical_event_ids)
    attack_nodes = set(known_attack_node_ids)
    left_nodes = set(left.node_ids) | {node for edge in left_edges.values() for node in (edge.src, edge.dst)}
    union_nodes = set(left.node_ids) | set(right.node_ids) | {node for edge in union_edges.values() for node in (edge.src, edge.dst)}
    return {
        "new_critical_edges": sorted(added & critical),
        "new_attack_nodes": sorted((union_nodes - left_nodes) & attack_nodes),
        "projected_edge_delta": projection.count(union_edges.values()) - projection.count(left_edges.values()),
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
    adapter_seconds: float = 0.0,
    peak_rss_kb: int | None, candidate_edges: int, final_edges: int | None,
) -> Mapping[str, int | float | None]:
    """Keep detector inference separate from post-alert reconstruction and selection."""
    numbers = (inference_seconds, adapter_seconds, candidate_seconds, final_seconds, peak_rss_kb, candidate_edges, final_edges)
    if any(value is not None and value < 0 for value in numbers):
        raise ValueError("durations must be non-negative")
    return {
        "detector_inference_seconds": inference_seconds,
        "candidate_reconstruction_seconds": candidate_seconds,
        "final_selection_seconds": final_seconds,
        "peak_rss_kb": peak_rss_kb,
        "candidate_raw_event_count": candidate_edges,
        "final_raw_event_count": final_edges,
        "adapter_seconds": adapter_seconds,
        "candidate_seconds": candidate_seconds,
        "selector_seconds": final_seconds,
        "total_post_alert_seconds": adapter_seconds + candidate_seconds + (final_seconds or 0.0),
    }


__all__ = [
    "CandidateSnapshot", "CandidateStageIds", "DetectorRunContract", "EdgeProjection", "ProjectionMode",
    "enforce_common_configuration", "evaluate_coverage_funnel", "pairwise_candidate_delta",
    "partial_positive_metrics", "performance_fields",
]
