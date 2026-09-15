"""Offline-only partial-positive seed-utility accounting and comparisons."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .benchmark_contract import EdgeProjection, ProjectionMode, performance_fields as _online_performance_fields
from .evidence_candidate_builder import CandidateSearchConfig
from .models import StoredEdge


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


def performance_fields(*, inference_seconds: float | None, candidate_seconds: float, final_seconds: float | None, adapter_seconds: float = 0.0, peak_rss_kb: int | None, candidate_edges: int, final_edges: int | None) -> Mapping[str, int | float | None]:
    """Compatibility shim; online code imports the label-free contract directly."""
    if candidate_edges < 0 or final_edges is not None and final_edges < 0:
        raise ValueError("counts must be non-negative")
    result = dict(_online_performance_fields(inference_seconds=inference_seconds, adapter_seconds=adapter_seconds,
        candidate_seconds=candidate_seconds, a_rasp_seconds=final_seconds, branch_fair_seconds=None, peak_rss_kb=peak_rss_kb))
    result.update({"candidate_reconstruction_seconds": candidate_seconds, "final_selection_seconds": final_seconds,
                   "candidate_raw_event_count": candidate_edges, "final_raw_event_count": final_edges,
                   "selector_seconds": final_seconds})
    return result


__all__ = [
    "CandidateSnapshot", "CandidateStageIds", "DetectorRunContract", "EdgeProjection", "ProjectionMode",
    "enforce_common_configuration", "evaluate_coverage_funnel", "pairwise_candidate_delta",
    "partial_positive_metrics", "performance_fields",
]
