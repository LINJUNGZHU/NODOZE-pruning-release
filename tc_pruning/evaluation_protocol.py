from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class GroundTruthCompleteness(str, Enum):
    COMPLETE_EDGE_GT = "COMPLETE_EDGE_GT"
    PARTIAL_POSITIVE_GT = "PARTIAL_POSITIVE_GT"


@dataclass(frozen=True, slots=True)
class CompleteEdgeMetrics:
    tp: int
    fp: int
    fn: int
    edge_count: int
    gt_edge_count: int
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float


@dataclass(frozen=True, slots=True)
class PartialPositiveMetrics:
    known_tp: int
    known_fn: int
    unlabeled_output_edges: int
    known_recall: float
    projected_edge_count: int
    known_gt_edge_count: int


def evaluate_edges(
    output_edges: Iterable[str], gt_edges: Iterable[str],
    completeness: GroundTruthCompleteness, *, negative_universe_count: int | None = None,
) -> CompleteEdgeMetrics | PartialPositiveMetrics:
    output = set(output_edges)
    truth = set(gt_edges)
    tp = len(output & truth)
    fn = len(truth - output)
    unlabeled = len(output - truth)
    recall = tp / len(truth) if truth else 1.0
    if completeness is GroundTruthCompleteness.PARTIAL_POSITIVE_GT:
        return PartialPositiveMetrics(tp, fn, unlabeled, recall, len(output), len(truth))
    if completeness is not GroundTruthCompleteness.COMPLETE_EDGE_GT:
        raise ValueError("unknown Ground Truth completeness")
    if negative_universe_count is None or negative_universe_count < unlabeled:
        raise ValueError("complete edge evaluation requires a valid negative universe")
    precision = tp / len(output) if output else (1.0 if not truth else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result = CompleteEdgeMetrics(
        tp, unlabeled, fn, len(output), len(truth), precision, recall, f1,
        unlabeled / negative_universe_count if negative_universe_count else 0.0,
        fn / len(truth) if truth else 0.0,
    )
    assert result.tp + result.fn == result.gt_edge_count
    assert result.tp + result.fp == result.edge_count
    return result


__all__ = [
    "CompleteEdgeMetrics", "GroundTruthCompleteness", "PartialPositiveMetrics",
    "evaluate_edges",
]
