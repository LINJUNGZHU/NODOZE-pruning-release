import pytest

from tc_pruning.evaluation_protocol import (
    GroundTruthCompleteness, evaluate_edges,
)


def test_complete_groundtruth_reports_fp_fn_and_checks_identities():
    result = evaluate_edges(
        {"a", "b"}, {"b", "c"}, GroundTruthCompleteness.COMPLETE_EDGE_GT,
        negative_universe_count=8,
    )
    assert (result.tp, result.fp, result.fn, result.edge_count) == (1, 1, 1, 2)
    assert result.tp + result.fn == result.gt_edge_count
    assert result.tp + result.fp == result.edge_count
    assert result.fpr == 1 / 8


def test_partial_positive_groundtruth_never_calls_unlabeled_edges_fp():
    result = evaluate_edges(
        {"a", "b"}, {"b", "c"}, GroundTruthCompleteness.PARTIAL_POSITIVE_GT,
    )
    assert (result.known_tp, result.known_fn, result.unlabeled_output_edges) == (1, 1, 1)
    assert not hasattr(result, "fp")
    with pytest.raises(ValueError):
        evaluate_edges({"a"}, {"a"}, GroundTruthCompleteness.COMPLETE_EDGE_GT)
