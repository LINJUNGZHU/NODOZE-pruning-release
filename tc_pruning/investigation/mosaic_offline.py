"""Frozen offline metrics for KAIROS-MOSAIC artifacts."""

from __future__ import annotations

from typing import Iterable, Mapping


def evaluate_online_artifact(
    online: Mapping,
    *,
    reference_event_ids: Iterable[str],
    reference_node_ids: Iterable[str],
    edge_endpoints: Mapping[str, tuple[str, str]],
) -> dict:
    reference_events = set(map(str, reference_event_ids))
    reference_nodes = {str(node).casefold() for node in reference_node_ids}
    candidates = set(map(str, online["retrieval_ablations"]["R4"]["event_ids"]))
    selected = set(map(str, online["selection_ablations"]["S5"]["event_ids"]))
    candidate_nodes = {
        str(node).casefold() for event in candidates
        for node in edge_endpoints.get(event, ())
    }
    selected_nodes = {
        str(node).casefold() for event in selected
        for node in edge_endpoints.get(event, ())
    }
    candidate_missing = reference_events - candidates
    selection_missing = (reference_events & candidates) - selected
    final_missing = reference_events - selected
    return {
        "groundtruth_completeness": "PARTIAL_POSITIVE_GT",
        "reference_edges": len(reference_events),
        "candidate_edge_tp": len(reference_events & candidates),
        "candidate_edge_fn": len(candidate_missing),
        "selection_edge_fn": len(selection_missing),
        "final_edge_fn": len(final_missing),
        "candidate_edge_recall": len(reference_events & candidates) / len(reference_events) if reference_events else 1.0,
        "final_edge_recall": len(reference_events & selected) / len(reference_events) if reference_events else 1.0,
        "reference_nodes": len(reference_nodes),
        "candidate_node_fn": len(reference_nodes - candidate_nodes),
        "final_node_fn": len(reference_nodes - selected_nodes),
        "candidate_node_recall": len(reference_nodes & candidate_nodes) / len(reference_nodes) if reference_nodes else 1.0,
        "final_node_recall": len(reference_nodes & selected_nodes) / len(reference_nodes) if reference_nodes else 1.0,
    }


__all__ = ["evaluate_online_artifact"]
