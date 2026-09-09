import pytest

from tc_pruning.alert_evaluation import (
    aggregate_alert_metrics,
    associate_groundtruth_components,
    evaluate_alert_context,
    time_respecting_groundtruth_context,
)
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge


def test_time_respecting_truth_excludes_close_after_earlier_accept_state():
    accept = _edge(1, "accept", "remote", "nginx", "EVENT_ACCEPT", 10)
    close = _edge(2, "close", "nginx", "remote", "EVENT_CLOSE", 11)
    poi = _edge(3, "poi", "nginx", "sink", "EVENT_SENDTO", 20)

    selected = time_respecting_groundtruth_context([poi], [accept, close, poi])

    assert selected == {"accept", "poi"}


def test_time_respecting_truth_includes_parallel_poi_dependency():
    poi = _edge(1, "poi", "process", "socket", "SEND", 20)
    parallel = _edge(2, "parallel", "process", "socket", "SEND", 20)

    assert time_respecting_groundtruth_context([poi], [poi, parallel]) == {
        "poi", "parallel"
    }


def test_time_respecting_truth_includes_common_ancestor_sibling_branch():
    parent = _edge(1, "parent-created", "root", "parent", "EVENT_FORK", 1)
    poi_birth = _edge(2, "poi-created", "parent", "poi-process", "EVENT_FORK", 2)
    sibling = _edge(3, "sibling-created", "parent", "sibling", "EVENT_FORK", 3)
    sibling_action = _edge(4, "sibling-action", "sibling", "sink", "EVENT_WRITE", 4)
    poi = _edge(5, "poi", "poi-process", "sink", "EVENT_WRITE", 10)

    selected = time_respecting_groundtruth_context(
        [poi], [parent, poi_birth, sibling, sibling_action, poi]
    )

    assert {"sibling-created", "sibling-action"} <= selected


def _edge(edge_id, event_id, src, dst, relation, timestamp_ns=None):
    return StoredEdge(
        edge_id=edge_id,
        event_id=event_id,
        src=src,
        dst=dst,
        relation=relation,
        timestamp_ns=edge_id if timestamp_ns is None else timestamp_ns,
        host="h",
        src_type="process",
        dst_type="process" if relation == "EVENT_FORK" else "file",
    )


def _graph(edges):
    nodes = {
        node: NodeRecord(node, "process", node, "h")
        for edge in edges
        for node in (edge.src, edge.dst)
    }
    return Neighborhood(nodes, list(edges))


def test_alert_denominator_contains_only_anchored_truth_component():
    truth_edges = [
        _edge(1, "attack-control", "a", "b", "EVENT_FORK"),
        _edge(2, "attack-data", "b", "c", "EVENT_READ"),
        _edge(3, "other-stage", "x", "y", "EVENT_FORK"),
    ]
    alert_edges = [
        _edge(10, "attack-control", "a", "b", "EVENT_FORK"),
        _edge(11, "benign-context", "b", "z", "EVENT_WRITE"),
    ]

    association = associate_groundtruth_components(
        group_id="window-1",
        alert_edges=alert_edges,
        groundtruth_edges=truth_edges,
        groundtruth_node_ids={"a", "b", "c", "x", "y"},
    )

    assert association["associated"] is True
    assert association["association_status"] == "strong"
    assert association["association_method"] == "event_and_node"
    assert association["attack_event_ids"] == ["attack-control", "attack-data"]
    assert association["attack_node_ids"] == ["a", "b", "c"]
    assert "other-stage" not in association["attack_event_ids"]


def test_unassociated_alert_is_excluded_from_attack_recall_denominator():
    association = associate_groundtruth_components(
        group_id="false-alert",
        alert_edges=[_edge(10, "alert", "u", "v", "EVENT_WRITE")],
        groundtruth_edges=[_edge(1, "attack", "a", "b", "EVENT_FORK")],
        groundtruth_node_ids={"a", "b"},
    )

    assert association == {
        "group_id": "false-alert",
        "associated": False,
        "association_status": "none",
        "association_method": None,
        "anchor_event_ids": [],
        "anchor_node_ids": [],
        "attack_event_ids": [],
        "attack_node_ids": [],
    }


def test_node_only_overlap_is_weak_and_not_a_primary_reconstruction_case():
    association = associate_groundtruth_components(
        group_id="node-only",
        alert_edges=[_edge(10, "benign-on-compromised-node", "a", "z", "EVENT_WRITE")],
        groundtruth_edges=[_edge(1, "attack", "a", "b", "EVENT_FORK")],
        groundtruth_node_ids={"a", "b"},
    )

    assert association["associated"] is False
    assert association["association_status"] == "weak"
    assert association["association_method"] == "node"
    assert association["attack_event_ids"] == ["attack"]
    assert association["attack_node_ids"] == ["a", "b"]


def test_pruned_metrics_penalize_benign_edges_and_separate_control_from_data():
    truth_edges = [
        _edge(1, "attack-control", "a", "b", "EVENT_FORK"),
        _edge(2, "attack-data", "b", "c", "EVENT_READ"),
    ]
    candidate_edges = [
        truth_edges[0],
        truth_edges[1],
        _edge(3, "benign", "b", "z", "EVENT_WRITE"),
    ]
    association = associate_groundtruth_components(
        group_id="window-1",
        alert_edges=[truth_edges[0]],
        groundtruth_edges=truth_edges,
        groundtruth_node_ids={"a", "b", "c"},
    )

    metrics = evaluate_alert_context(
        candidate_graph=_graph(candidate_edges),
        kept_edges=[candidate_edges[0], candidate_edges[2]],
        association=association,
        groundtruth_edges=truth_edges,
    )

    assert metrics["candidate_attack_edge_recall"] == 1.0
    assert metrics["pruned_attack_edge_recall"] == 0.5
    assert metrics["conditional_attack_edge_retention"] == 0.5
    assert metrics["pruned_edge_precision"] == 0.5
    assert metrics["pruned_edge_f1"] == 0.5
    assert metrics["control_dependency"]["recall"] == 1.0
    assert metrics["control_dependency"]["false_positive_rate"] == 0.0
    assert metrics["data_dependency"]["recall"] == 0.0
    assert metrics["data_dependency"]["false_positive_rate"] == 1.0


def test_context_metrics_exclude_the_protected_alert_anchor_from_reconstruction_credit():
    anchor = _edge(1, "alert-anchor", "a", "b", "EVENT_FORK")
    context = _edge(2, "attack-context", "b", "c", "EVENT_READ")
    benign = _edge(3, "benign", "b", "z", "EVENT_WRITE")
    association = associate_groundtruth_components(
        group_id="window-1",
        alert_edges=[anchor],
        groundtruth_edges=[anchor, context],
        groundtruth_node_ids={"a", "b", "c"},
    )

    metrics = evaluate_alert_context(
        candidate_graph=_graph([anchor, context, benign]),
        kept_edges=[anchor, benign],
        association=association,
        groundtruth_edges=[anchor, context],
    )

    assert metrics["pruned_attack_edge_recall"] == 0.5
    assert metrics["candidate_context_edge_recall"] == 1.0
    assert metrics["pruned_context_edge_recall"] == 0.0
    assert metrics["conditional_context_edge_retention"] == 0.0
    assert metrics["pruned_context_edge_precision"] == 0.0
    assert metrics["counts"]["groundtruth_context_edges"] == 1
    assert metrics["counts"]["kept_groundtruth_context_edges"] == 0


def test_empty_retained_context_has_zero_precision_and_recall_not_perfect_scores():
    truth_edge = _edge(1, "attack", "a", "b", "EVENT_FORK")
    association = associate_groundtruth_components(
        group_id="window-1",
        alert_edges=[truth_edge],
        groundtruth_edges=[truth_edge],
        groundtruth_node_ids={"a", "b"},
    )

    metrics = evaluate_alert_context(
        candidate_graph=_graph([truth_edge]),
        kept_edges=[],
        association=association,
        groundtruth_edges=[truth_edge],
    )

    assert metrics["pruned_attack_edge_recall"] == 0.0
    assert metrics["pruned_edge_precision"] == 0.0
    assert metrics["pruned_edge_f1"] == 0.0
    assert metrics["conditional_attack_edge_retention"] == 0.0
    assert metrics["conditional_pruning_edge_recall"] == 0.0


def test_aggregate_metrics_excludes_unassociated_alerts_and_reports_macro_and_micro():
    associated = {
        "associated": True,
        "association_status": "strong",
        "pruned_attack_edge_recall": 0.5,
        "pruned_edge_precision": 0.5,
        "pruned_edge_f1": 0.5,
        "pruned_attack_node_recall": 1.0,
        "pruned_node_precision": 0.5,
        "pruned_node_f1": 2 / 3,
        "candidate_attack_edge_recall": 1.0,
        "candidate_attack_node_recall": 1.0,
        "conditional_attack_edge_retention": 0.5,
        "conditional_attack_node_retention": 1.0,
        "candidate_context_edge_recall": 1.0,
        "pruned_context_edge_recall": 0.0,
        "conditional_context_edge_retention": 0.0,
        "pruned_context_edge_precision": 0.0,
        "pruned_context_edge_f1": 0.0,
        "counts": {
            "groundtruth_nodes": 2,
            "groundtruth_edges": 2,
            "candidate_groundtruth_nodes": 2,
            "candidate_groundtruth_edges": 2,
            "kept_groundtruth_nodes": 2,
            "kept_groundtruth_edges": 1,
            "groundtruth_context_edges": 1,
            "candidate_groundtruth_context_edges": 1,
            "kept_groundtruth_context_edges": 0,
            "kept_context_edges": 1,
        },
        "kept_nodes": 4,
        "kept_edges": 2,
    }
    weak = {
        "associated": False,
        "association_status": "weak",
        "group_id": "weak-alert",
    }
    unassociated = {
        "associated": False,
        "association_status": "none",
        "group_id": "false-alert",
    }

    aggregate = aggregate_alert_metrics([associated, weak, unassociated])

    assert aggregate["associated_alert_groups"] == 1
    assert aggregate["unassociated_alert_groups"] == 1
    assert aggregate["weakly_associated_alert_groups"] == 1
    assert aggregate["macro"]["pruned_attack_edge_recall"] == 0.5
    assert aggregate["micro"]["pruned_attack_edge_recall"] == 0.5
    assert aggregate["micro"]["pruned_edge_precision"] == 0.5
    assert aggregate["micro"]["pruned_context_edge_recall"] == 0.0
