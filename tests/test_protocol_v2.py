import json

from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.protocol_v2 import evaluate_protocol_v2
from tc_pruning.cli import build_parser


def edge(i, event, src, dst, timestamp=None, relation="EVENT_WRITE"):
    return StoredEdge(i, event, src, dst, relation, timestamp or i, "h", "process", "process")


def fixture():
    edges = [
        edge(1, "a", "n1", "n2", 1),
        edge(2, "b", "n2", "n3", 2),
        edge(3, "x", "n1", "n3", 3),
    ]
    graph = Neighborhood({n: NodeRecord(n, "process", n) for n in ("n1", "n2", "n3")}, edges)
    annotation = {
        "name": "tiny",
        "attack_node_uuids": ["n1", "n2", "n3", "missing-node"],
        "attack_event_ids": ["a", "b", "missing-event"],
        "attack_paths": [["a", "b"]],
        "metadata": {
            "groundtruth_source": "labels.csv",
            "groundtruth_source_sha256": "abc",
            "groundtruth_family": "ubc-provenance/ground-truth",
            "attack_event_rule": "both endpoints and time window",
            "path_rule": "derived",
            "path_quality": "derived_not_human",
        },
    }
    return graph, annotation


def test_protocol_v2_uses_fixed_denominators_and_reports_missing_labels():
    graph, annotation = fixture()
    report = evaluate_protocol_v2(
        candidate_graph=graph,
        retained_edges=graph.edges[:1],
        annotations=annotation,
        requested_retention=0.5,
        merge_threshold_seconds=0.0,
    )
    assert report["metrics"]["candidate_node_recall"] == {"numerator": 3, "denominator": 4, "value": 0.75}
    assert report["metrics"]["candidate_derived_event_recall"] == {"numerator": 2, "denominator": 3, "value": 2 / 3}
    assert report["metrics"]["conditional_derived_event_retention"] == {"numerator": 1, "denominator": 2, "value": 0.5}
    assert report["unmatched_annotations"] == {"node_ids": ["missing-node"], "event_ids": ["missing-event"]}


def test_strict_path_fails_when_required_edge_missing_even_with_alternative_reachability():
    graph, annotation = fixture()
    report = evaluate_protocol_v2(
        candidate_graph=graph,
        retained_edges=[graph.edges[0], graph.edges[2]],
        annotations=annotation,
        requested_retention=1.0,
        merge_threshold_seconds=0.0,
    )
    item = report["path_diagnostics"][0]
    assert item["candidate_satisfied"] is True
    assert item["retained_satisfied"] is False
    assert item["missing_retained_event_ids"] == ["b"]
    assert report["metrics"]["derived_reference_path_retention"]["value"] == 0.0
    assert report["metrics"]["verified_attack_path_retention"]["value"] is None


def test_event_groups_keep_exact_raw_event_cost_and_detect_partial_groups():
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in ("a", "b")},
        [edge(1, "e1", "a", "b", 1), edge(2, "e2", "a", "b", 2)],
    )
    annotation = {"attack_node_uuids": [], "attack_event_ids": [], "attack_paths": [], "metadata": {}}
    report = evaluate_protocol_v2(
        candidate_graph=graph,
        retained_edges=graph.edges[:1],
        annotations=annotation,
        requested_retention=0.5,
        merge_threshold_seconds=10.0,
    )
    assert report["graph_size"]["candidate_event_count"] == 2
    assert report["graph_size"]["candidate_event_group_count"] == 1
    assert report["graph_size"]["retained_event_group_count"] == 0
    assert report["event_groups"][0]["member_event_ids"] == ["e1", "e2"]
    assert report["event_groups"][0]["status"] == "partially_retained"


def test_zero_denominator_and_incomplete_are_explicit():
    graph = Neighborhood({}, [])
    report = evaluate_protocol_v2(
        candidate_graph=graph,
        retained_edges=[],
        annotations={"attack_node_uuids": [], "attack_event_ids": [], "attack_paths": [], "metadata": {}},
        requested_retention=0.2,
        merge_threshold_seconds=10.0,
        incomplete=True,
        truncation_reason="timeout",
    )
    assert report["metrics"]["candidate_node_recall"]["value"] is None
    assert report["metrics"]["candidate_node_recall"]["reason"] == "zero_denominator"
    assert report["graph_size"]["incomplete"] is True
    assert report["graph_size"]["truncation_reason"] == "timeout"


def test_invalid_derived_reference_path_makes_path_metrics_na():
    edges = [edge(1, "a", "n1", "n2", 2), edge(2, "b", "n3", "n4", 1)]
    graph = Neighborhood({}, edges)
    report = evaluate_protocol_v2(
        candidate_graph=graph,
        retained_edges=edges,
        annotations={"attack_node_uuids": [], "attack_event_ids": [], "attack_paths": [["a", "b"]], "metadata": {}},
        requested_retention=1.0,
        merge_threshold_seconds=0.0,
    )
    metric = report["metrics"]["derived_reference_path_retention"]
    assert metric["value"] is None
    assert metric["reason"] == "invalid_derived_reference_paths"


def test_cli_exposes_offline_protocol_v2_restatistics_command():
    args = build_parser().parse_args([
        "report-protocol-v2", "--db", "graph.db", "--result", "old.json",
        "--annotations", "truth.json", "--output", "new.json",
    ])
    assert args.command == "report-protocol-v2"
