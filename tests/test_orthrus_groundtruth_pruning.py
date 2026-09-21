from pathlib import Path
from tc_pruning.orthrus_groundtruth import (
    evaluate_groundtruth_retention,
    load_orthrus_groundtruth,
)


def _edge(edge_id, event_id, src, dst, timestamp_ns):
    return {
        "edge_id": edge_id,
        "event_id": event_id,
        "src": src,
        "dst": dst,
        "timestamp_ns": timestamp_ns,
    }


def test_loads_orthrus_csv_as_typed_node_groundtruth(tmp_path: Path):
    source = tmp_path / "node_Nginx_Backdoor_06.csv"
    source.write_text(
        "PROCESS-A,{'subject': 'None nginx'},1\n"
        "FILE-A,{'file': '/tmp/x'},2\n"
        "FLOW-A,{'netflow': 'a:1->b:2'},3\n",
        encoding="utf-8",
    )

    truth = load_orthrus_groundtruth(source)

    assert truth["source"] == str(source.resolve())
    assert truth["node_ids"] == ["FILE-A", "FLOW-A", "PROCESS-A"]
    assert truth["node_type_counts"] == {"file": 1, "process": 1, "socket": 1}
    assert truth["semantics"] == "ORTHRUS node-level ground truth"


def test_reports_nodes_and_strict_temporal_paths_remaining_after_pruning():
    candidate = [
        _edge(1, "e1", "attack-a", "x", 1),
        _edge(2, "e2", "x", "attack-b", 2),
        _edge(3, "e3", "attack-a", "y", 3),
        _edge(4, "e4", "y", "attack-b", 4),
        # Equal-time edges cannot be chained into a false temporal path.
        _edge(5, "e5", "attack-b", "z", 5),
        _edge(6, "e6", "z", "attack-c", 5),
    ]

    result = evaluate_groundtruth_retention(
        candidate_edges=candidate,
        selected_event_ids={"e3", "e4"},
        groundtruth_node_ids={"attack-a", "attack-b", "attack-c"},
    )

    assert result["groundtruth_nodes"] == 3
    assert result["candidate_groundtruth_nodes"] == 3
    assert result["retained_groundtruth_nodes"] == 2
    assert result["candidate_strict_temporal_paths"] == 1
    assert result["retained_strict_temporal_paths"] == 1
    assert result["canonical_candidate_paths_fully_retained"] == 0
    assert result["strict_temporal_path_reachability_retention"] == 1.0
    assert result["canonical_path_event_retention"] == 0.0
