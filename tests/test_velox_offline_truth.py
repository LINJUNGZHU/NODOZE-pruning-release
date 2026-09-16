import csv
import json

from tc_pruning.velox_offline_truth import build_offline_positives


def test_combines_pdf_critical_events_and_only_requested_orthrus_node_files(tmp_path):
    critical = tmp_path / "critical.json"
    critical.write_text(json.dumps({"critical_edges": [{"event_id": "e2"}, {"event_id": "e1"}, {"event_id": "e2"}]}))
    first, second = tmp_path / "06.csv", tmp_path / "12.csv"
    first.write_text("p1,{'subject': 'proc'},1\nf1,{'file': '/x'},2\n")
    second.write_text("p1,{'subject': 'proc'},1\nn1,{'netflow': 'a->b'},3\n")

    result = build_offline_positives(critical, [first, second])

    assert result["event_ids"] == ["e1", "e2"]
    assert result["node_ids"] == ["f1", "n1", "p1"]
    assert result["groundtruth_semantics"] == "PARTIAL_POSITIVE_GT"
    assert len(result["sources"]["orthrus_node_csvs"]) == 2
