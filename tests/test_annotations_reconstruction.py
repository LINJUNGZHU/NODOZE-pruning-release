import json

from tc_pruning.annotations import prepare_groundtruth_manifest
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.reconstruction import reconstruct_retained_paths
from tc_pruning.store import ProvenanceStore


def test_prepare_manifest_uses_earliest_internal_groundtruth_event_as_alert(tmp_path):
    groundtruth = tmp_path / "groundtruth.txt"
    groundtruth.write_text("a\nb\nc\nmissing\n", encoding="utf-8")
    output = tmp_path / "annotations.json"
    observations = [
        NodeRecord(name, "process", name, "h") for name in "abcz"
    ] + [
        EdgeRecord("e-alert", "a", "b", "R", 10, "h"),
        EdgeRecord("e-attack", "b", "c", "R", 20, "h"),
        EdgeRecord("e-normal", "a", "z", "R", 5, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        manifest = prepare_groundtruth_manifest(
            store, groundtruth, output_path=output
        )

    assert manifest["seed_event_ids"] == ["e-alert"]
    assert set(manifest["seed_uuids"]) == {"a", "b"}
    assert set(manifest["attack_node_uuids"]) == {"a", "b", "c"}
    assert set(manifest["attack_event_ids"]) == {"e-alert", "e-attack"}
    assert json.loads(output.read_text(encoding="utf-8")) == manifest


def test_reconstruction_returns_only_complete_retained_ordered_paths():
    from tc_pruning.models import StoredEdge

    def edge(edge_id, src, dst):
        return StoredEdge(
            edge_id,
            f"e{edge_id}",
            src,
            dst,
            "R",
            edge_id,
            "h",
            "process",
            "process",
        )

    path = [edge(1, "a", "b"), edge(2, "b", "c"), edge(3, "c", "d")]

    complete = reconstruct_retained_paths([path], path, [0.9])
    incomplete = reconstruct_retained_paths([path], path[:2], [0.9])

    assert complete == [
        {
            "event_ids": ["e1", "e2", "e3"],
            "node_uuids": ["a", "b", "c", "d"],
            "anomaly_score": 0.9,
        }
    ]
    assert incomplete == []
