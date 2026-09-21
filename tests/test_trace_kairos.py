import csv
import json

import pytest

import tc_pruning.trace_kairos as trace_kairos
from tc_pruning.trace_kairos import (
    build_native_trace_queues,
    choose_final_epoch,
    freeze_trace_pois,
    read_loss_window,
)


def _loss_csv(path, losses, *, src="1", dst="2", base=100):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=("loss", "srcnode", "dstnode", "time", "edge_type")
        )
        writer.writeheader()
        for offset, loss in enumerate(losses):
            writer.writerow({
                "loss": loss, "srcnode": src, "dstnode": dst,
                "time": base + offset, "edge_type": 3,
            })


def test_choose_final_epoch_is_numeric_and_label_free(tmp_path):
    root = tmp_path / "test"
    for name in ("model_epoch_1", "model_epoch_11", "model_epoch_9"):
        (root / name).mkdir(parents=True)
    assert choose_final_epoch(root).name == "model_epoch_11"
    with pytest.raises(ValueError, match="no model epochs"):
        choose_final_epoch(tmp_path / "missing")


def test_current_pidsmaker_csv_threshold_extracts_native_anomalous_endpoints(tmp_path):
    path = tmp_path / "2018-04-10 00.csv"
    _loss_csv(path, [1.0] * 9 + [10.0], src="17", dst="23")
    window = read_loss_window(path)
    assert window.anomalous_edges == 1
    assert window.anomalous_nodes == frozenset({"17", "23"})
    assert window.anomalous_event_keys == (("17", "23", 109),)
    assert window.start_ns == 100
    assert window.end_ns == 109
    assert window.anomaly_loss == 10.0


def test_event_mapping_groups_duplicate_raw_matches_deterministically():
    mapping = trace_kairos.group_event_mapping([
        ("1", "2", 109, "EVENT-B"),
        ("1", "2", 109, "EVENT-A"),
        ("1", "2", 109, "EVENT-A"),
        ("2", "3", 110, "EVENT-C"),
    ])

    assert mapping == {
        ("1", "2", 109): ("EVENT-A", "EVENT-B"),
        ("2", "3", 110): ("EVENT-C",),
    }


def test_native_queues_link_shared_rare_nodes_and_use_fixed_threshold(tmp_path):
    first = tmp_path / "2018-04-10 a.csv"
    second = tmp_path / "2018-04-10 b.csv"
    _loss_csv(first, [1.0] * 9 + [10.0], src="rare", dst="a")
    _loss_csv(second, [1.0] * 9 + [20.0], src="rare", dst="b", base=200)
    manifest = build_native_trace_queues(
        (first, second), training_documents=({"common"},),
        test_documents=({"rare", "a"}, {"rare", "b"}),
        node_labels={"rare": "subject uncommon", "a": "file /x", "b": "file /y"},
        queue_threshold=20.0,
    )
    assert len(manifest["queues"]) == 1
    queue = manifest["queues"][0]
    assert queue["selected"] is True
    assert queue["anomalous_node_ids"] == ["a", "b", "rare"]
    assert queue["score"] == 231.0


def test_frozen_pois_are_detector_only_uuid_mappings(tmp_path):
    loss = tmp_path / "2018-04-13 x.csv"
    _loss_csv(loss, [1.0] * 9 + [10.0], src="1", dst="2")
    queues = build_native_trace_queues(
        (loss,), training_documents=(), test_documents=({"1", "2"},),
        node_labels={}, queue_threshold=5.0,
    )
    frozen = freeze_trace_pois(
        queues,
        {"1": "UUID-A", "2": "UUID-B"},
        event_mapping={("1", "2", 109): ("EVENT-A",)},
    )
    assert frozen["poi_node_ids"] == ["UUID-A", "UUID-B"]
    assert frozen["poi_observations_by_day"] == {
        "2018-04-13": [{
            "end_ns": 109,
            "event_ids": ["EVENT-A"],
            "node_ids": ["UUID-A", "UUID-B"],
            "queue_id": "queue:0",
            "start_ns": 100,
            "window": "2018-04-13 x.csv",
        }]
    }
    assert frozen["poi_event_ids_by_day"] == {"2018-04-13": ["EVENT-A"]}
    assert frozen["event_mapping"] == {
        "mapped_anomalous_keys": 1,
        "mapped_event_ids": 1,
        "selected_anomalous_keys": 1,
        "unmapped_anomalous_keys": [],
    }
    assert frozen["mapping"]["mapped_index_nodes"] == 2
    rendered = json.dumps(frozen, sort_keys=True).lower()
    assert "groundtruth" not in rendered
    assert "orthrus" not in rendered
    assert len(frozen["content_sha256"]) == 64
