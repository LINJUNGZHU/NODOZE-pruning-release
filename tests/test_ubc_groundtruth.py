import csv
import json
import hashlib
import pytest
from datetime import datetime, timezone

from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore
from tc_pruning.ubc_groundtruth import prepare_ubc_manifests


def _utc_ns(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc
    ).timestamp() * 1_000_000_000)


def _write_scenario(directory, code, rows):
    path = directory / f"node_Nginx_Backdoor_{code}.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerows(rows)
    return path


def test_prepare_ubc_manifest_uses_core_nodes_and_scenario_time_window(tmp_path):
    groundtruth = tmp_path / "E3-CADETS"
    groundtruth.mkdir()
    _write_scenario(
        groundtruth,
        "06",
        [
            ["A", "{'subject': 'nginx'}", "9001"],
            ["B", "{'file': '/tmp/backdoor'}", "9002"],
            ["C", "{'netflow': 'attacker->victim'}", "9003"],
            ["MISSING", "{'file': '/not-captured'}", "9999"],
        ],
    )
    output_dir = tmp_path / "annotations"
    observations = [
        NodeRecord(name, "process", name, "h") for name in ("A", "B", "C", "Z")
    ] + [
        EdgeRecord("before", "A", "B", "R", _utc_ns("2018-04-06 15:19:59"), "h"),
        EdgeRecord("alert", "A", "B", "R", _utc_ns("2018-04-06 15:20:01"), "h"),
        EdgeRecord("attack", "B", "C", "R", _utc_ns("2018-04-06 16:08:59"), "h"),
        EdgeRecord("context", "C", "Z", "R", _utc_ns("2018-04-06 15:30:00"), "h"),
        EdgeRecord("after", "A", "C", "R", _utc_ns("2018-04-06 16:09:01"), "h"),
    ]

    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        manifests = prepare_ubc_manifests(
            store,
            groundtruth,
            output_dir=output_dir,
            scenario="06",
        )

    assert len(manifests) == 1
    manifest = manifests[0]
    assert manifest["name"] == "DARPA TC E3 CADETS UBC core attack 06"
    assert set(manifest["seed_event_ids"]) == {"alert", "attack"}
    assert set(manifest["seed_uuids"]) == {"A", "B", "C"}
    assert set(manifest["attack_node_uuids"]) == {"A", "B", "C"}
    assert set(manifest["attack_event_ids"]) == {"alert", "attack"}
    assert manifest["attack_node_attributes"]["A"] == {"subject": "nginx"}
    assert manifest["metadata"]["groundtruth_uuid_count"] == 4
    assert manifest["metadata"]["matched_attack_node_count"] == 3
    assert manifest["metadata"]["attack_event_rule"] == (
        "event occurs inside the UBC scenario time window and both endpoints "
        "are UBC core attack nodes"
    )
    source = groundtruth / "node_Nginx_Backdoor_06.csv"
    assert manifest["metadata"]["groundtruth_source_sha256"] == hashlib.sha256(
        source.read_bytes()
    ).hexdigest()
    assert manifest["metadata"]["groundtruth_family"] == "ubc-provenance/ground-truth"
    saved = json.loads(
        (output_dir / "cadets-e3-ubc-06-annotations.json").read_text(encoding="utf-8")
    )
    assert saved == manifest


def test_prepare_ubc_manifests_all_keeps_attack_scenarios_separate(tmp_path):
    groundtruth = tmp_path / "E3-CADETS"
    groundtruth.mkdir()
    for code in ("06", "12", "13"):
        _write_scenario(
            groundtruth,
            code,
            [[f"{code}-A", "{'subject': 'nginx'}", f"{code}01"],
             [f"{code}-B", "{'file': '/tmp/payload'}", f"{code}02"]],
        )
    event_times = {
        "06": "2018-04-06 15:30:00",
        "12": "2018-04-12 18:10:00",
        "13": "2018-04-13 13:10:00",
    }
    observations = []
    for code, timestamp in event_times.items():
        observations.extend(
            [
                NodeRecord(f"{code}-A", "process", f"{code}-A", "h"),
                NodeRecord(f"{code}-B", "file", f"{code}-B", "h"),
                EdgeRecord(
                    f"event-{code}",
                    f"{code}-A",
                    f"{code}-B",
                    "R",
                    _utc_ns(timestamp),
                    "h",
                ),
            ]
        )

    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        manifests = prepare_ubc_manifests(
            store,
            groundtruth,
            output_dir=tmp_path / "annotations",
            scenario="all",
        )

    assert [item["metadata"]["scenario"] for item in manifests] == ["06", "12", "13"]
    assert [item["seed_event_ids"] for item in manifests] == [
        ["event-06"],
        ["event-12"],
        ["event-13"],
    ]
    assert all(item["metadata"]["poi_selection_scope"] == "per_scenario" for item in manifests)
    assert all(item["attack_paths"] == [[f"event-{code}"]] for item, code in zip(manifests, ("06", "12", "13")))


def test_prepare_ubc_manifest_uses_ordered_external_pdf_pois_as_one_incident(tmp_path):
    groundtruth = tmp_path / "E3-CADETS"
    groundtruth.mkdir()
    _write_scenario(
        groundtruth, "12",
        [["A", "{'subject': 'nginx'}"], ["B", "{'file': '/tmp/XIM'}"],
         ["C", "{'subject': 'XIM'}"]],
    )
    observations = [
        NodeRecord("A", "process", "nginx", "h"),
        NodeRecord("B", "file", "/tmp/XIM", "h"),
        NodeRecord("C", "process", "XIM", "h"),
        EdgeRecord("download", "A", "B", "EVENT_WRITE", _utc_ns("2018-04-12 18:10:00"), "h"),
        EdgeRecord("execute", "B", "C", "EVENT_EXECUTE", _utc_ns("2018-04-12 18:20:00"), "h"),
    ]

    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        manifest = prepare_ubc_manifests(
            store, groundtruth, output_dir=tmp_path / "out", scenario="12",
            poi_event_ids=("download", "execute"),
        )[0]

    group = manifest["seed_event_groups"][0]
    assert manifest["seed_event_ids"] == ["download", "execute"]
    assert group["group_id"] == "ubc-12-pdf-incident"
    assert group["seed_event_ids"] == ["download", "execute"]
    assert group["window_start_ns"] == _utc_ns("2018-04-12 17:59:00")
    assert group["window_end_ns"] == _utc_ns("2018-04-12 18:39:00")
    assert [path[-1] for path in manifest["attack_paths"]] == ["download", "execute"]
    assert manifest["metadata"]["seed_rule"] == "ordered analyst POIs from DARPA report"


def test_prepare_ubc_manifest_rejects_external_poi_outside_groundtruth(tmp_path):
    groundtruth = tmp_path / "E3-CADETS"
    groundtruth.mkdir()
    _write_scenario(groundtruth, "12", [["A", "{}"], ["B", "{}"]])
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([
            NodeRecord("A", "process", "A", "h"), NodeRecord("B", "file", "B", "h"),
            EdgeRecord("outside", "A", "B", "EVENT_WRITE", 1, "h"),
            EdgeRecord("inside", "A", "B", "EVENT_WRITE", _utc_ns("2018-04-12 18:10:00"), "h"),
        ])
        with pytest.raises(ValueError, match="outside the UBC 12 attack window"):
            prepare_ubc_manifests(
                store, groundtruth, output_dir=tmp_path / "out", scenario="12",
                poi_event_ids=("outside",),
            )
