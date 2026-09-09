import json

import pytest

from tc_pruning.poi import load_poi_event_ids, load_poi_manifest
from tc_pruning.poi import select_poi_events
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.nodoze import NODOZEFrequencyModel
from tc_pruning.store import ProvenanceStore
from tc_pruning.cli import build_parser, main


def test_poi_loader_accepts_json_object_array_and_text(tmp_path):
    object_path = tmp_path / "object.json"
    object_path.write_text(json.dumps({"event_ids": ["e2", "e1", "e2"]}), encoding="utf-8")
    array_path = tmp_path / "array.json"
    array_path.write_text(json.dumps(["e3", "e1"]), encoding="utf-8")
    text_path = tmp_path / "events.txt"
    text_path.write_text("# analyst POIs\ne4\n\ne5\n", encoding="utf-8")

    assert load_poi_event_ids(object_path) == ["e1", "e2"]
    assert load_poi_event_ids(array_path) == ["e1", "e3"]
    assert load_poi_event_ids(text_path) == ["e4", "e5"]


def test_poi_loader_rejects_empty_input(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("# no ids\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no POI event IDs"):
        load_poi_event_ids(path)


def test_poi_loader_accepts_windows_powershell_utf8_bom(tmp_path):
    path = tmp_path / "powershell.json"
    path.write_bytes(b'\xef\xbb\xbf["event-1"]')

    assert load_poi_event_ids(path) == ["event-1"]


def test_poi_manifest_preserves_explicit_incident_order_and_window(tmp_path):
    path = tmp_path / "incident.json"
    path.write_text(
        json.dumps(
            {
                "event_ids": ["stage-1", "stage-2"],
                "seed_event_groups": [
                    {
                        "group_id": "incident-12",
                        "seed_event_ids": ["stage-1", "stage-2"],
                        "window_start_ns": 100,
                        "window_end_ns": 200,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = load_poi_manifest(path)

    assert manifest.event_ids == ("stage-1", "stage-2")
    assert len(manifest.groups) == 1
    assert manifest.groups[0].group_id == "incident-12"
    assert manifest.groups[0].event_ids == ("stage-1", "stage-2")
    assert manifest.groups[0].window_start_ns == 100
    assert manifest.groups[0].window_end_ns == 200


@pytest.mark.parametrize(
    "group, message",
    [
        (
            {
                "group_id": "partial",
                "seed_event_ids": ["stage-1"],
                "window_start_ns": 100,
            },
            "both window_start_ns and window_end_ns",
        ),
        (
            {
                "group_id": "reversed",
                "seed_event_ids": ["stage-1"],
                "window_start_ns": 200,
                "window_end_ns": 100,
            },
            "window_end_ns must be greater",
        ),
    ],
)
def test_poi_manifest_rejects_invalid_explicit_window(tmp_path, group, message):
    path = tmp_path / "invalid.json"
    path.write_text(
        json.dumps({"event_ids": ["stage-1"], "seed_event_groups": [group]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        load_poi_manifest(path)


def test_legacy_multi_poi_manifest_defaults_to_one_incident(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"event_ids": ["late", "early"]}), encoding="utf-8")

    manifest = load_poi_manifest(path)

    assert manifest.event_ids == ("late", "early")
    assert [group.group_id for group in manifest.groups] == ["all-pois"]
    assert manifest.groups[0].event_ids == ("late", "early")


def test_multi_poi_selector_prefers_diverse_downstream_terminal_events(tmp_path):
    observations = [
        NodeRecord(name, "process", name, "h") for name in "abcdef"
    ] + [
        EdgeRecord("early", "a", "b", "READ", 1, "h"),
        EdgeRecord("terminal-one", "b", "c", "WRITE", 2, "h", 100),
        EdgeRecord("same-destination-later", "a", "c", "WRITE", 3, "h", 10),
        EdgeRecord("terminal-two", "d", "e", "SEND", 4, "h", 200),
    ]
    candidate_ids = {
        "early", "terminal-one", "same-destination-later", "terminal-two"
    }
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        selection = select_poi_events(
            store,
            candidate_ids,
            NODOZEFrequencyModel({}, {}, 1),
            max_pois=2,
            source_kind="groundtruth",
        )

    assert selection.oracle_derived is True
    assert len(selection.event_ids) == 2
    destinations = {item.dst for item in selection.selected}
    assert len(destinations) == 2
    assert "early" not in selection.event_ids
    assert all(item.components["terminality"] == 1.0 for item in selection.selected)


def test_select_pois_cli_accepts_candidate_manifest_and_source_kind():
    args = build_parser().parse_args(
        [
            "select-pois",
            "--db", "graph.db",
            "--candidates", "ubc06.json",
            "--output", "pois.json",
            "--max-pois", "4",
            "--source-kind", "groundtruth",
        ]
    )

    assert args.command == "select-pois"
    assert args.max_pois == 4
    assert args.source_kind == "groundtruth"


def test_selector_keeps_downstream_poi_from_each_long_running_attack_episode(tmp_path):
    second = 1_000_000_000
    observations = [
        NodeRecord(name, "process", name, "h") for name in "abcd"
    ] + [
        EdgeRecord("stage-1", "a", "b", "EVENT_SENDTO", 1 * second, "h"),
        EdgeRecord("stage-2", "a", "b", "EVENT_SENDTO", 50 * second, "h"),
        EdgeRecord("stage-3", "a", "b", "EVENT_SENDTO", 100 * second, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        selection = select_poi_events(
            store,
            {"stage-1", "stage-2", "stage-3"},
            NODOZEFrequencyModel({}, {}, 1),
            max_pois=5,
            source_kind="groundtruth",
        )

    assert set(selection.event_ids) == {"stage-1", "stage-2", "stage-3"}


def test_select_pois_cli_records_pre_candidate_frequency_cutoff(tmp_path):
    database = tmp_path / "graph.db"
    candidates = tmp_path / "candidates.json"
    output = tmp_path / "pois.json"
    candidates.write_text(json.dumps({"event_ids": ["candidate"]}), encoding="utf-8")
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord("a", "process", "a", "h"),
                NodeRecord("b", "process", "b", "h"),
                EdgeRecord("history", "a", "b", "EVENT_SENDTO", 10, "h"),
                EdgeRecord("candidate", "a", "b", "EVENT_SENDTO", 20, "h"),
                EdgeRecord("future", "a", "b", "EVENT_SENDTO", 30, "h"),
            ]
        )

    assert main(
        [
            "select-pois", "--db", str(database),
            "--candidates", str(candidates), "--output", str(output),
        ]
    ) == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["metadata"]["frequency_cutoff_ns"] == 20
