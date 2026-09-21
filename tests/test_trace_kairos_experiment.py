import json

import tc_pruning.trace_kairos_experiment as trace_experiment
from tc_pruning.trace_kairos_experiment import (
    _evidence,
    detector_demand_pairs,
    scenario_scope,
    validate_online_record,
)
from tc_pruning.models import StoredEdge


def test_detector_demand_pairs_only_use_sealed_event_anchors_and_active_pois():
    edges = (
        StoredEdge(1, "alert", "P1", "P2", "EVENT_WRITE", 1, "h", "process", "file"),
        StoredEdge(2, "not-alert", "P1", "P3", "EVENT_WRITE", 2, "h", "process", "file"),
    )
    observations = [{"event_ids": ["ALERT", "MISSING"]}]

    assert detector_demand_pairs(edges, observations, {"P1", "P2", "P3"}) == frozenset({
        ("P1", "P2"),
    })


def test_day_aggregate_poi_does_not_pretend_to_have_an_exact_event_time():
    evidence = _evidence("2018-04-13", ["NODE"], 100, 200)

    assert evidence[0].timestamp_start is None
    assert evidence[0].timestamp_end is None
    assert evidence[0].detector_metadata["query_window_start_ns"] == 100
    assert evidence[0].detector_metadata["query_window_end_ns"] == 200


def test_native_window_observation_keeps_kairos_alert_time_bounds():
    evidence = _evidence(
        "2018-04-13",
        ["NODE"],
        100,
        200,
        observations=[{
            "queue_id": "queue:7", "window": "window.csv",
            "start_ns": 120, "end_ns": 140, "node_ids": ["NODE"],
            "event_ids": ["EVENT"],
        }],
    )

    assert len(evidence) == 1
    assert evidence[0].node_ids == ("NODE",)
    assert evidence[0].event_ids == ("EVENT",)
    assert evidence[0].timestamp_start == 120
    assert evidence[0].timestamp_end == 140
    assert evidence[0].detector_metadata["queue_id"] == "queue:7"


def test_scenario_without_detector_attack_poi_is_explicitly_not_scored():
    scope = scenario_scope({"detector-a"}, {"attack-b"})
    assert scope == {
        "status": "NO_ATTACK_POI_HIT",
        "detector_poi_count": 1,
        "attack_node_count": 1,
        "attack_poi_node_ids": [],
    }


def test_scenario_scope_uses_only_detector_and_attack_intersection():
    scope = scenario_scope({"A", "noise"}, {"a", "truth"})
    assert scope["status"] == "ELIGIBLE"
    assert scope["attack_poi_node_ids"] == ["a"]


def test_offline_scope_uses_all_sealed_detector_pois_not_candidate_survivors():
    scope = trace_experiment.scenario_scope_for_record(
        {
            "poi_node_ids": ["attack", "noise"],
            "candidate_poi_node_ids": ["noise"],
        },
        ["attack", "other-attack"],
    )

    assert scope["status"] == "ELIGIBLE"
    assert scope["attack_poi_node_ids"] == ["attack"]
    assert scope["candidate_attack_poi_node_ids"] == []
    assert scope["attack_poi_candidate_recall"] == 0.0


def test_online_record_has_one_candidate_hash_and_no_offline_inputs():
    record = {
        "day": "2018-04-10", "candidate_sha256": "a" * 64,
        "methods": {
            "A_rasp": {"candidate_sha256": "a" * 64},
            "A_rasp-PBR": {"candidate_sha256": "a" * 64},
            "C_branch_fair": {"candidate_sha256": "a" * 64},
        },
    }
    validate_online_record(record)
    bad = json.loads(json.dumps(record))
    bad["orthrus_csv"] = "/forbidden.csv"
    try:
        validate_online_record(bad)
    except ValueError as error:
        assert "offline" in str(error)
    else:
        raise AssertionError("offline dependency was accepted")
