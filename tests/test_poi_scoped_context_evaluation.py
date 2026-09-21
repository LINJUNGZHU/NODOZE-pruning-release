from __future__ import annotations

import hashlib
import json

from tc_pruning.benchmark_contract import EdgeProjection
from tc_pruning.models import EdgeRecord, NodeRecord, StoredEdge
from tc_pruning.orthrus_groundtruth import evaluate_poi_scoped_retention
from tc_pruning.store import ProvenanceStore


def _edge(edge_id, event_id, src, dst, timestamp_ns):
    return {
        "edge_id": edge_id,
        "event_id": event_id,
        "src": src,
        "dst": dst,
        "relation": "EVENT_WRITE",
        "timestamp_ns": timestamp_ns,
    }


def test_only_paths_with_a_poi_endpoint_enter_the_reconstruction_denominator():
    candidate = [
        _edge(1, "back-early-1", "attack-entry", "early", 1),
        _edge(2, "back-early-2", "early", "poi-back", 5),
        _edge(3, "back-alt-1", "attack-entry", "alternate", 10),
        _edge(4, "back-alt-2", "alternate", "poi-back", 20),
        _edge(5, "forward-1", "poi-forward", "forward-mid", 30),
        _edge(6, "forward-2", "forward-mid", "attack-impact", 40),
        _edge(7, "poi-pair", "poi-left", "poi-right", 50),
        _edge(8, "unrelated", "attack-other-a", "attack-other-b", 60),
        _edge(9, "benign-output", "noise-a", "noise-b", 70),
    ]

    result = evaluate_poi_scoped_retention(
        candidate_edges=candidate,
        selected_event_ids={
            "back-alt-1", "back-alt-2", "poi-pair", "benign-output"
        },
        groundtruth_node_ids={
            "attack-entry", "poi-back", "poi-forward", "attack-impact",
            "poi-left", "poi-right", "attack-other-a", "attack-other-b",
        },
        poi_node_ids={"poi-back", "poi-forward", "poi-left", "poi-right"},
    )

    # The unrelated attack-other-a -> attack-other-b path is outside every POI.
    assert result["scope"]["all_attack_pair_paths"] == 4
    assert result["scope"]["eligible_poi_paths"] == 3
    assert result["scope"]["excluded_non_poi_paths"] == 1

    backward = result["path_families"]["backward_path"]
    assert backward["eligible_paths"] == 1
    assert backward["canonical_complete_paths"] == 0
    assert backward["strict_reachable_pairs"] == 1
    assert backward["canonical_path_retention"] == 0.0
    assert backward["strict_temporal_reachability_retention"] == 1.0

    assert result["path_families"]["forward_path"]["canonical_path_retention"] == 0.0
    assert result["path_families"]["poi_to_poi_path"]["canonical_path_retention"] == 1.0
    assert result["path_families"]["anomaly_path"]["canonical_path_retention"] == 1 / 3

    # Partial-positive ORTHRUS labels cannot support FP/FPR/precision claims.
    contexts = result["contexts_aligned"]
    assert contexts["tp"] == 1
    assert contexts["tpr"] == 0.2
    assert contexts["non_poi_reference_nodes"] == 2
    assert contexts["non_poi_node_tp"] == 1
    assert contexts["non_poi_node_recall"] == 0.5
    assert contexts["unlabeled_output_edges"] == 3
    assert contexts["fp"] is None
    assert contexts["fpr"] is None
    assert contexts["precision"] is None
    assert contexts["negative_label_status"] == "NOT_AVAILABLE_PARTIAL_POSITIVE_GT"


def test_time_and_length_views_use_exclusive_hand_checked_buckets():
    minute = 60_000_000_000
    candidate = [
        _edge(1, "short-1", "attack-a", "m1", 1),
        _edge(2, "short-2", "m1", "poi-short", 1 + minute),
        _edge(3, "long-1", "poi-long", "m2", 10),
        _edge(4, "long-2", "m2", "m3", 10 + minute),
        _edge(5, "long-3", "m3", "attack-b", 10 + 11 * minute),
    ]

    result = evaluate_poi_scoped_retention(
        candidate_edges=candidate,
        selected_event_ids={"short-1", "short-2"},
        groundtruth_node_ids={"attack-a", "poi-short", "poi-long", "attack-b"},
        poi_node_ids={"poi-short", "poi-long"},
    )

    time_path = result["time_path"]
    assert time_path["by_time_interval"]["<=1m"]["eligible_paths"] == 1
    assert time_path["by_time_interval"][">1d"]["eligible_paths"] == 0
    assert time_path["by_path_length"]["1-2"]["canonical_path_retention"] == 1.0
    assert time_path["by_path_length"]["3-5"]["canonical_path_retention"] == 0.0
    assert time_path["by_path_length"][">10"]["canonical_path_retention"] is None
    assert time_path["time_interval_ns"]["maximum"] == 11 * minute
    assert time_path["path_length_edges"]["maximum"] == 3
    assert result["anomaly_time"]["<=1m|1-2"]["eligible_paths"] == 1
    assert result["anomaly_time"]["<=1h|3-5"]["eligible_paths"] == 1


def _stored(edge_id, event_id, src, dst, timestamp_ns):
    return StoredEdge(
        edge_id, event_id, src, dst, "EVENT_WRITE", timestamp_ns, "h",
        "process", "file",
    )


def test_k6_proxy_selection_uses_one_kairos_ranked_incident_event_per_poi():
    from tc_pruning.kairos_poi_experiment import select_poi_proxies

    edges = (
        _stored(1, "old-expansion", "poi-a", "x", 1),
        _stored(2, "native-alert", "poi-a", "poi-b", 20),
        _stored(3, "other-expansion", "poi-b", "y", 10),
    )

    proxies, audit = select_poi_proxies(
        edges,
        {"poi-a", "poi-b"},
        layer_priority=(frozenset({"native-alert"}), frozenset({"old-expansion"})),
    )

    assert proxies == frozenset({"native-alert"})
    assert audit["poi_to_proxy_event"] == {
        "poi-a": "native-alert",
        "poi-b": "native-alert",
    }
    assert audit["policy"] == "KAIROS-layer-priority,then-time,then-event-id"


def test_proxy_selection_can_report_detector_pois_outside_a_capped_candidate():
    from tc_pruning.kairos_poi_experiment import select_poi_proxies

    proxies, audit = select_poi_proxies(
        (_stored(1, "present-event", "present-poi", "x", 1),),
        {"present-poi", "capped-out-poi"},
        require_all=False,
    )

    assert proxies == frozenset({"present-event"})
    assert audit["active_poi_node_ids"] == ["present-poi"]
    assert audit["missing_poi_node_ids"] == ["capped-out-poi"]
    assert audit["poi_candidate_coverage"] == 0.5


def test_two_selectors_receive_identical_k6_envelope_and_hard_budget(
    tmp_path, monkeypatch
):
    from tc_pruning.kairos_poi_experiment import run_selectors
    from tc_pruning.frequency import FrequencyModel

    def full_scan_is_forbidden(*_args, **_kwargs):
        raise AssertionError("experiment must reuse the verified frequency cache")

    monkeypatch.setattr(
        "tc_pruning.detector_seed_benchmark.FrequencyModel.from_store",
        full_scan_is_forbidden,
    )

    database = tmp_path / "fixture.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            (
                NodeRecord("p0", "process", "p0"),
                NodeRecord("p1", "process", "p1"),
                NodeRecord("f0", "file", "f0"),
                NodeRecord("f1", "file", "f1"),
                EdgeRecord("e0", "p0", "f0", "EVENT_WRITE", 1, "h"),
                EdgeRecord("e1", "f0", "p1", "EVENT_READ", 2, "h"),
                EdgeRecord("e2", "p1", "f1", "EVENT_WRITE", 3, "h"),
            )
        )
        edges = tuple(store.get_edge_by_event_id(name) for name in ("e0", "e1", "e2"))
        result = run_selectors(
            store=store,
            edges=edges,
            poi_node_ids={"p1"},
            raw_event_cap=2,
            projection=EdgeProjection("DEPIMPACT_COMPATIBLE", 900_000_000_000),
            layer_priority=(frozenset({"e1"}),),
            frequency_model=FrequencyModel(
                {"process": 2, "file": 2},
                {"EVENT_WRITE": 2, "EVENT_READ": 1},
                {
                    ("process", "EVENT_WRITE", "file"): 2,
                    ("file", "EVENT_READ", "process"): 1,
                },
            ),
        )

    assert result["proxy_event_ids"] == ["e1"]
    assert result["A_rasp"]["input_event_ids_sha256"] == result["C_branch_fair"]["input_event_ids_sha256"]
    assert result["A_rasp"]["raw_events"] <= 2
    assert result["C_branch_fair"]["raw_events"] <= 2
    assert "e1" in result["A_rasp"]["selected_raw_event_ids"]
    assert "e1" in result["C_branch_fair"]["selected_raw_event_ids"]


def test_full_comparison_seals_three_scenarios_and_marks_oracle_poi_policy(tmp_path):
    from tc_pruning.kairos_poi_experiment import run_kairos_k6_poi_comparison

    database = tmp_path / "fixture.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            (
                NodeRecord("p0", "process", "p0"),
                NodeRecord("p1", "process", "p1"),
                NodeRecord("f0", "file", "f0"),
                EdgeRecord("e0", "p0", "f0", "EVENT_WRITE", 1, "h"),
                EdgeRecord("e1", "f0", "p1", "EVENT_READ", 2, "h"),
            )
        )
        from tc_pruning.frequency_cache import FrequencyCache

        FrequencyCache(store).build()

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    scenarios = []
    for scenario in ("06", "12", "13"):
        online = tmp_path / f"kairos-{scenario}.json"
        online.write_text(
            json.dumps(
                {
                    "scenario": scenario,
                    "track": "B",
                    "kairos_ablations": {
                        "K1": {"event_ids": ["e1"]},
                        "K6": {"event_ids": ["e1"]},
                    },
                }
            ),
            encoding="utf-8",
        )
        truth = tmp_path / f"node_Nginx_Backdoor_{scenario}.csv"
        truth.write_text(
            "p0,{'subject': 'fixture entry'},1\n"
            "p1,{'subject': 'fixture poi'},2\n",
            encoding="utf-8",
        )
        scenarios.append(
            {
                "scenario": scenario,
                "kairos_online": str(online),
                "kairos_sha256": sha(online),
                "orthrus_csv": str(truth),
                "orthrus_sha256": sha(truth),
            }
        )
    config = {
        "schema_version": "kairos-k6-poi-context-comparison-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "database": {"path": str(database), "sha256": sha(database)},
        "projection": {
            "mode": "DEPIMPACT_COMPATIBLE",
            "merge_window_ns": 900_000_000_000,
        },
        "candidate": {
            "candidate_cap": 10,
            "history_start_ns": 0,
            "cutoff_ns": 10,
            "max_strict_depth": 3,
            "max_control_depth": 0,
            "enable_common_cause": False,
            "scan_multiplier": 2
        },
        "raw_event_cap": 2,
        "scenarios": scenarios,
    }

    result = run_kairos_k6_poi_comparison(config, tmp_path / "evaluation.json")

    assert result["status"] == "COMPLETED"
    assert len(result["scenarios"]) == 3
    assert result["aggregate"]["scenario_annotation_count"] == 6
    assert result["aggregate"]["unique_attack_nodes"] == 2
    assert result["aggregate"]["A_rasp"]["reference_subgraph_nodes"] == 6
    assert result["aggregate"]["A_rasp"]["node_tpr"] == 0.5
    assert result["aggregate"]["common_candidate"]["raw_events"] == 6
    assert result["scenarios"][0]["A_rasp"]["evaluation"]["path_families"]["backward_path"]["eligible_paths"] == 1
    assert result["aggregate"]["A_rasp"]["time_path"]["by_time_interval"]["<=1m"]["eligible_paths"] == 3
    assert result["aggregate"]["A_rasp"]["time_path"]["by_path_length"]["1-2"]["eligible_paths"] == 3
    assert result["aggregate"]["A_rasp"]["anomaly_time"]["<=1m|1-2"]["eligible_paths"] == 3
    assert "oracle-assisted" in result["poi_policy"]
    assert len(result["content_sha256"]) == 64
