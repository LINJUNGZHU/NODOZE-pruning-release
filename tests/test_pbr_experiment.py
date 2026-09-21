from __future__ import annotations

from tc_pruning.benchmark_contract import EdgeProjection
from tc_pruning.models import StoredEdge


def e(number, event, src, dst, time, relation="EVENT_WRITE",
      src_type="process", dst_type="file"):
    return StoredEdge(number, event, src, dst, relation, time, "h", src_type, dst_type)


def read(number, event, src, dst, time):
    return e(number, event, src, dst, time, "EVENT_READ", "file", "process")


def test_branch_trajectory_reports_actual_projected_size_not_requested_target():
    from tc_pruning.pbr_experiment import branch_fair_checkpoints

    edges = (
        read(0, "proxy", "seed", "p1", 0),
        e(1, "a", "p1", "same", 1),
        e(2, "b", "p1", "same", 2),
        e(3, "c", "p1", "other", 3),
    )
    points = branch_fair_checkpoints(
        edges=edges,
        mandatory=frozenset({"proxy"}),
        provenance={},
        projection=EdgeProjection("DEPIMPACT_COMPATIBLE", 10),
        projected_targets=(3,),
        maximum_raw_budget=4,
    )
    assert points[0]["target_projected_edges"] == 3
    assert points[0]["actual_projected_edges"] == 3
    assert points[0]["actual_raw_events"] == 4
    assert len(points[0]["decision_sha256"]) == 64


def test_pbr_sweep_zero_checkpoint_is_legacy_exact_and_truth_file_cannot_change_online_hash(tmp_path):
    from tc_pruning.pbr_experiment import pbr_sweep

    candidate = (
        read(0, "proxy", "seed", "p1", 0),
        e(1, "a", "p1", "x", 1),
        read(2, "b", "x", "p2", 2),
    )
    truth = tmp_path / "truth.csv"
    truth.write_text("first", encoding="utf-8")
    first = pbr_sweep(
        candidate_edges=candidate,
        base_selected_event_ids=frozenset({"proxy"}),
        poi_node_ids=frozenset({"p1", "p2"}),
        mandatory_event_ids=frozenset({"proxy"}),
        projection=EdgeProjection("RAW_EVENT", 10),
        branch_provenance={}, relevance={}, rarity={}, allowances=(0.0, 1.0),
        fixed_extra_raw=10,
    )
    truth.write_text("completely different labels", encoding="utf-8")
    second = pbr_sweep(
        candidate_edges=candidate,
        base_selected_event_ids=frozenset({"proxy"}),
        poi_node_ids=frozenset({"p1", "p2"}),
        mandatory_event_ids=frozenset({"proxy"}),
        projection=EdgeProjection("RAW_EVENT", 10),
        branch_provenance={}, relevance={}, rarity={}, allowances=(0.0, 1.0),
        fixed_extra_raw=10,
    )
    assert first[0]["selected_raw_event_ids"] == ["proxy"]
    assert first[0]["decision_sha256"] == second[0]["decision_sha256"]
    assert first[1]["bridge_demands"] == second[1]["bridge_demands"]
    assert first[1]["bundles"] == second[1]["bundles"]


def test_non_poi_recall_excludes_hard_protected_poi_nodes():
    from tc_pruning.orthrus_groundtruth import evaluate_poi_scoped_retention

    rows = [
        {"edge_id": 1, "event_id": "a", "src": "p1", "dst": "x", "relation": "EVENT_WRITE", "timestamp_ns": 1},
        {"edge_id": 2, "event_id": "b", "src": "x", "dst": "attack", "relation": "EVENT_READ", "timestamp_ns": 2},
    ]
    result = evaluate_poi_scoped_retention(
        candidate_edges=rows,
        selected_event_ids={"a"},
        groundtruth_node_ids={"p1", "attack"},
        poi_node_ids={"p1"},
    )
    assert result["contexts_aligned"]["node_tpr"] == 0.5
    assert result["contexts_aligned"]["non_poi_node_recall"] == 0.0


def test_a_rasp_evidence_sidecar_exposes_normalized_relevance_and_rarity_without_changing_selector():
    from tc_pruning.frequency import FrequencyModel
    from tc_pruning.pbr_experiment import a_rasp_evidence

    candidate = (
        read(0, "proxy", "seed", "p1", 0),
        e(1, "a", "p1", "x", 1),
    )
    frequency = FrequencyModel(
        {"file": 2, "process": 2},
        {"EVENT_READ": 1, "EVENT_WRITE": 1},
        {("file", "EVENT_READ", "process"): 1,
         ("process", "EVENT_WRITE", "file"): 1},
    )
    sidecar = a_rasp_evidence(candidate, frozenset({"proxy"}), frequency)
    assert set(sidecar) == {"proxy", "a"}
    assert sidecar["proxy"]["path_score"] == 1.0
    assert all(0.0 <= row["rarity"] <= 1.0 for row in sidecar.values())
    assert all(0.0 <= row["ppr"] <= 1.0 for row in sidecar.values())
