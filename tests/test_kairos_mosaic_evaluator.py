from tc_pruning.investigation.mosaic_offline import evaluate_online_artifact


def test_offline_evaluator_separates_candidate_and_selection_false_negatives():
    online = {
        "scenario": "06",
        "retrieval_ablations": {
            "R4": {"event_ids": ["attack-1", "normal"]},
        },
        "selection_ablations": {
            "S5": {"event_ids": ["normal"]},
        },
    }
    result = evaluate_online_artifact(
        online,
        reference_event_ids={"attack-1", "attack-2"},
        reference_node_ids={"a", "b"},
        edge_endpoints={"attack-1": ("a", "x"), "normal": ("x", "y")},
    )
    assert result["candidate_edge_fn"] == 1
    assert result["selection_edge_fn"] == 1
    assert result["final_edge_fn"] == 2
    assert result["candidate_node_fn"] == 1
    assert result["final_node_fn"] == 2
    assert result["groundtruth_completeness"] == "PARTIAL_POSITIVE_GT"

