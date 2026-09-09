from tc_pruning.search_diagnostics import summarize_coverage_funnel


def test_coverage_funnel_separates_database_scope_search_and_pruning_losses():
    report = summarize_coverage_funnel(
        truth_ids={"a", "b", "c", "d"},
        database_ids={"a", "b", "c"},
        causal_scope_ids={"a", "b"},
        exhaustive_candidate_ids={"a", "b", "x"},
        current_candidate_ids={"a", "x"},
        pruned_ids={"a"},
    )

    assert report["groundtruth_manifest"]["count"] == 4
    assert report["database_match"]["count"] == 3
    assert report["independent_causal_scope"]["truth_count"] == 2
    assert report["exhaustive_diagnostic_search"]["truth_count"] == 2
    assert report["current_candidate_search"]["truth_count"] == 1
    assert report["pruned_output"]["truth_count"] == 1
    assert report["losses"]["not_in_database"] == ["d"]
    assert report["losses"]["outside_poi_causal_scope"] == ["c"]
    assert report["losses"]["lost_by_current_search"] == ["b"]
