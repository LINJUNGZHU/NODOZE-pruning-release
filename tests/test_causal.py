from tc_pruning.causal import (
    CausalSearchConfig,
    build_alert_context,
    build_cumulative_forward_contexts,
)
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.nodoze import NODOZEFrequencyModel
from tc_pruning.store import ProvenanceStore


def _nodes(*names):
    return [NodeRecord(name, "process", name, "h") for name in names]


def _search_config(**overrides):
    values = {
        "min_edge_suspicion": 0.0,
        "min_path_suspicion": 0.0,
        "suspicion_momentum": 0.8,
        "branch_suspicion_quantile": 0.0,
        "resource_max_edges": None,
        "resource_max_states": None,
    }
    values.update(overrides)
    return CausalSearchConfig(**values)


def test_alert_context_follows_direction_and_monotonic_time(tmp_path):
    observations = _nodes("x", "a", "b", "c", "y", "z") + [
        EdgeRecord("pre", "x", "a", "R", 5, "h"),
        EdgeRecord("alert", "a", "b", "R", 10, "h"),
        EdgeRecord("post", "b", "c", "R", 12, "h"),
        EdgeRecord("future-incoming", "y", "a", "R", 11, "h"),
        EdgeRecord("past-outgoing", "b", "z", "R", 9, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        model = NODOZEFrequencyModel.from_store(store)
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "pre",
        "alert",
        "post",
    }
    assert [edge.event_id for edge in context.paths[0]] == [
        "pre",
        "alert",
        "post",
    ]
    assert context.seed_uuids == {"a", "b"}


def test_read_like_poi_traces_the_subject_history_not_the_socket_history(tmp_path):
    observations = _nodes("ancestor", "socket", "process") + [
        EdgeRecord("subject-history", "ancestor", "process", "EVENT_FORK", 5, "h"),
        EdgeRecord("poi", "socket", "process", "EVENT_RECVFROM", 10, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["poi"],
            NODOZEFrequencyModel.from_store(store),
            _search_config(expansion_direction="backward"),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "subject-history",
        "poi",
    }


def test_poi_search_honors_backward_only_expansion_direction(tmp_path):
    observations = _nodes("ancestor", "process", "socket", "later") + [
        EdgeRecord("history", "ancestor", "process", "EVENT_FORK", 5, "h"),
        EdgeRecord("poi", "process", "socket", "EVENT_SENDTO", 10, "h"),
        EdgeRecord("future", "socket", "later", "EVENT_WRITE", 15, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["poi"],
            NODOZEFrequencyModel.from_store(store),
            _search_config(expansion_direction="backward"),
        )

    assert {edge.event_id for edge in context.graph.edges} == {"history", "poi"}


def test_send_poi_forward_search_follows_later_process_activity(tmp_path):
    observations = _nodes("process", "socket", "file") + [
        EdgeRecord("poi", "process", "socket", "EVENT_SENDTO", 10, "h"),
        EdgeRecord("future", "process", "file", "EVENT_WRITE", 20, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["poi"],
            NODOZEFrequencyModel.from_store(store),
            _search_config(expansion_direction="both"),
        )

    assert "future" in {edge.event_id for edge in context.graph.edges}


def test_per_node_limit_prefers_nodoze_rare_edge(tmp_path):
    observations = _nodes("a", "b", "normal", "rare") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("normal-edge", "b", "normal", "R", 11, "h"),
        EdgeRecord("rare-edge", "b", "rare", "R", 12, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        model = NODOZEFrequencyModel(
            exact_counts={
                ("process:b", "process:normal", "R"): 10,
                ("process:b", "process:rare", "R"): 1,
            },
            source_relation_counts={("process:b", "R"): 10},
            total_days=1,
        )
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(
                min_edge_suspicion=0.5,
                min_path_suspicion=0.5,
            ),
        )

    event_ids = {edge.event_id for edge in context.graph.edges}
    assert "rare-edge" in event_ids
    assert "normal-edge" not in event_ids


def test_candidate_graph_has_no_path_count_cutoff(tmp_path):
    branch_nodes = [f"tail-{index}" for index in range(75)]
    observations = _nodes("a", "b", *branch_nodes) + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        *[
            EdgeRecord(f"branch-{index}", "b", node, "R", 11 + index, "h")
            for index, node in enumerate(branch_nodes)
        ],
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        model = NODOZEFrequencyModel.from_store(store)
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(),
        )

    assert len(context.graph.edges) == 76
    assert len(context.paths) == 75
    assert context.truncated_path_count == 0
    assert "path_safety_limit" not in context.termination_reasons


def test_combined_backward_forward_path_drops_cross_half_cycles(tmp_path):
    observations = _nodes("x", "a", "b", "c") + [
        EdgeRecord("pre", "x", "a", "R", 5, "h"),
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("cycle", "b", "x", "R", 12, "h"),
        EdgeRecord("valid", "b", "c", "R", 13, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            NODOZEFrequencyModel.from_store(store),
            _search_config(),
        )

    event_paths = [[edge.event_id for edge in path] for path in context.paths]
    assert event_paths == [["pre", "alert", "valid"]]


def test_suspicious_path_is_not_cut_by_old_hop_or_48_hour_limits(tmp_path):
    day = 86_400_000_000_000
    names = ["a", "b", *(f"n{index}" for index in range(9))]
    observations = _nodes(*names) + [
        EdgeRecord("alert", "a", "b", "ALERT", day, "h")
    ]
    previous = "b"
    for index in range(9):
        current = f"n{index}"
        observations.append(
            EdgeRecord(
                f"stage-{index}", previous, current, "RARE", (index + 2) * day, "h"
            )
        )
        previous = current

    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            NODOZEFrequencyModel({}, {}, 1),
            _search_config(
                min_edge_suspicion=0.8,
                min_path_suspicion=0.8,
            ),
        )

    assert [edge.event_id for edge in context.paths[0]] == [
        "alert",
        *(f"stage-{index}" for index in range(9)),
    ]
    assert context.complete_path_count == 1
    assert context.truncated_path_count == 0


def test_low_suspicion_branch_stops_while_rare_branch_reaches_tail(tmp_path):
    observations = _nodes("a", "b", "rare", "normal") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("rare-edge", "b", "rare", "R", 11, "h"),
        EdgeRecord("normal-edge", "b", "normal", "R", 12, "h"),
    ]
    model = NODOZEFrequencyModel(
        exact_counts={("process:b", "process:normal", "R"): 10},
        source_relation_counts={("process:b", "R"): 10},
        total_days=1,
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(
                min_edge_suspicion=0.6,
                min_path_suspicion=0.6,
            ),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "alert",
        "rare-edge",
    }
    assert context.termination_reasons["natural_tail"] == 1


def test_soft_priority_keeps_low_suspicion_causal_dependency(tmp_path):
    observations = _nodes("a", "b", "normal") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("normal-edge", "b", "normal", "R", 11, "h"),
    ]
    model = NODOZEFrequencyModel(
        exact_counts={("process:b", "process:normal", "R"): 10},
        source_relation_counts={("process:b", "R"): 10},
        total_days=1,
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(
                eligibility_mode="soft_priority",
                min_edge_suspicion=0.9,
                min_path_suspicion=0.9,
                min_frontier_relevance=0.9,
            ),
        )

    assert "normal-edge" in {edge.event_id for edge in context.graph.edges}


def test_safety_limited_branch_is_not_reported_as_complete(tmp_path):
    observations = _nodes("a", "b", "c", "d") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("one", "b", "c", "RARE", 11, "h"),
        EdgeRecord("two", "c", "d", "RARE", 12, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            NODOZEFrequencyModel({}, {}, 1),
            _search_config(resource_max_states=1),
        )

    assert context.paths == []
    assert context.complete_path_count == 0
    assert context.truncated_path_count > 0
    assert context.termination_reasons["state_resource_limit"] > 0


def test_high_degree_quantile_prioritizes_without_deleting_valid_edges(tmp_path):
    observations = _nodes("a", "b", "best", "middle", "low") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("best-edge", "b", "best", "R", 11, "h"),
        EdgeRecord("middle-edge", "b", "middle", "R", 12, "h"),
        EdgeRecord("low-edge", "b", "low", "R", 13, "h"),
    ]
    model = NODOZEFrequencyModel(
        exact_counts={
            ("process:b", "process:best", "R"): 1,
            ("process:b", "process:middle", "R"): 2,
            ("process:b", "process:low", "R"): 3,
        },
        source_relation_counts={("process:b", "R"): 10},
        total_days=1,
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            model,
            _search_config(branch_suspicion_quantile=0.8),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "alert", "best-edge", "middle-edge", "low-edge"
    }


def test_repeated_dependency_instances_stay_as_evidence_but_only_nearest_expands(tmp_path):
    observations = _nodes("a", "b", "c") + [
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("nearest", "b", "c", "R", 11, "h"),
        EdgeRecord("duplicate-later", "b", "c", "R", 20, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store,
            ["alert"],
            NODOZEFrequencyModel({}, {}, 1),
            _search_config(),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "alert",
        "nearest",
        "duplicate-later",
    }
    assert [edge.event_id for edge in context.paths[0]] == ["alert", "nearest"]


def test_adaptive_window_expands_only_from_relevant_boundary(tmp_path):
    minute = 60_000_000_000
    observations = _nodes("a", "b", "near", "far") + [
        EdgeRecord("alert", "a", "b", "ALERT", 0, "h"),
        EdgeRecord("near-edge", "b", "near", "R", 14 * minute, "h"),
        EdgeRecord("far-edge", "b", "far", "R", 20 * minute, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1),
            _search_config(initial_window_seconds=15 * 60,
                           window_growth_factor=2.0,
                           window_boundary_fraction=0.1),
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "alert", "near-edge", "far-edge"
    }
    assert context.termination_reasons["adaptive_window_expansion"] >= 1


def test_priority_queue_expands_temporally_closer_equal_rarity_branch_first(tmp_path):
    minute = 60_000_000_000
    observations = _nodes("a", "b", "near", "far", "near-tail", "far-tail") + [
        EdgeRecord("alert", "a", "b", "ALERT", 0, "h"),
        EdgeRecord("near", "b", "near", "R", minute, "h"),
        EdgeRecord("far", "b", "far", "R", 2 * minute, "h"),
        EdgeRecord("near-tail", "near", "near-tail", "R", 3 * minute, "h"),
        EdgeRecord("far-tail", "far", "far-tail", "R", 4 * minute, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1),
            _search_config(resource_max_states=2),
        )

    event_ids = {edge.event_id for edge in context.graph.edges}
    assert "near-tail" in event_ids
    assert "far-tail" not in event_ids


def test_high_frequency_entity_reports_time_partitioning(tmp_path):
    minute = 60_000_000_000
    observations = _nodes("a", "b", "x", "y") + [
        EdgeRecord("alert", "a", "b", "ALERT", 0, "h"),
        EdgeRecord("early", "b", "x", "R", minute, "h"),
        EdgeRecord("late", "b", "y", "R", 3 * minute, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1),
            _search_config(high_frequency_degree=2,
                           high_frequency_partition_seconds=60),
        )

    assert context.termination_reasons["high_frequency_time_partitions"] == 2


def test_frontier_relevance_is_normal_termination_not_truncation(tmp_path):
    observations = _nodes("a", "b", "c") + [
        EdgeRecord("alert", "a", "b", "ALERT", 0, "h"),
        EdgeRecord("weak", "b", "c", "R", 1, "h"),
    ]
    model = NODOZEFrequencyModel(
        exact_counts={("process:b", "process:c", "R"): 1},
        source_relation_counts={("process:b", "R"): 2}, total_days=1,
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], model,
            _search_config(min_frontier_relevance=0.95),
        )

    assert context.termination_reasons["frontier_below_relevance"] == 1
    assert context.truncated_path_count == 0


def test_backward_search_revisits_entity_at_earlier_time_state(tmp_path):
    observations = _nodes("process", "socket", "sink") + [
        EdgeRecord("recv-old", "socket", "process", "RECV", 10, "h"),
        EdgeRecord("send-middle", "process", "socket", "SEND", 20, "h"),
        EdgeRecord("recv-new", "socket", "process", "RECV", 30, "h"),
        EdgeRecord("alert", "process", "sink", "WRITE", 40, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1), _search_config()
        )

    assert {edge.event_id for edge in context.graph.edges} == {
        "recv-old", "send-middle", "recv-new", "alert"
    }


def test_ancestral_cone_recovers_sibling_process_branch(tmp_path):
    observations = _nodes("root", "parent", "poi-process", "sibling", "sink") + [
        EdgeRecord("parent-created", "root", "parent", "EVENT_FORK", 1, "h"),
        EdgeRecord("poi-created", "parent", "poi-process", "EVENT_FORK", 2, "h"),
        EdgeRecord("sibling-created", "parent", "sibling", "EVENT_FORK", 3, "h"),
        EdgeRecord("sibling-action", "sibling", "sink", "EVENT_WRITE", 4, "h"),
        EdgeRecord("alert", "poi-process", "sink", "EVENT_WRITE", 10, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1),
            _search_config(expansion_direction="backward", topology="ancestral_cone"),
        )

    assert "sibling-created" in {edge.event_id for edge in context.graph.edges}
    assert "sibling-action" in {edge.event_id for edge in context.graph.edges}


def test_branch_quantile_prioritizes_but_does_not_hard_filter_causal_edge(tmp_path):
    observations = _nodes("entry", "noise", "process", "sink") + [
        EdgeRecord("causal", "entry", "process", "ACCEPT", 9, "h"),
        EdgeRecord("rarer", "noise", "process", "ODD", 9, "h"),
        EdgeRecord("alert", "process", "sink", "SEND", 10, "h"),
    ]
    model = NODOZEFrequencyModel(
        exact_counts={("process:entry", "process:process", "ACCEPT"): 1},
        source_relation_counts={("process:entry", "ACCEPT"): 4}, total_days=1,
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], model,
            _search_config(branch_suspicion_quantile=0.9),
        )

    assert "causal" in {edge.event_id for edge in context.graph.edges}


def test_seed_parallel_dependency_events_are_preserved(tmp_path):
    observations = _nodes("a", "b") + [
        EdgeRecord("parallel", "a", "b", "SEND", 10, "h"),
        EdgeRecord("alert", "a", "b", "SEND", 10, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        context = build_alert_context(
            store, ["alert"], NODOZEFrequencyModel({}, {}, 1), _search_config()
        )

    assert {edge.event_id for edge in context.graph.edges} == {"alert", "parallel"}


def test_kairos_alerts_are_processed_in_time_order_and_update_cumulative_graph(tmp_path):
    observations = _nodes("a", "b", "c", "d") + [
        EdgeRecord("early-alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("shared", "b", "c", "WRITE", 20, "h"),
        EdgeRecord("late-alert", "b", "c", "ALERT", 30, "h"),
        EdgeRecord("late-tail", "c", "d", "SEND", 40, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        result = build_cumulative_forward_contexts(
            store,
            [("late", {"late-alert"}), ("early", {"early-alert"})],
            NODOZEFrequencyModel.from_store(store),
            _search_config(min_frontier_relevance=0.0),
        )

    assert [step.group_id for step in result.steps] == ["early", "late"]
    assert result.steps[0].new_event_count == 4
    assert result.steps[1].new_event_count == 0
    assert result.steps[1].overlap_event_count == 2
    assert {edge.event_id for edge in result.context.graph.edges} == {
        "early-alert", "shared", "late-alert", "late-tail"
    }
    assert result.context.backward_paths == []


def test_kairos_cumulative_forward_does_not_follow_pre_alert_edges(tmp_path):
    observations = _nodes("x", "a", "b", "c") + [
        EdgeRecord("before", "x", "a", "READ", 5, "h"),
        EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
        EdgeRecord("after", "b", "c", "WRITE", 11, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        result = build_cumulative_forward_contexts(
            store, [("window", {"alert"})],
            NODOZEFrequencyModel.from_store(store), _search_config(),
        )

    assert {edge.event_id for edge in result.context.graph.edges} == {
        "alert", "after"
    }
