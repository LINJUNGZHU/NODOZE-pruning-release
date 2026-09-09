from tc_pruning.diffusion import DiffusionResult, diffuse_importance
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.pruning import adaptive_prune


def _edge(
    edge_id, event_id, src, dst, relation="COMMON", timestamp_ns=None
):
    return StoredEdge(
        edge_id=edge_id,
        event_id=event_id,
        src=src,
        dst=dst,
        relation=relation,
        timestamp_ns=edge_id if timestamp_ns is None else timestamp_ns,
        host="h",
        src_type="process",
        dst_type="process",
    )


def test_diffusion_reaches_multiple_hops_and_normalizes_scores():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[_edge(1, "ab", "a", "b"), _edge(2, "bc", "b", "c")],
    )

    result = diffuse_importance(
        graph, {"a"}, {1: 0.0, 2: 0.0}, damping=0.85, tolerance=1e-12
    )

    assert result.scores["b"] > 0
    assert result.scores["c"] > 0
    assert result.scores["c"] < result.scores["b"]
    assert sum(result.scores.values()) == pytest.approx(1.0)
    assert result.predecessors["b"] == 1
    assert result.predecessors["c"] == 2


def test_default_diffusion_budget_converges_on_small_connected_graph():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "ab", "a", "b"),
            _edge(2, "bc", "b", "c"),
            _edge(3, "cd", "c", "d"),
        ],
    )

    result = diffuse_importance(graph, {"a"}, {1: 0.0, 2: 0.5, 3: 1.0})

    assert result.converged is True


def test_diffusion_uses_depimpact_affinity_to_favor_common_causal_bridge():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "common-bridge", "a", "b"),
            _edge(2, "poi-side", "b", "c"),
            _edge(3, "rare-distractor", "a", "d"),
        ],
    )

    result = diffuse_importance(
        graph,
        {"a"},
        {1: 0.0, 2: 0.0, 3: 1.0},
        edge_affinity={1: 1.0, 2: 1.0, 3: 0.0},
        damping=0.85,
    )

    assert result.scores["b"] > result.scores["d"]


def test_pruning_does_not_add_remote_bridge_beyond_raw_event_budget():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcxde"},
        edges=[
            _edge(1, "ab", "a", "b"),
            _edge(2, "bc", "b", "c"),
            _edge(3, "cx", "c", "x", "RARE"),
            _edge(4, "bd", "b", "d"),
            _edge(5, "be", "b", "e"),
        ],
    )
    rarity = {1: 0.0, 2: 0.0, 3: 1.0, 4: 0.0, 5: 0.0}
    diffusion = diffuse_importance(graph, {"a"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"a"},
        keep_ratio=0.2,
        rarity_weight=0.8,
    )

    kept = {edge.event_id for edge in result.kept_edges}
    assert kept == {"ab"}
    assert result.actual_keep_ratio <= 0.2
    assert len(result.kept_edges) < len(graph.edges)
    assert result.edge_scores[3] > result.edge_scores[4]


def test_pruning_validates_keep_ratio():
    graph = Neighborhood()
    diffusion = diffuse_importance(graph, set(), {})

    with pytest.raises(ValueError, match="keep_ratio"):
        adaptive_prune(graph, {}, diffusion, seeds=set(), keep_ratio=0.0)


def test_pruning_keeps_edge_with_high_nodoze_path_importance():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "alert", "a", "b"),
            _edge(2, "attack-path", "b", "c"),
            _edge(3, "benign", "b", "d"),
        ],
    )
    rarity = {1: 0.0, 2: 0.0, 3: 0.0}
    diffusion = diffuse_importance(graph, {"a", "b"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"a", "b"},
        keep_ratio=0.2,
        rarity_weight=0.1,
        path_importance={2: 1.0},
        path_weight=0.8,
        protected_edge_ids={1},
    )

    kept = {edge.event_id for edge in result.kept_edges}
    assert "attack-path" in kept
    assert result.edge_scores[2] > result.edge_scores[3]


def test_protected_poi_consumes_budget_before_depimpact_edge():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "poi", "a", "b"),
            _edge(2, "common-attack", "b", "c"),
            _edge(3, "common-benign", "b", "d"),
        ],
    )
    rarity = {1: 0.0, 2: 0.0, 3: 0.0}
    diffusion = diffuse_importance(graph, {"b"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"b"},
        keep_ratio=0.2,
        rarity_weight=0.0,
        impact_importance={1: 0.5, 2: 1.0, 3: 0.0},
        impact_weight=0.9,
        protected_edge_ids={1},
        protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {"poi"}
    assert len(result.kept_edges) <= result.budget_edges
    assert result.edge_score_components[2]["depimpact"] == pytest.approx(1.0)


def test_adaptive_pruning_selects_high_score_side_of_largest_gap():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdefgh"},
        edges=[
            _edge(1, "high-1", "a", "b"),
            _edge(2, "high-2", "c", "d"),
            _edge(3, "low-1", "e", "f"),
            _edge(4, "low-2", "g", "h"),
        ],
    )
    rarity = {1: 1.0, 2: 0.9, 3: 0.1, 4: 0.09}
    diffusion = diffuse_importance(graph, set(), rarity, damping=0.0)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds=set(),
        keep_ratio=0.5,
        rarity_weight=1.0,
        selection_mode="adaptive",
    )

    assert {edge.event_id for edge in result.kept_edges} == {"high-1", "high-2"}
    assert result.selection_mode == "adaptive"


def test_event_seed_mode_does_not_keep_every_edge_incident_to_a_busy_seed():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcde"},
        edges=[
            _edge(1, "high", "a", "b"),
            _edge(2, "low-1", "a", "c"),
            _edge(3, "low-2", "a", "d"),
            _edge(4, "low-3", "a", "e"),
        ],
    )
    rarity = {1: 1.0, 2: 0.0, 3: 0.0, 4: 0.0}
    diffusion = diffuse_importance(graph, {"a"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"a"},
        keep_ratio=0.25,
        rarity_weight=1.0,
        protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {"high"}


def test_adaptive_mode_never_undercuts_requested_minimum_budget():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdefgh"},
        edges=[
            _edge(1, "outlier", "a", "b"),
            _edge(2, "middle", "c", "d"),
            _edge(3, "low-1", "e", "f"),
            _edge(4, "low-2", "g", "h"),
        ],
    )
    rarity = {1: 1.0, 2: 0.2, 3: 0.1, 4: 0.09}
    diffusion = diffuse_importance(graph, set(), rarity, damping=0.0)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds=set(),
        keep_ratio=0.5,
        rarity_weight=1.0,
        selection_mode="adaptive",
    )

    assert len(result.kept_edges) == 2


def test_pruning_never_splits_a_depimpact_merged_event_group():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "transfer-part-1", "a", "b"),
            _edge(2, "transfer-part-2", "a", "b"),
            _edge(3, "transfer-part-3", "a", "b"),
            _edge(4, "distractor", "c", "d"),
        ],
    )
    rarity = {1: 1.0, 2: 1.0, 3: 1.0, 4: 0.0}
    diffusion = diffuse_importance(graph, {"b"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"b"},
        keep_ratio=0.25,
        rarity_weight=1.0,
        atomic_edge_groups={1: (1, 2, 3)},
        protect_seed_incident_edges=False,
    )

    kept_transfer = {
        edge.event_id for edge in result.kept_edges
        if edge.event_id.startswith("transfer-part")
    }
    assert kept_transfer in (set(), {
        "transfer-part-1", "transfer-part-2", "transfer-part-3"
    })
    assert len(result.kept_edges) <= 1


def test_protected_atomic_group_reports_infeasible_raw_event_budget():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[_edge(1, "poi-1", "a", "b"), _edge(2, "poi-2", "a", "b"),
               _edge(3, "other", "b", "c")],
    )
    rarity = {1: 1.0, 2: 1.0, 3: 0.0}
    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"b"}, rarity), seeds={"b"},
        keep_ratio=0.3, rarity_weight=1.0, protected_edge_ids={1},
        atomic_edge_groups={1: (1, 2)}, protect_seed_incident_edges=False,
    )

    assert result.budget_edges == 1
    assert result.minimum_required_edges == 2
    assert result.budget_feasible is False
    assert result.budget_overflow_edges == 1


def test_atomic_group_budget_curve_is_nested():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(8)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 7)],
    )
    rarity = {1: 1.0, 2: 1.0, 3: 1.0, 4: 0.8, 5: 0.7, 6: 0.6}
    diffusion = diffuse_importance(graph, set(), rarity, damping=0.0)
    outputs = []
    for ratio in (0.2, 0.5, 1.0):
        result = adaptive_prune(
            graph, rarity, diffusion, seeds=set(), keep_ratio=ratio,
            rarity_weight=1.0, atomic_edge_groups={1: (1, 2, 3)},
            protect_seed_incident_edges=False,
        )
        outputs.append({edge.edge_id for edge in result.kept_edges})

    assert outputs[0] <= outputs[1] <= outputs[2]


def test_connectivity_protection_restores_directed_low_cost_bridge_to_poi():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcxyz"},
        edges=[
            _edge(1, "entry", "a", "b"),
            _edge(2, "common-bridge", "b", "c"),
            _edge(3, "poi", "c", "z"),
            _edge(4, "rare-dead-end", "x", "y"),
        ],
    )
    rarity = {1: 1.0, 2: 0.0, 3: 1.0, 4: 0.9}
    diffusion = diffuse_importance(graph, {"z"}, rarity)

    result = adaptive_prune(
        graph,
        rarity,
        diffusion,
        seeds={"z"},
        keep_ratio=0.75,
        rarity_weight=1.0,
        protected_edge_ids={3},
        connectivity_target_edge_ids={3},
        protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} >= {
        "entry", "common-bridge", "poi"
    }
    assert result.connectivity_added_edges == 1


def test_connectivity_protection_rejects_bridge_that_precedes_selected_core():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdxy"},
        edges=[
            _edge(8, "core", "a", "b", timestamp_ns=8),
            _edge(5, "too-early-bridge", "b", "c", timestamp_ns=5),
            _edge(10, "poi", "c", "d", timestamp_ns=10),
            _edge(20, "noise", "x", "y", timestamp_ns=20),
        ],
    )
    rarity = {8: 1.0, 5: 0.0, 10: 0.0, 20: 0.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"d"}, rarity), seeds={"d"},
        keep_ratio=0.5, rarity_weight=1.0, protected_edge_ids={10},
        connectivity_target_edge_ids={10}, protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {"core", "poi"}
    assert result.connectivity_added_edges == 0


def test_connectivity_ignores_target_edge_from_another_poi_graph():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[_edge(1, "entry", "a", "b"), _edge(2, "poi", "b", "c")],
    )
    rarity = {1: 1.0, 2: 1.0}
    diffusion = diffuse_importance(graph, {"c"}, rarity)

    result = adaptive_prune(
        graph, rarity, diffusion, seeds={"c"}, keep_ratio=0.5,
        rarity_weight=1.0, connectivity_target_edge_ids={2, 999999},
        protect_seed_incident_edges=False,
    )

    assert {edge.edge_id for edge in result.kept_edges} <= {1, 2}


def test_connectivity_shortest_path_plan_is_not_recomputed_per_ranked_group(monkeypatch):
    import tc_pruning.pruning as pruning

    graph = Neighborhood(
        nodes={
            **{f"n{index}": NodeRecord(f"n{index}", "process", f"n{index}")
               for index in range(1, 30)},
            "target": NodeRecord("target", "process", "target"),
            "poi": NodeRecord("poi", "process", "poi"),
        },
        edges=[_edge(index, f"e{index}", f"n{index}", "target")
               for index in range(1, 30)]
        + [_edge(30, "e30", "target", "poi")],
    )
    diffusion = DiffusionResult(
        scores={**{f"n{index}": 1.0 for index in range(1, 30)},
                "target": 1.0, "poi": 1.0},
        predecessors={}, iterations=1, converged=True, diagnostics=[],
    )
    original = pruning._directed_connectivity_backbone
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(pruning, "_directed_connectivity_backbone", counted)
    adaptive_prune(
        graph, {edge.edge_id: 1.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=0.8, rarity_weight=1.0,
        connectivity_target_edge_ids={30},
    )

    assert calls <= 1


def test_diffusion_reports_multihop_iteration_diagnostics():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "ab", "a", "b"),
            _edge(2, "bc", "b", "c"),
            _edge(3, "cd", "c", "d"),
        ],
    )

    result = diffuse_importance(graph, {"a"}, {1: 0.0, 2: 0.0, 3: 0.0})

    assert result.diagnostics
    assert result.diagnostics[0]["nonzero_nodes"] >= 2
    assert max(row["max_reached_hop"] for row in result.diagnostics) == 3
    assert result.diagnostics[-1]["sum_score"] == pytest.approx(1.0)
    assert result.diagnostics[-1]["max_delta"] >= 0.0


def test_time_respecting_bidirectional_diffusion_rejects_time_reversed_edges():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "pxyzwq"},
        edges=[
            _edge(10, "poi", "p", "x", "EVENT_CONNECT"),
            _edge(5, "valid-history", "y", "p"),
            _edge(15, "future-arrival", "w", "p"),
            _edge(12, "valid-future", "p", "z"),
            _edge(8, "past-departure", "p", "q"),
        ],
    )

    result = diffuse_importance(
        graph,
        {"p"},
        {edge.edge_id: 0.0 for edge in graph.edges},
        mode="time_respecting_bidir",
        seed_edges=[graph.edges[0]],
    )

    assert result.mode == "time_respecting_bidir"
    assert result.edge_scores[10] == pytest.approx(1.0)
    assert result.edge_scores[5] > 0.0
    assert result.edge_scores[12] > 0.0
    assert result.edge_scores.get(15, 0.0) == 0.0
    assert result.edge_scores.get(8, 0.0) == 0.0


def test_temporal_diffusion_suppresses_busy_hub_fanout():
    distractors = [
        _edge(11 + index, f"noise-{index}", "h", f"n{index}")
        for index in range(25)
    ]
    graph = Neighborhood(
        nodes={
            name: NodeRecord(name, "process", name)
            for name in ["p", "h", "x", *(f"n{i}" for i in range(25))]
        },
        edges=[
            _edge(10, "poi", "h", "x", "EVENT_CONNECT"),
            _edge(9, "causal-history", "p", "h"),
            *distractors,
        ],
    )

    result = diffuse_importance(
        graph,
        {"h"},
        {edge.edge_id: 0.0 for edge in graph.edges},
        mode="time_respecting_bidir",
        seed_edges=[graph.edges[0]],
    )

    assert result.edge_scores[9] > result.edge_scores[11]


def test_pruning_prefers_edge_level_temporal_diffusion_over_equal_endpoints():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[_edge(1, "low", "a", "b"), _edge(2, "high", "c", "d")],
    )
    diffusion = DiffusionResult(
        scores={name: 1.0 for name in "abcd"},
        predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 0.1, 2: 0.9}, mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {1: 0.0, 2: 0.0}, diffusion, seeds=set(),
        keep_ratio=0.5, rarity_weight=0.0, protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {"high"}


def test_ordered_poi_stage_backbone_is_retained_even_when_budget_is_too_small():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdefgh"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "common-bridge", "b", "c"),
            _edge(3, "stage-2", "c", "d"),
            _edge(4, "rare-1", "e", "f"),
            _edge(5, "rare-2", "f", "g"),
            _edge(6, "rare-3", "g", "h"),
        ],
    )
    rarity = {1: 0.0, 2: 0.0, 3: 0.0, 4: 1.0, 5: 1.0, 6: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=0.25, rarity_weight=1.0,
        protected_edge_ids={1, 3}, ordered_connectivity_edge_ids=(1, 3),
        protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {
        "stage-1", "common-bridge", "stage-2"
    }
    assert result.stage_pairs == 1
    assert result.connected_stage_pairs == 1
    assert result.retained_stage_pairs == 1
    assert result.minimum_required_edges == 3
    assert result.budget_feasible is False
    assert result.budget_overflow_edges == 2


def test_ordered_poi_stage_metrics_report_disconnected_candidate_pair():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[_edge(1, "stage-1", "a", "b"), _edge(3, "stage-2", "c", "d")],
    )
    rarity = {1: 1.0, 3: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=1.0, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1, 3), protect_seed_incident_edges=False,
    )

    assert result.stage_pairs == 1
    assert result.connected_stage_pairs == 0
    assert result.retained_stage_pairs == 0


def test_ordered_stage_connectivity_understands_write_then_execute_information_flow():
    graph = Neighborhood(
        nodes={
            "writer": NodeRecord("writer", "process", "writer"),
            "payload": NodeRecord("payload", "file", "/tmp/payload"),
            "child": NodeRecord("child", "process", "payload"),
        },
        edges=[
            _edge(1, "write", "writer", "payload", "EVENT_WRITE"),
            _edge(2, "execute", "child", "payload", "EVENT_EXECUTE"),
        ],
    )
    rarity = {1: 1.0, 2: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"writer"}, rarity),
        seeds={"writer"}, keep_ratio=1.0, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1, 2), protect_seed_incident_edges=False,
    )

    assert result.connected_stage_pairs == 1
    assert result.retained_stage_pairs == 1


def test_ordered_stage_connectivity_accepts_consecutive_actions_by_same_process():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in ("p", "socket", "file")},
        edges=[
            _edge(1, "c2", "p", "socket", "EVENT_CONNECT"),
            _edge(2, "drop", "p", "file", "EVENT_WRITE"),
        ],
    )
    rarity = {1: 1.0, 2: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"p"}, rarity), seeds={"p"},
        keep_ratio=1.0, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1, 2), protect_seed_incident_edges=False,
    )

    assert result.connected_stage_pairs == 1


def test_certificate_reports_candidate_disconnected_pair_as_invalid():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "stage-2", "c", "d"),
        ],
    )
    rarity = {1: 1.0, 2: 1.0}

    result = adaptive_prune(
        graph,
        rarity,
        diffuse_importance(graph, {"a", "c"}, rarity),
        seeds={"a", "c"},
        keep_ratio=1.0,
        rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1, 2),
        certificate_poi_edge_ids={1, 2},
        protect_seed_incident_edges=False,
    )

    assert result.connected_stage_pairs == 0
    assert result.retained_stage_pairs == 0
    assert result.certificate_retained_poi_edges == 2
    assert result.path_certificate_valid is False
    assert result.path_certificate_status == "candidate_disconnected"
    assert result.strict_multistage_certificate_valid is False
    assert result.stage_path_witnesses == ()


def test_causal_path_cover_certifies_strict_chain_plus_independent_branch():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdef"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "bridge", "b", "c"),
            _edge(3, "stage-2", "c", "d"),
            _edge(4, "branch-poi", "e", "f"),
        ],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph,
        rarity,
        diffuse_importance(graph, {"a", "e"}, rarity),
        seeds={"a", "e"},
        keep_ratio=1.0,
        rarity_weight=1.0,
        ordered_connectivity_edge_sequences=((1, 3), (4,)),
        certificate_poi_edge_ids={1, 3, 4},
        certificate_expected_poi_count=3,
        protect_seed_incident_edges=False,
    )

    assert result.stage_pairs == 1
    assert result.connected_stage_pairs == 1
    assert result.retained_stage_pairs == 1
    assert result.certificate_topology == "forest"
    assert result.certificate_branch_count == 2
    assert result.path_certificate_status == "valid_forest"
    assert result.path_certificate_valid is True
    assert result.causal_path_cover_certificate_valid is True
    assert result.strict_multistage_certificate_valid is False
    assert result.candidate_disconnected_stage_pairs == ()
    assert result.stage_path_witnesses == ((1, 3, (2,)),)
    for edge_id in (1, 2, 3, 4):
        assert "causal_path_cover" in result.edge_selection_reasons[edge_id]


def test_causal_path_cover_still_rejects_disconnected_declared_chain():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcdef"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "stage-2", "c", "d"),
            _edge(3, "branch-poi", "e", "f"),
        ],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph,
        rarity,
        diffuse_importance(graph, {"a", "c", "e"}, rarity),
        seeds={"a", "c", "e"},
        keep_ratio=1.0,
        rarity_weight=1.0,
        ordered_connectivity_edge_sequences=((1, 2), (3,)),
        certificate_poi_edge_ids={1, 2, 3},
        certificate_expected_poi_count=3,
        protect_seed_incident_edges=False,
    )

    assert result.certificate_topology == "forest"
    assert result.path_certificate_status == "candidate_disconnected"
    assert result.path_certificate_valid is False
    assert result.causal_path_cover_certificate_valid is False
    assert result.candidate_disconnected_stage_pairs == ((1, 2),)


def test_single_poi_certificate_is_explicitly_poi_only():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "ab"},
        edges=[_edge(1, "poi", "a", "b")],
    )
    rarity = {1: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=1.0, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1,), certificate_poi_edge_ids={1},
        certificate_expected_poi_count=1, protect_seed_incident_edges=False,
    )

    assert result.path_certificate_status == "poi_only"
    assert result.path_certificate_valid is True
    assert result.strict_multistage_certificate_valid is False


def test_unordered_multi_poi_set_is_not_a_path_certificate():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[_edge(1, "poi-1", "a", "b"), _edge(2, "poi-2", "c", "d")],
    )
    rarity = {1: 1.0, 2: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a", "c"}, rarity),
        seeds={"a", "c"}, keep_ratio=1.0, rarity_weight=1.0,
        protected_edge_ids={1, 2}, certificate_poi_edge_ids={1, 2},
        certificate_expected_poi_count=2, protect_seed_incident_edges=False,
    )

    assert result.path_certificate_status == "unordered_multi_poi"
    assert result.path_certificate_valid is False
    assert result.strict_multistage_certificate_valid is False


def test_certificate_reports_budget_infeasible_before_claiming_validity():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "bridge", "b", "c"),
            _edge(3, "stage-2", "c", "d"),
            _edge(4, "noise", "a", "d"),
        ],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=0.25, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1, 3), certificate_poi_edge_ids={1, 3},
        certificate_expected_poi_count=2, protect_seed_incident_edges=False,
    )

    assert result.budget_feasible is False
    assert result.path_certificate_status == "budget_infeasible"
    assert result.path_certificate_valid is False


def test_certificate_reports_declared_poi_missing_from_candidate_graph():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "ab"},
        edges=[_edge(1, "present-poi", "a", "b")],
    )
    rarity = {1: 1.0}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=1.0, rarity_weight=1.0,
        ordered_connectivity_edge_ids=(1,), certificate_poi_edge_ids={1},
        certificate_expected_poi_count=2, protect_seed_incident_edges=False,
    )

    assert result.path_certificate_status == "missing_poi"
    assert result.path_certificate_valid is False


def test_prefix_stable_selection_bounds_churn_and_explains_every_kept_edge():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(7)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 6)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 0.4, 2: 0.5, 3: 0.6, 4: 1.0, 5: 0.9},
        mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {edge.edge_id: 0.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=0.6, rarity_weight=0.0,
        selection_mode="rdp_guard", fusion_mode="rdp_guard",
        protect_seed_incident_edges=False,
        previous_kept_edge_ids={1, 2, 3}, churn_slack_ratio=1 / 3,
        positive_score_only=True,
    )

    assert len(result.kept_edges) == 3
    assert result.removed_previous_edges <= result.allowed_removed_previous_edges
    assert result.churn_bound_satisfied is True
    assert len({edge.edge_id for edge in result.kept_edges} & {1, 2, 3}) >= 2
    assert all(result.edge_selection_reasons[edge.edge_id] for edge in result.kept_edges)
    assert result.prefix_jaccard is not None


def test_prefix_churn_bound_accounts_for_indivisible_atomic_group():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(6)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 5)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 1.0, 2: 1.0, 3: 1.0, 4: 0.9},
        mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {edge.edge_id: 0.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=0.75, rarity_weight=0.0,
        selection_mode="rdp_guard", fusion_mode="rdp_guard",
        protected_edge_ids={4}, atomic_edge_groups={1: (1, 2, 3)},
        protect_seed_incident_edges=False,
        previous_kept_edge_ids={1, 2, 3}, churn_slack_ratio=0.0,
        positive_score_only=True,
    )

    assert result.removed_previous_edges == 3
    assert result.declared_allowed_removed_previous_edges == 1
    assert result.atomicity_churn_slack_edges == 2
    assert result.allowed_removed_previous_edges == 3
    assert result.churn_bound_satisfied is True


def test_atomic_group_does_not_pregrant_churn_slack_when_it_fits():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(7)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 6)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 1.0, 2: 1.0, 3: 1.0, 4: 0.9, 5: 0.1},
        mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {edge.edge_id: 0.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=0.8, rarity_weight=0.0,
        selection_mode="rdp_guard", fusion_mode="rdp_guard",
        protected_edge_ids={4}, atomic_edge_groups={1: (1, 2, 3)},
        protect_seed_incident_edges=False,
        previous_kept_edge_ids={1, 2, 3}, churn_slack_ratio=0.0,
        positive_score_only=True,
    )

    assert result.removed_previous_edges == 0
    assert result.atomicity_churn_slack_edges == 0
    assert result.allowed_removed_previous_edges == 1


def test_prior_retention_uses_feasible_atomic_packing_not_score_greedy_order():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(8)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 7)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 1.0, 2: 1.0, 3: 0.9, 4: 0.9, 5: 0.9, 6: 0.8},
        mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {edge.edge_id: 0.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=4 / 6, rarity_weight=0.0,
        selection_mode="rdp_guard", fusion_mode="rdp_guard",
        protected_edge_ids={6},
        atomic_edge_groups={1: (1, 2), 3: (3, 4, 5)},
        protect_seed_incident_edges=False,
        previous_kept_edge_ids={1, 2, 3, 4, 5}, churn_slack_ratio=0.0,
        positive_score_only=True,
    )

    assert {edge.edge_id for edge in result.kept_edges} == {3, 4, 5, 6}
    assert result.removed_previous_edges == 2
    assert result.churn_bound_satisfied is True


def test_ordered_certificate_rejects_bridge_before_start_at_same_timestamp():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(10, "stage-1", "a", "b", timestamp_ns=10),
            _edge(1, "pre-start-bridge", "b", "c", timestamp_ns=10),
            _edge(20, "stage-2", "c", "d", timestamp_ns=20),
        ],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"a"}, rarity), seeds={"a"},
        keep_ratio=1.0, rarity_weight=1.0,
        protected_edge_ids={10, 20},
        ordered_connectivity_edge_ids=(10, 20),
        certificate_poi_edge_ids={10, 20},
        certificate_expected_poi_count=2,
        protect_seed_incident_edges=False,
    )

    assert result.connected_stage_pairs == 0
    assert result.path_certificate_status == "candidate_disconnected"
    assert result.strict_multistage_certificate_valid is False


def test_positive_score_only_does_not_fill_budget_with_zero_score_ties():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[_edge(1, "zero-1", "a", "b"), _edge(2, "zero-2", "b", "c")],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 0.0, 2: 0.0}, mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {1: 1.0, 2: 1.0}, diffusion, seeds=set(), keep_ratio=0.5,
        rarity_weight=0.2, selection_mode="rdp_guard", fusion_mode="rdp_guard",
        protect_seed_incident_edges=False, positive_score_only=True,
    )

    assert result.kept_edges == []
    assert result.unused_budget_edges == 1
    assert result.zero_score_fill_stopped is True


def test_rarity_escape_diversity_quota_retains_disconnected_novel_edge_inside_cap():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(11)},
        edges=[_edge(i, f"e{i}", str(i - 1), str(i)) for i in range(1, 11)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={edge.edge_id: 0.0 for edge in graph.edges},
        mode="time_respecting_bidir",
    )
    main_scores = {edge.edge_id: (11 - edge.edge_id) / 10 for edge in graph.edges}

    result = adaptive_prune(
        graph,
        {edge.edge_id: 1.0 for edge in graph.edges},
        diffusion,
        seeds=set(),
        keep_ratio=0.3,
        rarity_weight=0.2,
        fusion_mode="rdp_guard",
        selection_mode="rdp_guard",
        protect_seed_incident_edges=False,
        edge_scores_override=main_scores,
        edge_score_components_override={edge.edge_id: {} for edge in graph.edges},
        escape_importance={10: 0.95},
        escape_eligible_edge_ids={10},
        escape_quota_ratio=0.34,
        escape_threshold=0.9,
    )

    assert {edge.edge_id for edge in result.kept_edges} == {1, 2, 10}
    assert result.budget_edges == 3
    assert result.actual_keep_ratio == 0.3
    assert result.escape_budget_edges == 1
    assert result.escape_selected_edges == 1
    assert "rarity_escape_diversity" in result.edge_selection_reasons[10]


def test_pruning_reports_linear_incremental_candidate_work():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(101)},
        edges=[_edge(i, f"e{i}", str(i - 1), str(i)) for i in range(1, 101)],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph, rarity, diffuse_importance(graph, {"0"}, rarity), seeds={"0"},
        keep_ratio=1.0, rarity_weight=1.0, protect_seed_incident_edges=False,
    )

    assert result.selection_candidate_edges_examined <= len(graph.edges)


def test_rdp_guard_fusion_keeps_diffusion_supported_common_bridge_over_remote_rare_noise():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "common-bridge", "a", "b"),
            _edge(2, "remote-rare", "c", "d", "RARE"),
        ],
    )
    diffusion = DiffusionResult(
        scores={name: 0.0 for name in "abcd"},
        predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 0.8, 2: 0.0}, mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {1: 0.0, 2: 1.0}, diffusion, seeds=set(),
        keep_ratio=0.5, rarity_weight=0.2, fusion_mode="rdp_guard",
        selection_mode="rdp_guard", protect_seed_incident_edges=False,
    )

    assert {edge.event_id for edge in result.kept_edges} == {"common-bridge"}
    assert result.scoring_mode == "rdp_guard"
    assert result.edge_score_components[2]["gated_rarity"] == 0.0


def test_rdp_guard_budget_skips_oversized_atomic_group_and_fills_with_smaller_groups():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(7)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 6)],
    )
    diffusion = DiffusionResult(
        scores={}, predecessors={}, iterations=1, converged=True, diagnostics=[],
        edge_scores={1: 1.0, 2: 1.0, 3: 1.0, 4: 0.8, 5: 0.7},
        mode="time_respecting_bidir",
    )

    result = adaptive_prune(
        graph, {edge.edge_id: 0.0 for edge in graph.edges}, diffusion,
        seeds=set(), keep_ratio=0.4, rarity_weight=0.2,
        fusion_mode="rdp_guard", selection_mode="rdp_guard",
        atomic_edge_groups={1: (1, 2, 3)}, protect_seed_incident_edges=False,
    )

    assert result.budget_edges == 2
    assert len(result.kept_edges) == 2
    assert {edge.edge_id for edge in result.kept_edges} == {4, 5}
    assert result.actual_keep_ratio == pytest.approx(0.4)


def test_fractional_raw_event_budget_uses_floor_as_a_hard_ratio_cap():
    graph = Neighborhood(
        nodes={str(i): NodeRecord(str(i), "process", str(i)) for i in range(8)},
        edges=[_edge(i, f"e{i}", str(i), str(i + 1)) for i in range(1, 7)],
    )
    rarity = {edge.edge_id: 1.0 for edge in graph.edges}

    result = adaptive_prune(
        graph,
        rarity,
        diffuse_importance(graph, set(), rarity),
        seeds=set(),
        keep_ratio=0.2,
        rarity_weight=1.0,
        protect_seed_incident_edges=False,
    )

    assert result.budget_edges == 1
    assert len(result.kept_edges) == 1
    assert result.actual_keep_ratio <= 0.2
    assert result.budget_rounding_policy == "floor_hard_cap_minimum_one"


def test_rdp_guard_reports_auditable_ordered_poi_path_certificate():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "stage-1", "a", "b"),
            _edge(2, "bridge", "b", "c"),
            _edge(3, "stage-2", "c", "d"),
            _edge(4, "noise", "a", "d"),
        ],
    )
    rarity = {edge.edge_id: 0.0 for edge in graph.edges}

    result = adaptive_prune(
        graph, rarity,
        diffuse_importance(
            graph, {"a"}, rarity, mode="time_respecting_bidir",
            seed_edges=[graph.edges[0], graph.edges[2]],
        ),
        seeds={"a"}, keep_ratio=0.75, rarity_weight=0.2,
        fusion_mode="rdp_guard", selection_mode="rdp_guard",
        protected_edge_ids={1, 3}, ordered_connectivity_edge_ids=(1, 3),
        protect_seed_incident_edges=False,
    )

    assert result.certificate_poi_edges == 2
    assert result.certificate_retained_poi_edges == 2
    assert result.stage_pairs == result.retained_stage_pairs == 1
    assert result.path_certificate_valid is True
    assert result.path_certificate_status == "valid"
    assert result.strict_multistage_certificate_valid is True
    assert result.stage_path_witnesses == ((1, 3, (2,)),)
    assert result.score_mass_retained > 0.0
    assert result.score_mass_retained <= 1.0


import pytest
