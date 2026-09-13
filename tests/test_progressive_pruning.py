import pytest

from tc_pruning.diffusion import DiffusionResult
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.progressive_pruning import progressive_select
from tc_pruning.pruning import adaptive_prune


class _CountingEvidence(dict):
    def __init__(self, values):
        super().__init__(values)
        self.get_calls = 0

    def get(self, key, default=None):
        self.get_calls += 1
        return super().get(key, default)


def _edge(edge_id, src, dst):
    return StoredEdge(
        edge_id, str(edge_id), src, dst, "COMMON", edge_id,
        "h", "process", "process",
    )


def test_progressive_removes_low_value_noise_first_and_is_deterministic():
    kwargs = dict(
        edge_scores={1: .9, 2: .1, 3: .6},
        groups=[(3,), (1,), (2,)], budget_edges=2,
    )
    first = progressive_select(**kwargs)
    second = progressive_select(**kwargs)
    assert first.selected_edge_ids == frozenset({1, 3})
    assert first == second
    assert first.audit[2]["removal_round"] == 1


def test_progressive_charges_atomic_group_by_raw_event_count():
    result = progressive_select(
        edge_scores={1: .1, 2: .1, 3: .9},
        groups=[(1, 2), (3,)], budget_edges=1,
    )
    assert result.selected_edge_ids == frozenset({3})
    assert result.audit[1]["raw_cost"] == 2
    assert result.audit[2]["raw_cost"] == 2


def test_progressive_guards_mandatory_and_dependency_groups():
    result = progressive_select(
        edge_scores={1: .0, 2: .1, 3: .9},
        groups=[(1,), (2,), (3,)], budget_edges=2,
        mandatory_edge_ids={1}, dependencies={(3,): [(2,)]},
    )
    assert result.selected_edge_ids == frozenset({1, 2})
    assert result.audit[1]["rejection_reason"] == "protected_evidence"
    assert result.audit[2]["rejection_reason"] == "required_dependency"
    assert result.budget_feasible is True


def test_progressive_prefix_churn_guard_limits_removal():
    result = progressive_select(
        edge_scores={1: .1, 2: .2, 3: .9},
        groups=[(1,), (2,), (3,)], budget_edges=0,
        previous_edge_ids={1, 2}, max_removed_previous_edges=1,
    )
    assert len(result.selected_edge_ids) == 1
    assert len(result.selected_edge_ids & {1, 2}) == 1
    assert result.budget_feasible is False
    assert any(
        row["rejection_reason"] == "prefix_churn"
        for row in result.audit.values()
    )


def test_adaptive_progressive_preserves_path_cover_certificate():
    edges = [
        _edge(1, "a", "b"), _edge(2, "b", "c"),
        _edge(3, "c", "d"), _edge(4, "x", "y"),
    ]
    graph = Neighborhood({n: NodeRecord(n, "process", n) for n in "abcdxy"}, edges)
    diffusion = DiffusionResult({}, {}, 0, True, [], {i: 0.0 for i in range(1, 5)})
    result = adaptive_prune(
        graph, {1: .8, 2: .2, 3: .8, 4: 0.0}, diffusion,
        seeds=set(), keep_ratio=.75, rarity_weight=1.0,
        selection_mode="progressive", protect_seed_incident_edges=False,
        ordered_connectivity_edge_ids=(1, 3), certificate_expected_poi_count=2,
    )
    assert {e.edge_id for e in result.kept_edges} == {1, 2, 3}
    assert result.path_certificate_valid
    assert result.progressive_audit[4]["removal_allowed"] is True


def test_progressive_uses_consistency_and_configurable_weak_redundancy():
    result = progressive_select(
        edge_scores={1: .5, 2: .5}, groups=[(1,), (2,)], budget_edges=1,
        edge_evidence={1: {"consistency": .9}, 2: {"consistency": .1}},
        config={"consistency_weight": .2, "redundancy_weight": 0.0},
    )
    assert result.selected_edge_ids == frozenset({1})


def test_progressive_protected_group_is_never_attempted_for_removal():
    result = progressive_select(
        edge_scores={1: 0.0, 2: 1.0}, groups=[(1,), (2,)],
        budget_edges=1, mandatory_edge_ids={1},
    )
    assert result.audit[1]["removal_attempted"] is False
    assert result.audit[1]["rejection_reason"] == "protected_evidence"


def test_progressive_rejects_unknown_config_fields():
    with pytest.raises(ValueError, match="unknown progressive config"):
        progressive_select(
            edge_scores={1: 1.0}, groups=[(1,)], budget_edges=1,
            config={"dependencies": {}},
        )


def test_adaptive_progressive_gives_every_retained_edge_a_reason():
    edges = [_edge(1, "a", "b"), _edge(2, "x", "y")]
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in "abxy"}, edges,
    )
    diffusion = DiffusionResult({}, {}, 0, True, [], {1: .8, 2: .7})
    result = adaptive_prune(
        graph, {1: .8, 2: .7}, diffusion, seeds=set(), keep_ratio=1.0,
        rarity_weight=1.0, selection_mode="progressive",
        protect_seed_incident_edges=False,
    )
    assert set(result.edge_selection_reasons) == {1, 2}
    assert all(result.edge_selection_reasons.values())


def test_adaptive_progressive_positive_score_only_excludes_zero_score_noise():
    edges = [_edge(1, "a", "b"), _edge(2, "x", "y")]
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in "abxy"}, edges,
    )
    diffusion = DiffusionResult({}, {}, 0, True, [], {1: 0.0, 2: 0.0})
    result = adaptive_prune(
        graph, {1: 1.0, 2: 0.0}, diffusion, seeds=set(), keep_ratio=1.0,
        rarity_weight=1.0, selection_mode="progressive",
        protect_seed_incident_edges=False, positive_score_only=True,
    )
    assert {edge.edge_id for edge in result.kept_edges} == {1}
    assert result.progressive_audit[2]["rejection_reason"] == "ineligible"


def test_adaptive_progressive_holds_connectivity_witness_for_selected_group():
    edges = [
        _edge(1, "a", "b"), _edge(2, "b", "c"), _edge(3, "c", "d")
    ]
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in "abcd"}, edges,
    )
    diffusion = DiffusionResult({}, {}, 0, True, [], {1: .9, 2: .1, 3: .8})
    result = adaptive_prune(
        graph, {1: .9, 2: .1, 3: .8}, diffusion, seeds=set(), keep_ratio=1.0,
        rarity_weight=1.0, selection_mode="progressive",
        protect_seed_incident_edges=False, connectivity_target_edge_ids={3},
    )
    assert {edge.edge_id for edge in result.kept_edges} == {1, 2, 3}
    assert "progressive_dependency" in result.edge_selection_reasons[2]


def test_adaptive_progressive_closes_overlapping_atomic_declarations():
    edges = [
        _edge(1, "a", "b"), _edge(2, "b", "c"),
        _edge(3, "c", "d"), _edge(4, "x", "y"),
    ]
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in "abcdxy"}, edges,
    )
    diffusion = DiffusionResult({}, {}, 0, True, [], {})
    result = adaptive_prune(
        graph, {1: .1, 2: .1, 3: .1, 4: .9}, diffusion,
        seeds=set(), keep_ratio=.25, rarity_weight=1.0,
        selection_mode="progressive", protect_seed_incident_edges=False,
        atomic_edge_groups={1: (1, 2), 2: (2, 3)},
    )
    assert {edge.edge_id for edge in result.kept_edges} == {4}
    assert result.progressive_audit[1]["raw_cost"] == 3


def test_progressive_remaps_dependency_references_through_atomic_groups():
    edges = [
        _edge(1, "a", "b"), _edge(2, "a", "c"), _edge(3, "c", "d"),
    ]
    graph = Neighborhood(
        {n: NodeRecord(n, "process", n) for n in "abcd"}, edges,
    )
    diffusion = DiffusionResult({}, {}, 0, True, [], {})
    result = adaptive_prune(
        graph, {1: .9, 2: .9, 3: .1}, diffusion, seeds=set(),
        keep_ratio=2 / 3, rarity_weight=1.0, selection_mode="progressive",
        protect_seed_incident_edges=False, protected_edge_ids={1},
        atomic_edge_groups={1: (1, 2)},
        progressive_dependencies={(1,): ((3,),)},
    )
    assert {edge.edge_id for edge in result.kept_edges} == {1, 2, 3}
    assert "progressive_dependency" in result.edge_selection_reasons[3]
    assert result.budget_feasible is False


def test_progressive_long_dependency_chain_expands_without_quadratic_rescan():
    count = 2000
    edges = [_edge(i, f"n{i}", f"n{i + 1}") for i in range(1, count + 1)]
    graph = Neighborhood({}, edges)
    diffusion = DiffusionResult({}, {}, 0, True, [], {})
    dependencies = {(i,): ((i + 1,),) for i in range(1, count)}
    result = adaptive_prune(
        graph, {i: float(i == 1) for i in range(1, count + 1)},
        diffusion, seeds=set(), keep_ratio=1 / count, rarity_weight=1.0,
        selection_mode="progressive", protect_seed_incident_edges=False,
        positive_score_only=True, progressive_dependencies=dependencies,
    )
    assert len(result.progressive_audit) == count
    assert result.selection_candidate_edges_examined <= 2 * count


def test_large_mandatory_atomic_group_builds_audit_in_linear_operations():
    count = 2000
    evidence = _CountingEvidence({
        edge_id: {"consistency": .5} for edge_id in range(count)
    })
    result = progressive_select(
        edge_scores={edge_id: .5 for edge_id in range(count)},
        groups=[tuple(range(count))], budget_edges=1,
        mandatory_edge_ids={0}, edge_evidence=evidence,
    )
    assert len(result.audit) == count
    assert evidence.get_calls <= 3 * count
