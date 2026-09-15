from tc_pruning.investigation.branch_fair_selector import BranchFairConfig, LazyGreedySelector
from tc_pruning.investigation.evidence_units import EvidenceUnit, ecdf_relevance


def _unit(name, score, branch, events=None, verification=1.0):
    return EvidenceUnit(name, "edge", tuple(events or (name,)), (name,), frozenset({branch}), frozenset(), None, frozenset(), score, score, verification)


def test_ecdf_is_stable_when_disconnected_zero_scores_are_added():
    assert ecdf_relevance({"a": 1.0, "b": 2.0})["b"] == ecdf_relevance({"a": 1.0, "b": 2.0, **{f"z{i}": 0.0 for i in range(100)}})["b"]


def test_branch_fair_selection_does_not_starve_small_verified_branch():
    units = tuple(_unit(f"a{i}", .9, "A") for i in range(100)) + (_unit("b1", .7, "B"), _unit("b2", .6, "B"))
    result = LazyGreedySelector(BranchFairConfig(lambda_branch=4.0)).select(units, mandatory_event_ids=set(), budget=3)
    assert any(unit.startswith("b") for unit in result.selected_unit_ids)


def test_overlap_cost_counts_only_new_raw_events_and_is_deterministic():
    units = (_unit("u1", .8, "A", ("e1","e2")), _unit("u2", .7, "B", ("e2","e3")))
    selector = LazyGreedySelector(BranchFairConfig())
    first = selector.select(units, mandatory_event_ids={"e1"}, budget=3)
    second = selector.select(units, mandatory_event_ids={"e1"}, budget=3)
    assert first == second
    assert first.raw_event_cost == 3


def test_diminishing_return_for_repeated_branch_evidence():
    selector = LazyGreedySelector(BranchFairConfig(lambda_branch=1.0))
    unit = _unit("u", .0, "A")
    assert selector.marginal(unit, {}, set(), set())["branch"] > selector.marginal(unit, {"A": 100}, set(), set())["branch"]
