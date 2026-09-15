from tc_pruning.investigation.mosaic_selector import (
    MosaicEvidenceUnit, ObjectiveTargets, RobustMultiobjectiveSelector,
)


def _unit(name, *, kairos=(), branches=(), anchors=(), prizes=None, relevance=0.0):
    return MosaicEvidenceUnit(name, (name,), frozenset(kairos), frozenset(branches),
                              frozenset(anchors), prizes or {}, relevance, 0.0, False)


def test_worst_objective_prevents_relevance_only_starvation():
    units = (
        _unit("high", relevance=1.0, branches=("main",)),
        _unit("k", kairos=("k1",), anchors=("a",)),
        _unit("p", branches=("small",), prizes={"d": 1.0}),
    )
    targets = ObjectiveTargets(kairos=1, branch=1, anchor=1, path_prize=1, relevance=0)
    result = RobustMultiobjectiveSelector().select_trajectory(units, targets)
    assert result.minimum_satisfying_event_ids == ("k", "p")
    assert result.checkpoints[-1].objective.minimum_ratio >= 1.0


def test_branch_concavity_has_diminishing_returns():
    selector = RobustMultiobjectiveSelector()
    first = selector.branch_gain(frozenset({"a"}), {})
    later = selector.branch_gain(frozenset({"a"}), {"a": 100})
    assert later < first


def test_representative_prefilter_keeps_branch_and_anchor_lanes():
    units = (
        _unit("a-low", branches=("shared",), anchors=("a",), relevance=0.1),
        _unit("a-high", branches=("shared",), anchors=("a",), relevance=1.0),
        _unit("b", branches=("shared",), anchors=("b",), relevance=0.2),
    )
    kept = RobustMultiobjectiveSelector.representative_prefilter(units, top_k=1)
    assert {unit.unit_id for unit in kept} == {"a-high", "b"}
