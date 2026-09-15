from tc_pruning.investigation.mosaic_selector import MosaicEvidenceUnit, ObjectiveTargets
from tc_pruning.investigation.safe_reducer import CertifiedProgressiveReducer
from tc_pruning.investigation.causal_corridors import PathBundle


def _u(name, event, branch, risk, bridge=False):
    return MosaicEvidenceUnit(name, (event,), frozenset({"k"}), frozenset({branch}),
                              frozenset({"a"}), {"d": 1.0}, 1.0, risk, bridge)


def test_safe_delete_removes_redundancy_but_keeps_unique_bridge():
    units = (_u("copy1", "e1", "b", 0.0), _u("copy2", "e2", "b", 0.1),
             _u("bridge", "e3", "unique", 0.0, True))
    targets = ObjectiveTargets(kairos=1, branch=2, anchor=1, path_prize=1, relevance=1)
    result = CertifiedProgressiveReducer().reduce(units, targets)
    assert len({"copy1", "copy2"} & set(result.selected_unit_ids)) == 1
    assert "bridge" in result.selected_unit_ids


def test_safe_delete_rejects_nonmandatory_unit_needed_by_only_temporal_witness():
    units = (_u("first", "e1", "b", 0.0), _u("second", "e2", "b", 0.1))
    target = ObjectiveTargets(kairos=1, branch=1, anchor=1, path_prize=0, relevance=1)
    witness = PathBundle("d", ("e1", "e2"), ("p1", "p2"), "a", "b", (1, 2),
                         ("EVENT_WRITE", "EVENT_READ"), 1.0, 1.0, (), ())
    result = CertifiedProgressiveReducer().reduce(units, target, path_bundles=(witness,))
    assert result.selected_event_ids == ("e1", "e2")


def test_unsatisfied_soft_demand_does_not_turn_into_hard_delete_blocker():
    units = (_u("copy1", "e1", "b", 0.0), _u("copy2", "e2", "b", 0.1))
    target = ObjectiveTargets(kairos=1, branch=1, anchor=1, path_prize=1, relevance=1)
    absent_witness = PathBundle(
        "soft", ("missing1", "missing2"), ("p1", "p2"), "a", "b", (1, 2),
        ("EVENT_WRITE", "EVENT_READ"), 1.0, 1.0, (), (),
    )
    result = CertifiedProgressiveReducer().reduce(
        units, target, path_bundles=(absent_witness,)
    )
    assert len(result.selected_event_ids) == 1
