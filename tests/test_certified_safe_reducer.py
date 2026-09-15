from tc_pruning.investigation.mosaic_selector import MosaicEvidenceUnit, ObjectiveTargets
from tc_pruning.investigation.safe_reducer import CertifiedProgressiveReducer


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
