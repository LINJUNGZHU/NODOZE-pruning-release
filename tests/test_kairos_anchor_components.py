from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.investigation.kairos_components import KairosAnchorComponentBuilder


def _e(name, time, queues=(), src="p", dst="f"):
    return KairosEvidence(name, src, dst, "EVENT_WRITE", time, 2.0, 1.0, True,
                          queues, 3.0, False, None, name, "w", "EXACT")


def test_queue_members_merge_but_time_alone_does_not():
    result = KairosAnchorComponentBuilder().build((
        _e("a", 1, ("q",)), _e("b", 2, ("q",), src="x"),
        _e("c", 3, (), src="z", dst="y"),
    ))
    assert [component.event_ids for component in result] == [("a", "b"), ("c",)]


def test_large_single_queue_avoids_quadratic_pair_scan():
    rows = tuple(_e(f"e{index}", index, ("large",)) for index in range(20_000))
    components = KairosAnchorComponentBuilder().build(rows)
    assert len(components) == 1
    assert len(components[0].event_ids) == 20_000
