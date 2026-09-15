from tc_pruning.investigation.edge_projection import EvaluationEdgeProjection, ProjectionMode
from tc_pruning.models import StoredEdge


def _edge(event, timestamp):
    return StoredEdge(1, event, "p", "f", "event_write", timestamp, "h", "process", "file")


def test_raw_projection_is_one_to_one_and_preserves_ids():
    projection = EvaluationEdgeProjection(ProjectionMode.RAW_EVENT, merge_window_ns=10)
    edges = (_edge("e1", 9), _edge("e2", 10))
    result = projection.project(edges)
    assert len(result) == 2
    assert {row.raw_event_ids for row in result} == {("e1",), ("e2",)}
    assert projection.count(edges) == len(result)


def test_depimpact_projection_merges_only_inside_same_time_group():
    projection = EvaluationEdgeProjection(
        ProjectionMode.DEPIMPACT_COMPATIBLE, merge_window_ns=10
    )
    edges = (_edge("e1", 1), _edge("e2", 9), _edge("e3", 10))
    result = projection.project(edges)
    assert [row.raw_event_ids for row in result] == [("e1", "e2"), ("e3",)]
    assert result[0].normalized_relation == "EVENT_WRITE"
    assert projection.count(edges) == len(result)
