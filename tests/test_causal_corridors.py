from tc_pruning.investigation.causal_corridors import CausalCorridorBuilder, CorridorConfig
from tc_pruning.investigation.graph_views import InvestigationGraphs, PropagationEdge
from tc_pruning.investigation.kairos_components import KairosAnchorComponent


def _p(name, src, dst, time):
    return PropagationEdge(name, name, src, dst, "EVENT_WRITE", "FILE_WRITE", time, 1.0, 1.0)


def _c(name, node, time):
    return KairosAnchorComponent(name, (name,), (node,), (), (), 1.0, time, time, (), {})


def test_corridor_contains_strict_raw_replay_witness():
    graph = InvestigationGraphs((), (_p("e1", "a", "x", 1), _p("e2", "x", "b", 2)))
    paths = CausalCorridorBuilder(CorridorConfig(k_paths=2)).between(
        graph, _c("ca", "a", 0), _c("cb", "b", 3)
    )
    assert paths[0].raw_event_ids == ("e1", "e2")
    assert paths[0].temporal_witness == (1, 2)


def test_equal_time_edges_do_not_form_a_corridor():
    graph = InvestigationGraphs((), (_p("e1", "a", "x", 1), _p("e2", "x", "b", 1)))
    assert CausalCorridorBuilder().between(graph, _c("ca", "a", 0), _c("cb", "b", 3)) == ()
