from tc_pruning.investigation.graph_views import InvestigationGraphs, PropagationEdge
from tc_pruning.investigation.inverse_coverage import InverseCoverageConfig, SourceAwareInverseCoverage
from tc_pruning.investigation.kairos_components import KairosAnchorComponent


def _p(name, src, dst, time):
    return PropagationEdge(name, name, src, dst, "EVENT_FORK", "CONTROL", time, 1.0, 1.0)


def _component(name, node, time):
    return KairosAnchorComponent(name, (name,), (node,), (), (), 1.0, time, time, (), {})


def test_root_is_ranked_by_how_many_components_it_explains():
    graphs = InvestigationGraphs((), (_p("e1", "root", "a", 1), _p("e2", "root", "b", 2)))
    roots = SourceAwareInverseCoverage(InverseCoverageConfig(max_states=20)).explain(
        graphs, (_component("a", "a", 3), _component("b", "b", 3))
    )
    root = next(item for item in roots if item.node_id == "root")
    assert root.explained_components == ("a", "b")
    assert root.anchor_support == 1.0
