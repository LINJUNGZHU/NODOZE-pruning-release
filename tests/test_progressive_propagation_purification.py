from tc_pruning.investigation.graph_views import InvestigationGraphs, PropagationEdge
from tc_pruning.investigation.progressive_purification import (
    ProgressivePurification, PurificationConfig,
)


def _p(name, src, dst, weight=1.0):
    return PropagationEdge(name, name, src, dst, "EVENT_READ", "FILE_READ", 1, weight, weight)


def test_purification_downweights_interference_without_touching_full_facts():
    graph = InvestigationGraphs(("immutable",), (_p("noise", "hub", "x"), _p("proof", "p", "a")))
    result = ProgressivePurification(PurificationConfig(rounds=2, frequency_threshold=2,
                                                         fanout_threshold=2)).run(
        graph, frequency={"noise": 10, "proof": 10}, fanout={"noise": 10, "proof": 10},
        kairos_support={"proof": 1.0}, target_support={}, unique_coverage={"proof"},
    )
    assert result.graph.full_edges == ("immutable",)
    weights = {edge.raw_event_id: edge.raw_weight for edge in result.graph.propagation_edges}
    assert weights["noise"] < 1.0
    assert weights["proof"] == 1.0


def test_unstable_top_candidates_stop_early():
    graph = InvestigationGraphs((), (_p("a", "p", "x"), _p("b", "p", "y")))
    calls = iter((frozenset({"a"}), frozenset({"b"})))
    result = ProgressivePurification(PurificationConfig(rounds=4, minimum_stability=.8)).run(
        graph, frequency={}, fanout={}, kairos_support={}, target_support={}, unique_coverage=set(),
        ranking=lambda _: next(calls),
    )
    assert result.stop_reason == "RANKING_INSTABILITY"
