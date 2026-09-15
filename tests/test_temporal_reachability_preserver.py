from tc_pruning.investigation.reachability import TemporalDemandPair, TemporalReachabilityPreserver
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import StoredEdge


def _e(i, src, dst, t):
    return StoredEdge(i, f"e{i}", src, dst, "EVENT_FORK", t, "h", "process", "process", src, dst, None)


def test_preserves_demand_and_drops_redundant_longer_path():
    edges = (_e(1,"a","b",1), _e(2,"b","d",2), _e(3,"a","c",1), _e(4,"c","x",2), _e(5,"x","d",3))
    result = TemporalReachabilityPreserver(InvestigationSemanticsRegistry.cadets()).preserve(
        edges, (TemporalDemandPair("q","a","d","ROOT_ANCHOR","a","test",(0,10),1.0),), {e.event_id: 1 for e in edges}, budget=2
    )
    assert result.event_ids == ("e1", "e2")
    assert result.reachability_preservation_rate == 1.0


def test_static_but_reverse_time_path_is_not_preserved():
    edges = (_e(1,"a","b",2), _e(2,"b","d",1))
    result = TemporalReachabilityPreserver(InvestigationSemanticsRegistry.cadets()).preserve(
        edges, (TemporalDemandPair("q","a","d","ROOT_ANCHOR","a","test",(0,10),1.0),), {}, budget=10
    )
    assert result.preserved_demand_count == 0


def test_mandatory_overflow_is_explicit_and_keeps_witness():
    edges = (_e(1,"a","b",1), _e(2,"b","d",2))
    result = TemporalReachabilityPreserver(InvestigationSemanticsRegistry.cadets()).preserve(
        edges, (TemporalDemandPair("q","a","d","ROOT_ANCHOR","a","test",(0,10),1.0),), {}, budget=1
    )
    assert result.event_ids == ("e1", "e2")
    assert result.budget_feasible is False
    assert result.budget_overflow_events == 1
