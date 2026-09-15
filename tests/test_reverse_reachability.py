from dataclasses import replace

from tc_pruning.investigation.graph_views import CleanPropagationConfig
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.reverse_reachability import (
    ReverseReachabilityConfig,
    TemporalReverseReachability,
)
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import StoredEdge


def _edge(i, src, dst, timestamp):
    return StoredEdge(
        i, f"e{i}", src, dst, "EVENT_FORK", timestamp, "h",
        "process", "process", src, dst, None,
    )


def _graphs(edges, cutoff=100):
    return CleanPropagationBuilder(
        InvestigationSemanticsRegistry.cadets(), CleanPropagationConfig()
    ).build(edges, cutoff_ns=cutoff)


def test_exhaustive_reverse_finds_root_of_root_a_poi_chain():
    result = TemporalReverseReachability(
        ReverseReachabilityConfig(exhaustive=True, max_hops=4)
    ).run(_graphs((_edge(1, "root", "a", 10), _edge(2, "a", "poi", 20))), {"poi": 30})

    assert result.roots[0].node_id == "root"
    assert result.roots[0].minimum_hops == 2
    assert result.roots[0].witness_event_ids == ("e1", "e2")


def test_equal_time_cannot_create_reverse_source():
    result = TemporalReverseReachability(
        ReverseReachabilityConfig(exhaustive=True, max_hops=4)
    ).run(_graphs((_edge(1, "root", "a", 10), _edge(2, "a", "poi", 10))), {"poi": 30})

    assert "root" not in {root.node_id for root in result.roots}


def test_fixed_seed_produces_identical_sketches_and_roots():
    graphs = _graphs((
        _edge(1, "r1", "a", 10), _edge(2, "r2", "a", 11),
        _edge(3, "a", "poi", 20),
    ))
    config = ReverseReachabilityConfig(samples=32, seed=17, max_hops=4)

    first = TemporalReverseReachability(config).run(graphs, {"poi": 30})
    second = TemporalReverseReachability(config).run(graphs, {"poi": 30})

    assert first.sketches == second.sketches
    assert first.roots == second.roots


def test_hub_suppression_prefers_rare_origin():
    edges = [
        _edge(1, "hub", "a", 10),
        _edge(2, "rare", "a", 11),
        _edge(3, "a", "poi", 20),
    ] + [_edge(10 + i, "hub", f"noise{i}", 12 + i) for i in range(12)]
    graphs = CleanPropagationBuilder(
        InvestigationSemanticsRegistry.cadets(),
        CleanPropagationConfig(alpha=1.0, gamma=1.0),
    ).build(edges, cutoff_ns=40, historical_frequency={"e1": 1000})
    result = TemporalReverseReachability(
        ReverseReachabilityConfig(samples=400, seed=9, max_hops=4)
    ).run(graphs, {"poi": 30})
    scores = {root.node_id: root.source_support for root in result.roots}

    assert scores["rare"] > scores.get("hub", 0.0)


def test_disconnected_graph_copy_does_not_change_reverse_ranking():
    base = (_edge(1, "root", "a", 10), _edge(2, "a", "poi", 20))
    config = ReverseReachabilityConfig(samples=20, seed=3, max_hops=4)
    first = TemporalReverseReachability(config).run(_graphs(base), {"poi": 30})
    noise = tuple(_edge(100 + i, f"x{i}", f"y{i}", i + 1) for i in range(20))
    second = TemporalReverseReachability(config).run(_graphs(base + noise), {"poi": 30})

    assert first.roots == second.roots
