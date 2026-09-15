import pytest

from tc_pruning.investigation.graph_views import CleanPropagationConfig, InvestigationGraphs
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import StoredEdge


def _edge(i, src, dst, relation, timestamp, src_type="process", dst_type="process"):
    return StoredEdge(
        i, f"e{i}", src, dst, relation, timestamp, "h",
        src_type, dst_type, src, dst, None,
    )


def test_full_graph_keeps_future_unknown_and_suppressed_evidence():
    edges = (
        _edge(1, "p", "f", "EVENT_WRITE", 10, dst_type="file"),
        _edge(2, "p", "x", "EVENT_MYSTERY", 11),
        _edge(3, "p", "q", "EVENT_FORK", 30),
    )
    graphs = CleanPropagationBuilder(
        InvestigationSemanticsRegistry.cadets(), CleanPropagationConfig()
    ).build(edges, cutoff_ns=20, historical_frequency={"e1": 100})

    assert {edge.event_id for edge in graphs.full_edges} == {"e1", "e2", "e3"}
    assert {edge.raw_event_id for edge in graphs.propagation_edges} == {"e1"}
    assert graphs.output_event_ids == frozenset()


def test_relation_channels_normalize_separately():
    edges = (
        _edge(1, "f1", "p", "EVENT_READ", 10, src_type="file", dst_type="process"),
        _edge(2, "f2", "p", "EVENT_READ", 11, src_type="file", dst_type="process"),
        _edge(3, "p", "child", "EVENT_FORK", 12),
    )
    # READ is causally file -> process, so use two file sources that converge on p.
    graphs = CleanPropagationBuilder(
        InvestigationSemanticsRegistry.cadets(), CleanPropagationConfig()
    ).build(edges, cutoff_ns=20)

    control = [e for e in graphs.propagation_edges if e.relation_family == "CONTROL"]
    reads = [e for e in graphs.propagation_edges if e.relation_family == "FILE_READ"]
    assert sum(e.transition_weight for e in control) == pytest.approx(1.0)
    assert all(e.transition_weight == pytest.approx(1.0) for e in reads)


def test_frequency_and_fanout_softly_suppress_hub_edges():
    edges = tuple(
        _edge(i, "hub", f"f{i}", "EVENT_WRITE", 10 + i, dst_type="file")
        for i in range(1, 6)
    ) + (_edge(10, "rare", "fr", "EVENT_WRITE", 15, dst_type="file"),)
    config = CleanPropagationConfig(alpha=1.0, gamma=1.0)
    graphs = CleanPropagationBuilder(
        InvestigationSemanticsRegistry.cadets(), config
    ).build(edges, cutoff_ns=20, historical_frequency={f"e{i}": 10 for i in range(1, 6)})

    hub_raw = max(e.raw_weight for e in graphs.propagation_edges if e.causal_source == "hub")
    rare_raw = next(e.raw_weight for e in graphs.propagation_edges if e.causal_source == "rare")
    assert hub_raw < rare_raw
    assert len(graphs.full_edges) == 6


def test_rejects_history_snapshot_after_query_cutoff():
    edge = _edge(1, "p", "f", "EVENT_WRITE", 10, dst_type="file")
    with pytest.raises(ValueError, match="history cutoff"):
        CleanPropagationBuilder(
            InvestigationSemanticsRegistry.cadets(), CleanPropagationConfig()
        ).build((edge,), cutoff_ns=20, history_cutoff_ns=21)


def test_output_must_be_subset_of_full_raw_events():
    graph = InvestigationGraphs(full_edges=(), propagation_edges=())
    with pytest.raises(ValueError, match="subset"):
        graph.with_output({"missing"})
