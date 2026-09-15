from tc_pruning.investigation.forward_sphere import (
    ForwardCausalSphereBuilder, ForwardSphereConfig, OnlineForwardSignals,
    harmonic_verification,
)
from tc_pruning.investigation.graph_views import CleanPropagationConfig
from tc_pruning.investigation.propagation import CleanPropagationBuilder
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import StoredEdge


def _edge(i, src, dst, timestamp):
    return StoredEdge(i, f"e{i}", src, dst, "EVENT_FORK", timestamp, "h", "process", "process", src, dst, None)


def _graphs(edges):
    return CleanPropagationBuilder(InvestigationSemanticsRegistry.cadets(), CleanPropagationConfig()).build(edges, cutoff_ns=100)


def test_forward_sphere_recovers_sibling_descendant():
    graph = _graphs((_edge(1, "root", "poi", 10), _edge(2, "root", "sib", 11), _edge(3, "sib", "desc", 12)))
    sphere = ForwardCausalSphereBuilder(ForwardSphereConfig(max_rounds=5)).build(
        "root", graph, OnlineForwardSignals(anchor_ids=frozenset({"poi"}), normalized_relevance={"e3": 1.0}), backward_support=0.8
    )
    assert {"e2", "e3"} <= set(sphere.raw_event_ids)
    assert "desc" in sphere.node_ids


def test_verified_sibling_scores_above_false_sibling():
    graph = _graphs((_edge(1, "root", "false", 10), _edge(2, "root", "good", 11), _edge(3, "good", "terminal", 12)))
    builder = ForwardCausalSphereBuilder(ForwardSphereConfig(max_rounds=3))
    false = builder.build("false", graph, OnlineForwardSignals(), backward_support=0.9)
    good = builder.build("good", graph, OnlineForwardSignals(rare_event_ids=frozenset({"e3"})), backward_support=0.9)
    assert good.verification_score > false.verification_score


def test_useful_chain_can_exceed_fixed_depth_two():
    edges = tuple(_edge(i, f"n{i-1}", f"n{i}", i) for i in range(1, 7))
    sphere = ForwardCausalSphereBuilder(ForwardSphereConfig(max_rounds=8, low_gain_patience=2)).build(
        "n0", _graphs(edges), OnlineForwardSignals(normalized_relevance={f"e{i}": 1.0 for i in range(1, 7)}), backward_support=1.0
    )
    assert len(sphere.raw_event_ids) == 6
    assert sphere.rounds[-1].round_index > 2


def test_harmonic_verification_penalizes_one_sided_support():
    assert harmonic_verification(1.0, 0.01) < harmonic_verification(0.6, 0.6)
    assert harmonic_verification(1.0, 0.0) == 0.0


def test_resource_cap_bounds_hub_expansion():
    edges = tuple(_edge(i, "hub", f"n{i}", i) for i in range(1, 101))
    sphere = ForwardCausalSphereBuilder(ForwardSphereConfig(max_events=7, max_rounds=3)).build(
        "hub", _graphs(edges), OnlineForwardSignals(normalized_relevance={f"e{i}": 1.0 for i in range(1, 101)}), backward_support=1.0
    )
    assert len(sphere.raw_event_ids) == 7
    assert sphere.stop_reason == "RESOURCE_CAP"


def test_detector_anchor_is_a_terminal_not_a_bridge_to_future_noise():
    graph = _graphs((_edge(1, "root", "poi", 10), _edge(2, "poi", "noise", 11)))
    sphere = ForwardCausalSphereBuilder(ForwardSphereConfig(max_rounds=4)).build(
        "root", graph, OnlineForwardSignals(anchor_ids=frozenset({"poi"})), backward_support=1.0
    )
    assert sphere.raw_event_ids == ("e1",)
