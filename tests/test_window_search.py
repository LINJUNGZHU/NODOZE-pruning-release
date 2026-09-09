from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore
from tc_pruning.window_search import (
    InvestigationWindow,
    WindowSearchLimits,
    build_window_context,
    expand_window_context,
)


def _nodes(*names):
    return [NodeRecord(name, "process", name, "h") for name in names]


def test_window_context_streams_union_with_inclusive_boundaries_and_dedup(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b") + [
            EdgeRecord("e0", "a", "b", "R", 9, "h"),
            EdgeRecord("e1", "a", "b", "R", 10, "h"),
            EdgeRecord("e2", "a", "b", "R", 20, "h"),
            EdgeRecord("e3", "a", "b", "R", 30, "h"),
            EdgeRecord("e4", "a", "b", "R", 31, "h"),
        ])
        result = build_window_context(
            store,
            [InvestigationWindow("w1", 10, 20, ("e1",)),
             InvestigationWindow("w2", 20, 30, ("e3",))],
            WindowSearchLimits(page_size=1, max_candidate_events=100),
        )

    assert {edge.event_id for edge in result.graph.edges} == {"e1", "e2", "e3"}
    assert result.diagnostics.queried_event_count == 3
    assert result.diagnostics.unique_candidate_event_count == 3
    assert result.diagnostics.pages_read == 3
    assert result.diagnostics.incomplete is False


def test_window_context_resource_limit_returns_explicit_partial_result(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b") + [
            EdgeRecord(f"e{i}", "a", "b", "R", i, "h") for i in range(5)
        ])
        result = build_window_context(
            store, [InvestigationWindow("w", 0, 4, ())],
            WindowSearchLimits(page_size=2, max_candidate_events=3),
        )

    assert len(result.graph.edges) == 3
    assert result.diagnostics.incomplete is True
    assert result.diagnostics.truncation_reason == "candidate_event_limit"


def test_multisource_expansion_reuses_duplicate_alert_state(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b", "c") + [
            EdgeRecord("a1", "a", "b", "ALERT", 10, "h"),
            EdgeRecord("a2", "a", "b", "ALERT", 10, "h"),
            EdgeRecord("tail", "b", "c", "SEND", 11, "h"),
        ])
        base = build_window_context(
            store, [InvestigationWindow("w", 10, 10, ("a1", "a2"))]
        )
        result = expand_window_context(
            store, base, [InvestigationWindow("w", 10, 10, ("a1", "a2"))],
            direction="forward",
            limits=WindowSearchLimits(max_candidate_events=100),
            completion_span_seconds=1,
        )

    assert {edge.event_id for edge in result.graph.edges} == {"a1", "a2", "tail"}
    assert result.diagnostics.expanded_state_count == 2
    assert result.diagnostics.reused_state_count >= 1


def test_multisource_expansion_keeps_earlier_time_state_that_covers_later(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("x", "a", "b", "c") + [
            EdgeRecord("early", "x", "b", "ALERT", 10, "h"),
            EdgeRecord("middle", "b", "c", "SEND", 15, "h"),
            EdgeRecord("late", "a", "b", "ALERT", 20, "h"),
        ])
        windows = [InvestigationWindow("w", 10, 20, ("late", "early"))]
        base = build_window_context(store, windows)
        result = expand_window_context(
            store, base, windows, direction="forward",
            limits=WindowSearchLimits(max_candidate_events=100),
            completion_span_seconds=1,
        )

    assert "middle" in {edge.event_id for edge in result.graph.edges}
    assert result.diagnostics.reused_state_count >= 1


def test_multisource_resource_stop_marks_partial_and_pending_states(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b", "c", "d") + [
            EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
            EdgeRecord("one", "b", "c", "R", 11, "h"),
            EdgeRecord("two", "c", "d", "R", 12, "h"),
        ])
        windows = [InvestigationWindow("w", 10, 10, ("alert",))]
        base = build_window_context(store, windows)
        result = expand_window_context(
            store, base, windows, direction="forward",
            limits=WindowSearchLimits(max_candidate_events=100),
            completion_span_seconds=1, max_states=1,
        )

    assert result.diagnostics.incomplete is True
    assert result.diagnostics.truncation_reason == "state_limit"
    assert result.diagnostics.pending_state_count > 0


def test_fixed_block_cache_preserves_exact_causal_boundary(tmp_path):
    second = 1_000_000_000
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b", "c") + [
            EdgeRecord("alert", "a", "b", "ALERT", 59 * second, "h"),
            EdgeRecord("boundary", "b", "c", "SEND", 60 * second, "h"),
        ])
        windows = [InvestigationWindow("w", 59 * second, 59 * second, ("alert",))]
        result = expand_window_context(
            store, build_window_context(store, windows), windows,
            direction="forward", completion_span_seconds=2, block_seconds=60,
        )

    assert "boundary" in {edge.event_id for edge in result.graph.edges}


def test_complete_multisource_equals_union_of_complete_single_sources(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_nodes("a", "b", "c", "d", "e") + [
            EdgeRecord("left", "a", "b", "ALERT", 10, "h"),
            EdgeRecord("right", "d", "c", "ALERT", 10, "h"),
            EdgeRecord("bc", "b", "c", "R", 11, "h"),
            EdgeRecord("ce", "c", "e", "R", 12, "h"),
        ])
        both = [InvestigationWindow("both", 10, 10, ("left", "right"))]
        multi = expand_window_context(
            store, build_window_context(store, both), both,
            completion_span_seconds=1, max_states=100,
        )
        singles = []
        for event_id in ("left", "right"):
            windows = [InvestigationWindow(event_id, 10, 10, (event_id,))]
            singles.append(expand_window_context(
                store, build_window_context(store, windows), windows,
                completion_span_seconds=1, max_states=100,
            ))

    expected = {edge.event_id for result in singles for edge in result.graph.edges}
    assert {edge.event_id for edge in multi.graph.edges} == expected
    assert multi.diagnostics.incomplete is False
