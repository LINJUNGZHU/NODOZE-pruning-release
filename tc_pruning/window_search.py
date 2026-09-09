from __future__ import annotations

from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import heapq
import itertools
import time
from typing import Iterable

import psutil

from .models import Neighborhood, StoredEdge
from .store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class InvestigationWindow:
    group_id: str
    start_ns: int
    end_ns: int
    alert_event_ids: tuple[str, ...] = ()
    anomaly_score: float | None = None


@dataclass(frozen=True, slots=True)
class WindowSearchLimits:
    page_size: int = 5000
    max_candidate_events: int = 250_000
    timeout_seconds: float = 120.0
    memory_limit_mb: float = 4096.0
    cache_max_blocks: int = 256


@dataclass(slots=True)
class WindowSearchDiagnostics:
    mode: str = "window_context"
    window_count: int = 0
    alert_count: int = 0
    processed_window_count: int = 0
    queried_event_count: int = 0
    unique_candidate_event_count: int = 0
    pages_read: int = 0
    database_query_seconds: float = 0.0
    baseline_rss_mb: float = 0.0
    peak_rss_mb: float = 0.0
    elapsed_seconds: float = 0.0
    incomplete: bool = False
    truncation_reason: str | None = None
    pending_state_count: int = 0
    enqueued_state_count: int = 0
    expanded_state_count: int = 0
    reused_state_count: int = 0
    cache_hits: int = 0
    cache_size: int = 0
    complete_path_count: int = 0
    truncated_path_count: int = 0
    termination_reasons: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class WindowSearchResult:
    graph: Neighborhood
    diagnostics: WindowSearchDiagnostics
    window_event_counts: dict[str, int] = field(default_factory=dict)


def parse_kairos_window(
    value: str, *, utc_offset_hours: float = -4.0
) -> tuple[int, int]:
    text = value.removesuffix(".txt")
    parts = text.split("~")
    if len(parts) != 2:
        raise ValueError(f"invalid KAIROS window: {value}")
    zone = timezone(timedelta(hours=utc_offset_hours))

    def parse(item: str) -> int:
        base, _, fraction = item.partition(".")
        instant = datetime.strptime(base, "%Y-%m-%d %H:%M:%S").replace(tzinfo=zone)
        nanos = int((fraction + "000000000")[:9])
        return int(instant.timestamp()) * 1_000_000_000 + nanos

    return parse(parts[0]), parse(parts[1])


def _merge_ranges(windows: Iterable[InvestigationWindow]) -> list[tuple[int, int, list[str]]]:
    ordered = sorted(windows, key=lambda item: (item.start_ns, item.end_ns, item.group_id))
    result: list[tuple[int, int, list[str]]] = []
    for window in ordered:
        if window.start_ns > window.end_ns:
            raise ValueError(f"invalid investigation window {window.group_id}")
        if result and window.start_ns <= result[-1][1]:
            start, end, ids = result[-1]
            result[-1] = (start, max(end, window.end_ns), ids + [window.group_id])
        else:
            result.append((window.start_ns, window.end_ns, [window.group_id]))
    return result


def build_window_context(
    store: ProvenanceStore,
    windows: list[InvestigationWindow],
    limits: WindowSearchLimits | None = None,
) -> WindowSearchResult:
    """Stream the union of raw events in alert windows without causal expansion."""
    limits = limits or WindowSearchLimits()
    process = psutil.Process()
    baseline = process.memory_info().rss / (1024 * 1024)
    diagnostics = WindowSearchDiagnostics(
        window_count=len(windows),
        alert_count=len({event for window in windows for event in window.alert_event_ids}),
        baseline_rss_mb=baseline,
        peak_rss_mb=baseline,
    )
    started = time.perf_counter()
    selected: dict[int, StoredEdge] = {}
    counts = {window.group_id: 0 for window in windows}
    try:
        for lower, upper, group_ids in _merge_ranges(windows):
            query_started = time.perf_counter()
            for page in store.iter_edges_by_time(lower, upper, page_size=limits.page_size):
                diagnostics.database_query_seconds += time.perf_counter() - query_started
                diagnostics.pages_read += 1
                diagnostics.queried_event_count += len(page)
                for edge in page:
                    if edge.edge_id not in selected:
                        if len(selected) >= limits.max_candidate_events:
                            diagnostics.incomplete = True
                            diagnostics.truncation_reason = "candidate_event_limit"
                            diagnostics.truncated_path_count = 1
                            diagnostics.termination_reasons["candidate_event_limit"] = 1
                            break
                        selected[edge.edge_id] = edge
                    for window in windows:
                        if window.start_ns <= edge.timestamp_ns <= window.end_ns:
                            counts[window.group_id] += 1
                rss = process.memory_info().rss / (1024 * 1024)
                diagnostics.peak_rss_mb = max(diagnostics.peak_rss_mb, rss)
                if diagnostics.incomplete:
                    break
                if rss - baseline >= limits.memory_limit_mb:
                    diagnostics.incomplete = True
                    diagnostics.truncation_reason = "memory_limit"
                    diagnostics.truncated_path_count = 1
                    diagnostics.termination_reasons["memory_limit"] = 1
                    break
                if time.perf_counter() - started >= limits.timeout_seconds:
                    diagnostics.incomplete = True
                    diagnostics.truncation_reason = "timeout_limit"
                    diagnostics.truncated_path_count = 1
                    diagnostics.termination_reasons["timeout_limit"] = 1
                    break
                query_started = time.perf_counter()
            diagnostics.processed_window_count += len(group_ids)
            if diagnostics.incomplete:
                break
    except KeyboardInterrupt:
        diagnostics.incomplete = True
        diagnostics.truncation_reason = "keyboard_interrupt"
        diagnostics.truncated_path_count = 1
        diagnostics.termination_reasons["keyboard_interrupt"] = 1
    diagnostics.unique_candidate_event_count = len(selected)
    diagnostics.elapsed_seconds = time.perf_counter() - started
    return WindowSearchResult(
        graph=store.neighborhood_from_edges(selected.values()),
        diagnostics=diagnostics,
        window_event_counts=counts,
    )


class _BlockCache:
    def __init__(
        self, store: ProvenanceStore, block_ns: int, capacity: int
    ) -> None:
        self.store = store
        self.block_ns = block_ns
        self.capacity = capacity
        self.values: OrderedDict[tuple[str, str, int], list[StoredEdge]] = OrderedDict()
        self.hits = 0
        self.queries = 0
        self.query_seconds = 0.0

    def get(self, node: str, direction: str, block: int) -> list[StoredEdge]:
        key = (node, direction, block)
        if key in self.values:
            self.hits += 1
            self.values.move_to_end(key)
            return self.values[key]
        lower = block * self.block_ns
        upper = lower + self.block_ns - 1
        started = time.perf_counter()
        value = self.store.get_directional_edges(
            node, direction=direction,
            minimum_time_ns=lower, maximum_time_ns=upper,
        )
        self.query_seconds += time.perf_counter() - started
        self.queries += 1
        self.values[key] = value
        if len(self.values) > self.capacity:
            self.values.popitem(last=False)
        return value


def expand_window_context(
    store: ProvenanceStore,
    base: WindowSearchResult,
    windows: list[InvestigationWindow],
    *,
    direction: str = "forward",
    limits: WindowSearchLimits | None = None,
    completion_span_seconds: float = 900.0,
    block_seconds: float = 60.0,
    max_states: int = 100_000,
) -> WindowSearchResult:
    """Perform one bounded shared-state multi-source causal completion."""
    if direction not in {"forward", "backward"}:
        raise ValueError("direction must be forward or backward")
    limits = limits or WindowSearchLimits()
    started = time.perf_counter()
    process = psutil.Process()
    baseline = process.memory_info().rss / (1024 * 1024)
    selected = {edge.edge_id: edge for edge in base.graph.edges}
    alerts = []
    for window in windows:
        for event_id in window.alert_event_ids:
            edge = store.get_edge_by_event_id(event_id)
            if edge is not None:
                alerts.append(edge)
                selected[edge.edge_id] = edge
    diagnostics = WindowSearchDiagnostics(
        mode="window_context_expand",
        window_count=len(windows),
        alert_count=len({edge.event_id for edge in alerts}),
        processed_window_count=len(windows),
        queried_event_count=base.diagnostics.queried_event_count,
        pages_read=base.diagnostics.pages_read,
        baseline_rss_mb=base.diagnostics.baseline_rss_mb or baseline,
        peak_rss_mb=max(base.diagnostics.peak_rss_mb, baseline),
        incomplete=base.diagnostics.incomplete,
        truncation_reason=base.diagnostics.truncation_reason,
        enqueued_state_count=base.diagnostics.enqueued_state_count,
        expanded_state_count=base.diagnostics.expanded_state_count,
        reused_state_count=base.diagnostics.reused_state_count,
        cache_hits=base.diagnostics.cache_hits,
        complete_path_count=base.diagnostics.complete_path_count,
        truncated_path_count=base.diagnostics.truncated_path_count,
        termination_reasons=dict(base.diagnostics.termination_reasons),
    )
    if diagnostics.incomplete or not alerts:
        diagnostics.unique_candidate_event_count = len(selected)
        return WindowSearchResult(
            store.neighborhood_from_edges(selected.values()), diagnostics,
            dict(base.window_event_counts),
        )
    block_ns = max(1, int(block_seconds * 1_000_000_000))
    span_ns = max(0, int(completion_span_seconds * 1_000_000_000))
    lower_bound = min(window.start_ns for window in windows) - span_ns
    upper_bound = max(window.end_ns for window in windows) + span_ns
    cache = _BlockCache(store, block_ns, limits.cache_max_blocks)
    sequence = itertools.count()
    queue = []
    for edge in alerts:
        node = edge.dst if direction == "forward" else edge.src
        priority = edge.timestamp_ns if direction == "forward" else -edge.timestamp_ns
        heapq.heappush(queue, (priority, next(sequence), node, edge.timestamp_ns))
        diagnostics.enqueued_state_count += 1
    coverage: dict[str, int] = {}
    try:
        while queue:
            expansion_states = diagnostics.expanded_state_count - base.diagnostics.expanded_state_count
            if expansion_states >= max_states:
                diagnostics.incomplete = True
                diagnostics.truncation_reason = "state_limit"
                diagnostics.truncated_path_count = 1
                diagnostics.termination_reasons["state_limit"] = 1
                break
            _, _, node, anchor = heapq.heappop(queue)
            prior = coverage.get(node)
            covered = prior is not None and (
                prior <= anchor if direction == "forward" else prior >= anchor
            )
            if covered:
                diagnostics.reused_state_count += 1
                continue
            coverage[node] = anchor
            diagnostics.expanded_state_count += 1
            first_block = anchor // block_ns
            last_time = upper_bound if direction == "forward" else lower_bound
            last_block = last_time // block_ns
            blocks = (
                range(first_block, last_block + 1)
                if direction == "forward"
                else range(first_block, last_block - 1, -1)
            )
            for block in blocks:
                for edge in cache.get(node, direction, block):
                    legal = (
                        anchor <= edge.timestamp_ns <= upper_bound
                        if direction == "forward"
                        else lower_bound <= edge.timestamp_ns <= anchor
                    )
                    if not legal:
                        continue
                    if edge.edge_id not in selected:
                        if len(selected) >= limits.max_candidate_events:
                            diagnostics.incomplete = True
                            diagnostics.truncation_reason = "candidate_event_limit"
                            diagnostics.truncated_path_count = 1
                            diagnostics.termination_reasons["candidate_event_limit"] = 1
                            break
                        selected[edge.edge_id] = edge
                    neighbor = edge.dst if direction == "forward" else edge.src
                    priority = edge.timestamp_ns if direction == "forward" else -edge.timestamp_ns
                    heapq.heappush(
                        queue, (priority, next(sequence), neighbor, edge.timestamp_ns)
                    )
                    diagnostics.enqueued_state_count += 1
                if diagnostics.incomplete:
                    break
            rss = process.memory_info().rss / (1024 * 1024)
            diagnostics.peak_rss_mb = max(diagnostics.peak_rss_mb, rss)
            if not diagnostics.incomplete and rss - baseline >= limits.memory_limit_mb:
                diagnostics.incomplete = True
                diagnostics.truncation_reason = "memory_limit"
                diagnostics.truncated_path_count = 1
                diagnostics.termination_reasons["memory_limit"] = 1
            if not diagnostics.incomplete and time.perf_counter() - started >= limits.timeout_seconds:
                diagnostics.incomplete = True
                diagnostics.truncation_reason = "timeout_limit"
                diagnostics.truncated_path_count = 1
                diagnostics.termination_reasons["timeout_limit"] = 1
            if diagnostics.incomplete:
                break
    except KeyboardInterrupt:
        diagnostics.incomplete = True
        diagnostics.truncation_reason = "keyboard_interrupt"
        diagnostics.truncated_path_count = 1
        diagnostics.termination_reasons["keyboard_interrupt"] = 1
    diagnostics.pending_state_count = len(queue)
    diagnostics.unique_candidate_event_count = len(selected)
    diagnostics.cache_hits += cache.hits
    diagnostics.cache_size = len(cache.values)
    diagnostics.database_query_seconds = (
        base.diagnostics.database_query_seconds + cache.query_seconds
    )
    diagnostics.elapsed_seconds = base.diagnostics.elapsed_seconds + time.perf_counter() - started
    return WindowSearchResult(
        store.neighborhood_from_edges(selected.values()), diagnostics,
        dict(base.window_event_counts),
    )


__all__ = [
    "InvestigationWindow", "WindowSearchDiagnostics", "WindowSearchLimits",
    "WindowSearchResult", "build_window_context",
    "expand_window_context",
    "parse_kairos_window",
]
