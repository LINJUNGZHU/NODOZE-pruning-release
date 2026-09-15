"""Detector-neutral, label-free reconstruction from immutable alert evidence."""
from __future__ import annotations

from dataclasses import dataclass
import heapq
import resource
import time
from typing import Iterable

from .detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from .models import StoredEdge
from .store import ProvenanceStore

_RESOURCE = frozenset({"file", "socket", "netflow", "memory", "unknown"})
_PROCESS = frozenset({"process", "subject"})
_READ = frozenset({"EVENT_READ", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_MMAP", "EVENT_LOADLIBRARY", "EVENT_READ_SOCKET_PARAMS"})
_WRITE = frozenset({"EVENT_WRITE", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_CONNECT", "EVENT_CREATE_OBJECT", "EVENT_TRUNCATE", "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_RENAME", "EVENT_LINK", "EVENT_UNLINK"})
_CONTROL = frozenset({"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"})
_MIN_TIME, _MAX_TIME = -(2**63), 2**63 - 1


@dataclass(frozen=True, slots=True)
class CandidateSearchConfig:
    candidate_cap: int = 10_000
    history_start_ns: int | None = None
    cutoff_ns: int | None = None
    max_strict_depth: int = 8
    max_control_depth: int = 0
    enable_common_cause: bool = False
    scan_multiplier: int = 20

    def __post_init__(self) -> None:
        if self.candidate_cap <= 0 or self.scan_multiplier <= 0:
            raise ValueError("candidate cap and scan multiplier must be positive")
        if self.max_strict_depth < 0 or self.max_control_depth < 0:
            raise ValueError("search depths must be non-negative")
        if self.history_start_ns is not None and self.cutoff_ns is not None and self.history_start_ns > self.cutoff_ns:
            raise ValueError("history_start_ns cannot exceed cutoff_ns")


@dataclass(frozen=True, slots=True)
class CandidatePerformance:
    elapsed_seconds: float
    peak_rss_kb: int
    frontiers_seen: int
    store_edge_queries: int
    unexpanded_anchor_count: int = 0
    unexpanded_anchor_reason: str | None = None
    control_witness_count: int = 0


@dataclass(frozen=True, slots=True)
class CandidateResult:
    edges: tuple[StoredEdge, ...]
    node_ids: frozenset[str]
    event_ids: frozenset[str]
    anchor_event_ids: frozenset[str]
    anchor_node_ids: frozenset[str]
    soft_seed_node_ids: frozenset[str]
    stop_reason: str
    performance: CandidatePerformance


@dataclass(frozen=True, slots=True)
class _Frontier:
    node_id: str
    direction: str
    lower_time_ns: int
    upper_time_ns: int
    depth: int
    score: float
    identity: tuple[object, ...]


class EvidenceDrivenCandidateBuilder:
    """Search the full store without inspecting detector-specific identity fields."""

    def __init__(self, store: ProvenanceStore, config: CandidateSearchConfig) -> None:
        self.store, self.config = store, config

    def build(self, evidence: Iterable[AlertEvidence]) -> CandidateResult:
        started = time.perf_counter()
        before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        candidates: dict[int, StoredEdge] = {}
        nodes: set[str] = set()
        anchor_events: set[str] = set()
        anchor_nodes: set[str] = set()
        soft_nodes: set[str] = set()
        queue: list[tuple[float, tuple[object, ...], int, _Frontier]] = []
        serial = queries = unexpanded = 0
        cap_reached = False
        seen: set[tuple[object, ...]] = set()
        control: list[tuple[str, int, int, int]] = []

        def add(edge: StoredEdge) -> bool:
            nonlocal cap_reached
            if edge.edge_id not in candidates and len(candidates) >= self.config.candidate_cap:
                cap_reached = True
                return False
            candidates[edge.edge_id] = edge
            nodes.update((edge.src, edge.dst))
            if len(candidates) == self.config.candidate_cap:
                cap_reached = True
            return True

        def enqueue(frontier: _Frontier) -> None:
            nonlocal serial
            heapq.heappush(queue, (-frontier.score, frontier.identity, serial, frontier))
            serial += 1

        for item in sorted(evidence, key=lambda row: (-row.calibrated_score, self._identity(row))):
            identity, directions = self._identity(item), self._directions(item.role_hint)
            soft = item.granularity in {EvidenceGranularity.SUBGRAPH, EvidenceGranularity.PATH, EvidenceGranularity.STRUCTURAL_GRAPH}
            event_edges = [edge for event_id in item.event_ids if (edge := self.store.get_edge_by_event_id(event_id)) is not None]
            for edge in event_edges:
                anchor_events.add(edge.event_id)
                add(edge)
                for node in self._anchor_endpoints(edge):
                    anchor_nodes.add(node)
                    nodes.add(node)
                    if soft:
                        soft_nodes.add(node)
                    for direction in directions:
                        lower, upper = self._bounds(direction, edge.timestamp_ns, edge.timestamp_ns)
                        enqueue(_Frontier(node, direction, lower, upper, 0, item.calibrated_score, identity + (edge.event_id,)))
            event_members = {node for edge in event_edges for node in self._anchor_endpoints(edge)}
            extra = {item.src_uuid, item.dst_uuid} if item.granularity is EvidenceGranularity.EDGE else set()
            for node in sorted(set(item.node_ids) | extra):
                if node is None or node in event_members:
                    continue
                anchor_nodes.add(node)
                nodes.add(node)
                if soft:
                    soft_nodes.add(node)
                if item.timestamp_start is None and item.timestamp_end is None and not self._has_common_window:
                    unexpanded += 1
                    continue
                for direction in directions:
                    lower, upper = self._bounds(direction, item.timestamp_start, item.timestamp_end)
                    enqueue(_Frontier(node, direction, lower, upper, 0, item.calibrated_score, identity + (node,)))

        while queue and not cap_reached:
            _, _, _, frontier = heapq.heappop(queue)
            key = (frontier.node_id, frontier.direction, frontier.lower_time_ns, frontier.upper_time_ns, frontier.depth)
            if key in seen:
                continue
            seen.add(key)
            if frontier.depth >= self.config.max_strict_depth:
                continue
            found, used = self._strict_neighbors(frontier)
            queries += used
            for edge in found:
                if not add(edge):
                    break
                source, target = self._causal_endpoints(edge)
                next_node = source if frontier.direction == "backward" else target
                lower, upper = (frontier.lower_time_ns, edge.timestamp_ns) if frontier.direction == "backward" else (edge.timestamp_ns, frontier.upper_time_ns)
                enqueue(_Frontier(next_node, frontier.direction, lower, upper, frontier.depth + 1, frontier.score, frontier.identity))
                if self._node_is_process(next_node):
                    control.append((next_node, lower, upper, frontier.depth + 1))
            if frontier.direction == "backward" and self._node_is_process(frontier.node_id):
                control.append((frontier.node_id, frontier.lower_time_ns, frontier.upper_time_ns, frontier.depth))

        control_queries = control_witnesses = 0
        if not cap_reached and self.config.max_control_depth:
            control_queries, control_witnesses = self._add_control_context(candidates, nodes, control)
            queries += control_queries
            cap_reached = len(candidates) >= self.config.candidate_cap
        ordered = tuple(candidates[key] for key in sorted(candidates))
        return CandidateResult(
            ordered, frozenset(nodes), frozenset(edge.event_id for edge in ordered), frozenset(anchor_events), frozenset(anchor_nodes), frozenset(soft_nodes),
            "CAP_REACHED" if cap_reached else "FRONTIER_EXHAUSTED",
            CandidatePerformance(time.perf_counter() - started, int(max(before_rss, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)), len(seen), queries, unexpanded, "MISSING_TIME_CHECKPOINT" if unexpanded else None, control_witnesses),
        )

    @property
    def _has_common_window(self) -> bool:
        return self.config.history_start_ns is not None and self.config.cutoff_ns is not None

    def build_legacy(self, *, event_ids: Iterable[str] = (), node_ids: Iterable[str] = ()) -> CandidateResult:
        events = [AlertEvidence(f"legacy-event-{n}", "legacy", "1", EvidenceGranularity.EVENT, None, 0.0, True, event_ids=(event_id,), role_hint=RoleHint.UNKNOWN) for n, event_id in enumerate(sorted(set(event_ids)))]
        nodes = [AlertEvidence(f"legacy-node-{n}", "legacy", "1", EvidenceGranularity.NODE, None, 0.0, True, node_ids=(node_id,), role_hint=RoleHint.UNKNOWN) for n, node_id in enumerate(sorted(set(node_ids)))]
        return self.build(events + nodes)

    @staticmethod
    def _identity(item: AlertEvidence) -> tuple[object, ...]:
        return (item.granularity.value, item.event_ids, item.node_ids, item.supporting_event_ids, item.timestamp_start, item.timestamp_end, item.src_uuid, item.dst_uuid, item.relation, item.role_hint.value)

    @staticmethod
    def _directions(role: RoleHint) -> tuple[str, ...]:
        if role in {RoleHint.ROOT, RoleHint.ENTRY}:
            return ("forward",)
        if role in {RoleHint.EXIT, RoleHint.TERMINAL}:
            return ("backward",)
        return ("backward", "forward")

    def _bounds(self, direction: str, start: int | None, end: int | None) -> tuple[int, int]:
        lower = self.config.history_start_ns if self.config.history_start_ns is not None else _MIN_TIME
        upper = self.config.cutoff_ns if self.config.cutoff_ns is not None else _MAX_TIME
        if direction == "backward" and start is not None:
            upper = min(upper, start)
        if direction == "forward" and end is not None:
            lower = max(lower, end)
        return lower, upper

    def _node_is_process(self, node_id: str) -> bool:
        node = self.store.get_node(node_id)
        return node is not None and node.node_type.lower() in _PROCESS

    @classmethod
    def _causal_endpoints(cls, edge: StoredEdge) -> tuple[str, str]:
        relation, src, dst = edge.relation.upper(), edge.src_type.lower(), edge.dst_type.lower()
        if relation in _READ and src in _RESOURCE and dst in _PROCESS:
            return edge.src, edge.dst
        if relation in _WRITE and src in _PROCESS and dst in _RESOURCE:
            return edge.src, edge.dst
        if relation == "EVENT_EXECUTE" and src in _PROCESS and dst in _RESOURCE:
            return edge.dst, edge.src
        if relation in _CONTROL and src in _PROCESS and dst in _PROCESS:
            return edge.src, edge.dst
        raise ValueError("relation or endpoint types are not in the strict CADETS causal view")

    @classmethod
    def _anchor_endpoints(cls, edge: StoredEdge) -> tuple[str, str]:
        try:
            return cls._causal_endpoints(edge)
        except ValueError:
            return edge.src, edge.dst

    def _strict_neighbors(self, frontier: _Frontier) -> tuple[tuple[StoredEdge, ...], int]:
        raw: dict[int, StoredEdge] = {}
        for direction in ("backward", "forward"):
            for edge in self.store.get_directional_edges(frontier.node_id, direction=direction, minimum_time_ns=frontier.lower_time_ns, maximum_time_ns=frontier.upper_time_ns, scan_limit=self.config.candidate_cap * self.config.scan_multiplier):
                raw[edge.edge_id] = edge
        result = []
        for edge in raw.values():
            if not frontier.lower_time_ns < edge.timestamp_ns < frontier.upper_time_ns:
                continue
            try:
                source, target = self._causal_endpoints(edge)
            except ValueError:
                continue
            if (frontier.direction == "backward" and target == frontier.node_id) or (frontier.direction == "forward" and source == frontier.node_id):
                result.append(edge)
        return tuple(sorted(result, key=lambda edge: (edge.timestamp_ns, edge.edge_id), reverse=frontier.direction == "backward")), 2

    def _add_control_context(self, candidates: dict[int, StoredEdge], nodes: set[str], initial: list[tuple[str, int, int, int]]) -> tuple[int, int]:
        queue = [(node, lower, upper, depth, 0) for node, lower, upper, depth in initial]
        seen: set[tuple[str, int, int, int]] = set()
        queries = witnesses = 0
        branches: list[tuple[str, StoredEdge, int, int]] = []
        while queue and len(candidates) < self.config.candidate_cap:
            child, lower, upper, strict_depth, control_depth = queue.pop(0)
            state = (child, lower, upper, control_depth)
            if state in seen or control_depth >= self.config.max_control_depth:
                continue
            seen.add(state)
            queries += 1
            for edge in self.store.get_directional_edges(child, direction="backward", minimum_time_ns=lower, maximum_time_ns=upper, scan_limit=self.config.candidate_cap * self.config.scan_multiplier):
                if not lower < edge.timestamp_ns < upper:
                    continue
                try:
                    parent, target = self._causal_endpoints(edge)
                except ValueError:
                    continue
                if edge.relation.upper() not in _CONTROL or target != child:
                    continue
                if edge.edge_id not in candidates:
                    candidates[edge.edge_id] = edge
                    nodes.update((edge.src, edge.dst))
                    witnesses += 1
                queue.append((parent, lower, edge.timestamp_ns, strict_depth, control_depth + 1))
                branches.append((parent, edge, lower, upper))
                # A validated control parent is a bounded context anchor. Continue
                # strict reconstruction only through the depth that remains.
                if strict_depth < self.config.max_strict_depth:
                    continued, continued_queries = self._strict_neighbors(_Frontier(
                        parent, "forward", edge.timestamp_ns, upper, strict_depth,
                        0.0, ("control", parent, edge.event_id),
                    ))
                    queries += continued_queries
                    for strict_edge in continued:
                        if strict_edge.edge_id not in candidates:
                            candidates[strict_edge.edge_id] = strict_edge
                            nodes.update((strict_edge.src, strict_edge.dst))
                            witnesses += 1
                        if len(candidates) >= self.config.candidate_cap:
                            break
                if len(candidates) >= self.config.candidate_cap:
                    break
        if self.config.enable_common_cause:
            for parent, branch, lower, upper in branches:
                if len(candidates) >= self.config.candidate_cap:
                    break
                queries += 1
                for edge in self.store.get_directional_edges(parent, direction="forward", minimum_time_ns=lower, maximum_time_ns=upper, scan_limit=self.config.candidate_cap * self.config.scan_multiplier):
                    if not lower < edge.timestamp_ns < upper or edge.event_id == branch.event_id:
                        continue
                    try:
                        source, target = self._causal_endpoints(edge)
                    except ValueError:
                        continue
                    if edge.relation.upper() in _CONTROL and source == parent:
                        if edge.edge_id not in candidates:
                            candidates[edge.edge_id] = edge
                            nodes.update((edge.src, edge.dst))
                            witnesses += 1
                    if len(candidates) >= self.config.candidate_cap:
                        break
        return queries, witnesses


__all__ = ["CandidatePerformance", "CandidateResult", "CandidateSearchConfig", "EvidenceDrivenCandidateBuilder"]
