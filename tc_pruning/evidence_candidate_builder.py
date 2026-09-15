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


_FORWARD_RELATIONS = frozenset({
    "EVENT_READ", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT", "EVENT_MMAP",
    "EVENT_LOADLIBRARY", "EVENT_READ_SOCKET_PARAMS", "EVENT_WRITE", "EVENT_SENDTO",
    "EVENT_SENDMSG", "EVENT_CONNECT", "EVENT_CREATE_OBJECT", "EVENT_TRUNCATE",
    "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_RENAME", "EVENT_LINK", "EVENT_UNLINK",
    "EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE",
})
_REVERSED_RELATIONS = frozenset({"EVENT_EXECUTE"})
_CONTROL_RELATIONS = frozenset({"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"})
_MIN_TIME = -(2**63)
_MAX_TIME = 2**63 - 1


@dataclass(frozen=True, slots=True)
class CandidateSearchConfig:
    """The shared online search policy; scores never appear as a threshold here."""

    candidate_cap: int = 10_000
    history_start_ns: int | None = None
    cutoff_ns: int | None = None
    max_strict_depth: int = 8
    max_control_depth: int = 0
    enable_common_cause: bool = False
    scan_multiplier: int = 20

    def __post_init__(self) -> None:
        if self.candidate_cap <= 0:
            raise ValueError("candidate_cap must be positive")
        if self.max_strict_depth < 0 or self.max_control_depth < 0:
            raise ValueError("search depths must be non-negative")
        if self.scan_multiplier <= 0:
            raise ValueError("scan_multiplier must be positive")
        if (
            self.history_start_ns is not None and self.cutoff_ns is not None
            and self.history_start_ns > self.cutoff_ns
        ):
            raise ValueError("history_start_ns cannot exceed cutoff_ns")


@dataclass(frozen=True, slots=True)
class CandidatePerformance:
    elapsed_seconds: float
    peak_rss_kb: int
    frontiers_seen: int
    store_edge_queries: int


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
    evidence_id: str


class EvidenceDrivenCandidateBuilder:
    """Reconstruct on the full store without reading detector identity or labels."""

    def __init__(self, store: ProvenanceStore, config: CandidateSearchConfig) -> None:
        self.store = store
        self.config = config

    def build(self, evidence: Iterable[AlertEvidence]) -> CandidateResult:
        started = time.perf_counter()
        before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        candidates: dict[int, StoredEdge] = {}
        nodes: set[str] = set()
        anchor_events: set[str] = set()
        anchor_nodes: set[str] = set()
        soft_nodes: set[str] = set()
        frontier_heap: list[tuple[float, str, int, _Frontier]] = []
        frontier_serial = 0
        frontiers_seen = 0
        store_queries = 0
        cap_reached = False
        control_anchors: set[str] = set()

        def add_edge(edge: StoredEdge) -> bool:
            nonlocal cap_reached
            if edge.edge_id not in candidates and len(candidates) >= self.config.candidate_cap:
                cap_reached = True
                return False
            candidates[edge.edge_id] = edge
            nodes.update((edge.src, edge.dst))
            if len(candidates) >= self.config.candidate_cap:
                cap_reached = True
            return True

        def enqueue(frontier: _Frontier) -> None:
            nonlocal frontier_serial
            # The score is deliberately only a deterministic scheduling priority.
            heapq.heappush(frontier_heap, (-frontier.score, frontier.evidence_id, frontier_serial, frontier))
            frontier_serial += 1

        for item in sorted(evidence, key=lambda row: (-row.calibrated_score, row.evidence_id)):
            directions = self._directions(item.role_hint)
            soft = item.granularity in {
                EvidenceGranularity.SUBGRAPH, EvidenceGranularity.PATH, EvidenceGranularity.STRUCTURAL_GRAPH,
            }
            event_edges: list[StoredEdge] = []
            for event_id in item.event_ids:
                edge = self.store.get_edge_by_event_id(event_id)
                if edge is not None:
                    event_edges.append(edge)
                    anchor_events.add(edge.event_id)
                    add_edge(edge)
            member_nodes = set(item.node_ids)
            for edge in event_edges:
                source, target = self._anchor_endpoints(edge)
                member_nodes.update((source, target))
            if item.granularity is EvidenceGranularity.EDGE:
                member_nodes.update(value for value in (item.src_uuid, item.dst_uuid) if value is not None)
            for node_id in sorted(member_nodes):
                anchor_nodes.add(node_id)
                nodes.add(node_id)
                if soft:
                    soft_nodes.add(node_id)
                if self.store.get_node(node_id) is not None:
                    control_anchors.add(node_id)
                anchor_time = self._anchor_time(item, event_edges)
                for direction in directions:
                    lower, upper = self._bounds(direction, anchor_time)
                    enqueue(_Frontier(node_id, direction, lower, upper, 0, item.calibrated_score, item.evidence_id))

        seen: set[tuple[str, str, int, int, int]] = set()
        while frontier_heap and not cap_reached:
            _, _, _, frontier = heapq.heappop(frontier_heap)
            key = (frontier.node_id, frontier.direction, frontier.lower_time_ns, frontier.upper_time_ns, frontier.depth)
            if key in seen:
                continue
            seen.add(key)
            frontiers_seen += 1
            if frontier.depth >= self.config.max_strict_depth:
                continue
            neighbors, query_count = self._strict_neighbors(frontier)
            store_queries += query_count
            for edge in neighbors:
                if not add_edge(edge):
                    break
                source, target = self._causal_endpoints(edge)
                next_node = source if frontier.direction == "backward" else target
                if frontier.direction == "backward":
                    lower, upper = frontier.lower_time_ns, edge.timestamp_ns
                else:
                    lower, upper = edge.timestamp_ns, frontier.upper_time_ns
                enqueue(_Frontier(
                    next_node, frontier.direction, lower, upper, frontier.depth + 1,
                    frontier.score, frontier.evidence_id,
                ))

        if not cap_reached and self.config.max_control_depth:
            control_queries = self._add_control_context(candidates, nodes, control_anchors)
            store_queries += control_queries
            if len(candidates) >= self.config.candidate_cap:
                cap_reached = True

        elapsed = time.perf_counter() - started
        peak_rss = max(before_rss, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        ordered = tuple(candidates[key] for key in sorted(candidates))
        return CandidateResult(
            edges=ordered, node_ids=frozenset(nodes), event_ids=frozenset(edge.event_id for edge in ordered),
            anchor_event_ids=frozenset(anchor_events), anchor_node_ids=frozenset(anchor_nodes),
            soft_seed_node_ids=frozenset(soft_nodes), stop_reason="CAP_REACHED" if cap_reached else "FRONTIER_EXHAUSTED",
            performance=CandidatePerformance(elapsed, int(peak_rss), frontiers_seen, store_queries),
        )

    def build_legacy(self, *, event_ids: Iterable[str] = (), node_ids: Iterable[str] = ()) -> CandidateResult:
        """Compatibility bridge for legacy stored event/node seeds, not detector logic."""
        items: list[AlertEvidence] = []
        for number, event_id in enumerate(sorted(set(event_ids))):
            items.append(AlertEvidence(
                evidence_id=f"legacy-event-{number}", detector_id="legacy", detector_version="1",
                granularity=EvidenceGranularity.EVENT, raw_score=None, calibrated_score=0.0,
                native_decision=True, event_ids=(event_id,), role_hint=RoleHint.UNKNOWN,
            ))
        for number, node_id in enumerate(sorted(set(node_ids))):
            items.append(AlertEvidence(
                evidence_id=f"legacy-node-{number}", detector_id="legacy", detector_version="1",
                granularity=EvidenceGranularity.NODE, raw_score=None, calibrated_score=0.0,
                native_decision=True, node_ids=(node_id,), role_hint=RoleHint.UNKNOWN,
            ))
        return self.build(items)

    @staticmethod
    def _directions(role: RoleHint) -> tuple[str, ...]:
        if role in {RoleHint.ROOT, RoleHint.ENTRY}:
            return ("forward",)
        if role in {RoleHint.EXIT, RoleHint.TERMINAL}:
            return ("backward",)
        # UNKNOWN and OBSERVATION are observations, never implicit endpoints.
        return ("backward", "forward")

    def _anchor_time(self, item: AlertEvidence, event_edges: list[StoredEdge]) -> int | None:
        if item.timestamp_end is not None:
            return item.timestamp_end
        if item.timestamp_start is not None:
            return item.timestamp_start
        return min((edge.timestamp_ns for edge in event_edges), default=None)

    def _bounds(self, direction: str, anchor_time: int | None) -> tuple[int, int]:
        lower = self.config.history_start_ns if self.config.history_start_ns is not None else _MIN_TIME
        upper = self.config.cutoff_ns if self.config.cutoff_ns is not None else _MAX_TIME
        if anchor_time is not None:
            if direction == "backward":
                upper = min(upper, anchor_time)
            else:
                lower = max(lower, anchor_time)
        return lower, upper

    @staticmethod
    def _causal_endpoints(edge: StoredEdge) -> tuple[str, str]:
        relation = edge.relation.upper()
        if relation in _REVERSED_RELATIONS:
            return edge.dst, edge.src
        if relation in _FORWARD_RELATIONS:
            return edge.src, edge.dst
        raise ValueError("relation is not in the strict CADETS causal view")

    @classmethod
    def _anchor_endpoints(cls, edge: StoredEdge) -> tuple[str, str]:
        """Replay any mapped raw event while reserving causal claims for known semantics."""
        try:
            return cls._causal_endpoints(edge)
        except ValueError:
            return edge.src, edge.dst

    def _strict_neighbors(self, frontier: _Frontier) -> tuple[tuple[StoredEdge, ...], int]:
        raw: dict[int, StoredEdge] = {}
        queries = 0
        for raw_direction in ("backward", "forward"):
            queries += 1
            for edge in self.store.get_directional_edges(
                frontier.node_id, direction=raw_direction,
                minimum_time_ns=frontier.lower_time_ns, maximum_time_ns=frontier.upper_time_ns,
                scan_limit=self.config.candidate_cap * self.config.scan_multiplier,
            ):
                raw[edge.edge_id] = edge
        accepted: list[StoredEdge] = []
        for edge in raw.values():
            if not frontier.lower_time_ns < edge.timestamp_ns < frontier.upper_time_ns:
                continue
            try:
                source, target = self._causal_endpoints(edge)
            except ValueError:
                continue
            if (frontier.direction == "backward" and target == frontier.node_id) or (
                frontier.direction == "forward" and source == frontier.node_id
            ):
                accepted.append(edge)
        return tuple(sorted(
            accepted, key=lambda edge: (edge.timestamp_ns, edge.edge_id), reverse=frontier.direction == "backward",
        )), queries

    def _add_control_context(
        self, candidates: dict[int, StoredEdge], nodes: set[str], anchors: set[str],
    ) -> int:
        queries = 0
        queue = [(node, 0) for node in sorted(anchors)]
        seen = set(anchors)
        lower = self.config.history_start_ns if self.config.history_start_ns is not None else _MIN_TIME
        upper = self.config.cutoff_ns if self.config.cutoff_ns is not None else _MAX_TIME
        parents: list[tuple[str, StoredEdge]] = []
        while queue and len(candidates) < self.config.candidate_cap:
            child, depth = queue.pop(0)
            if depth >= self.config.max_control_depth:
                continue
            queries += 1
            for edge in self.store.get_directional_edges(
                child, direction="backward", minimum_time_ns=lower, maximum_time_ns=upper,
                scan_limit=self.config.candidate_cap * self.config.scan_multiplier,
            ):
                if edge.relation.upper() not in _CONTROL_RELATIONS or edge.dst != child:
                    continue
                candidates.setdefault(edge.edge_id, edge)
                nodes.update((edge.src, edge.dst))
                parents.append((edge.src, edge))
                if edge.src not in seen:
                    seen.add(edge.src)
                    queue.append((edge.src, depth + 1))
                if len(candidates) >= self.config.candidate_cap:
                    break
        if self.config.enable_common_cause:
            for parent, branch in parents:
                if len(candidates) >= self.config.candidate_cap:
                    break
                queries += 1
                for edge in self.store.get_directional_edges(
                    parent, direction="forward", minimum_time_ns=lower, maximum_time_ns=upper,
                    scan_limit=self.config.candidate_cap * self.config.scan_multiplier,
                ):
                    if edge.relation.upper() in _CONTROL_RELATIONS and edge.event_id != branch.event_id:
                        candidates.setdefault(edge.edge_id, edge)
                        nodes.update((edge.src, edge.dst))
                    if len(candidates) >= self.config.candidate_cap:
                        break
        return queries


__all__ = ["CandidatePerformance", "CandidateResult", "CandidateSearchConfig", "EvidenceDrivenCandidateBuilder"]
