from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import hashlib
import math
from typing import Iterable, Mapping

from ..models import StoredEdge


class MotifType(str, Enum):
    CONTROL_SPAWN = "CONTROL_SPAWN"
    FILE_TRANSFER = "FILE_TRANSFER"
    DROP_EXECUTE = "DROP_EXECUTE"
    NETWORK_CONSEQUENCE = "NETWORK_CONSEQUENCE"
    RECEIVE_TO_EXECUTION = "RECEIVE_TO_EXECUTION"
    COMMON_CAUSE_BRANCH = "COMMON_CAUSE_BRANCH"
    CROSS_ANCHOR_BRIDGE = "CROSS_ANCHOR_BRIDGE"


@dataclass(frozen=True, slots=True)
class TemporalCausalMotif:
    motif_id: str
    motif_type: MotifType
    node_ids: tuple[str, ...]
    raw_event_ids: tuple[str, ...]
    relation_pattern: tuple[str, ...]
    time_range: tuple[int, int]
    raw_event_cost: int
    motif_relevance: float
    motif_rarity: float
    motif_verification: float
    motif_anchor_support: float
    motif_branch_support: float
    motif_score: float
    semantic_validity: float = 1.0


class TemporalCausalMotifBuilder:
    def __init__(self, *, max_bridge_hops: int = 6) -> None:
        self.max_bridge_hops = max_bridge_hops

    @staticmethod
    def _causal(edge: StoredEdge) -> tuple[str, str]:
        return (edge.dst, edge.src) if edge.relation.upper() == "EVENT_EXECUTE" else (edge.src, edge.dst)

    def _motif(
        self,
        kind: MotifType,
        edges: tuple[StoredEdge, ...],
        *,
        anchor_ids: set[str],
        relevance: Mapping[str, float],
        rarity: Mapping[str, float],
        verification: Mapping[str, float],
        branch_support: float = 0.0,
    ) -> TemporalCausalMotif:
        event_ids = tuple(dict.fromkeys(edge.event_id for edge in edges))
        nodes = tuple(sorted({node for edge in edges for node in (edge.src, edge.dst)}))
        rel = sum((max(0.0, float(relevance.get(event, 0.0))) for event in event_ids), 0.0) / len(event_ids)
        ver = sum((max(0.0, float(verification.get(event, 1.0))) for event in event_ids), 0.0) / len(event_ids)
        rare = sum((max(0.0, float(rarity.get(event, 0.0))) for event in event_ids), 0.0) / len(event_ids)
        anchor_support = len(set(nodes) & anchor_ids) / max(1, len(anchor_ids))
        core = (max(rel, 1e-12) * max(ver, 1e-12)) ** 0.5
        score = core * (1.0 + 0.1 * min(1.0, rare))
        digest = hashlib.sha256((kind.value + "\0" + "\0".join(event_ids)).encode()).hexdigest()[:20]
        times = [edge.timestamp_ns for edge in edges]
        return TemporalCausalMotif(
            f"motif:{digest}", kind, nodes, event_ids,
            tuple(edge.relation.upper() for edge in edges),
            (min(times), max(times)), len(event_ids), rel, rare, ver,
            anchor_support, branch_support, score,
        )

    def build(
        self,
        edges: Iterable[StoredEdge],
        *,
        anchor_ids: Iterable[str] = (),
        verified_terminal_ids: Iterable[str] = (),
        normalized_relevance: Mapping[str, float] | None = None,
        rarity: Mapping[str, float] | None = None,
        verification: Mapping[str, float] | None = None,
    ) -> tuple[TemporalCausalMotif, ...]:
        ordered = tuple(sorted(edges, key=lambda edge: (edge.timestamp_ns, edge.edge_id)))
        anchors = set(anchor_ids)
        terminals = set(verified_terminal_ids)
        relevance = normalized_relevance or {}
        rarity_map = rarity or {}
        verification_map = verification or {}
        by_relation: dict[str, list[StoredEdge]] = defaultdict(list)
        for edge in ordered:
            by_relation[edge.relation.upper()].append(edge)
        writes = by_relation["EVENT_WRITE"] + by_relation["EVENT_CREATE_OBJECT"]
        reads = by_relation["EVENT_READ"]
        executes = by_relation["EVENT_EXECUTE"]
        forks = by_relation["EVENT_FORK"] + by_relation["EVENT_CLONE"] + by_relation["PROCESS_CREATE"]
        receives = by_relation["EVENT_RECVFROM"] + by_relation["EVENT_RECVMSG"] + by_relation["EVENT_ACCEPT"]
        network_out = by_relation["EVENT_CONNECT"] + by_relation["EVENT_SENDTO"] + by_relation["EVENT_SENDMSG"]
        found: list[tuple[MotifType, tuple[StoredEdge, ...], float]] = []
        executes_by_process: dict[str, list[StoredEdge]] = defaultdict(list)
        reads_by_file: dict[str, list[StoredEdge]] = defaultdict(list)
        executes_by_file: dict[str, list[StoredEdge]] = defaultdict(list)
        consequences_by_process: dict[str, list[StoredEdge]] = defaultdict(list)
        for execute in executes:
            executes_by_process[execute.src].append(execute)
            executes_by_file[execute.dst].append(execute)
        for read in reads:
            reads_by_file[read.src].append(read)
        for consequence in (*forks, *executes):
            consequences_by_process[consequence.src].append(consequence)
        for fork in forks:
            for execute in executes_by_process.get(fork.dst, ()):
                if fork.timestamp_ns < execute.timestamp_ns:
                    found.append((MotifType.CONTROL_SPAWN, (fork, execute), 0.0))
        for write in writes:
            for read in reads_by_file.get(write.dst, ()):
                if write.timestamp_ns < read.timestamp_ns:
                    found.append((MotifType.FILE_TRANSFER, (write, read), 0.0))
            for execute in executes_by_file.get(write.dst, ()):
                if write.timestamp_ns < execute.timestamp_ns:
                    found.append((MotifType.DROP_EXECUTE, (write, execute), 0.0))
        found.extend(
            (MotifType.NETWORK_CONSEQUENCE, (edge,), 0.0)
            for edge in network_out
            if float(relevance.get(edge.event_id, 0.0)) > 0.0
            or float(verification_map.get(edge.event_id, 0.0)) > 0.0
            or edge.src in anchors or edge.dst in anchors or edge.dst in terminals
        )
        for receive in receives:
            for consequence in consequences_by_process.get(receive.dst, ()):
                if receive.timestamp_ns < consequence.timestamp_ns:
                    found.append((MotifType.RECEIVE_TO_EXECUTION, (receive, consequence), 0.0))
        children: dict[str, list[StoredEdge]] = defaultdict(list)
        outgoing: dict[str, list[StoredEdge]] = defaultdict(list)
        for fork in forks:
            children[fork.src].append(fork)
        for edge in ordered:
            outgoing[edge.src].append(edge)
        for sibling_edges in children.values():
            for anchor_edge in sibling_edges:
                if anchor_edge.dst not in anchors:
                    continue
                for sibling in sibling_edges:
                    if sibling is anchor_edge:
                        continue
                    for consequence in outgoing.get(sibling.dst, ()):
                        if consequence.dst in terminals and sibling.timestamp_ns < consequence.timestamp_ns:
                            found.append((MotifType.COMMON_CAUSE_BRANCH, (anchor_edge, sibling, consequence), 1.0))
        found.extend((MotifType.CROSS_ANCHOR_BRIDGE, path, 1.0) for path in self._anchor_paths(ordered, anchors))
        unique = {}
        for kind, witness, branch_support in found:
            key = (kind.value, tuple(edge.event_id for edge in witness))
            unique[key] = self._motif(
                kind, witness, anchor_ids=anchors, relevance=relevance, rarity=rarity_map,
                verification=verification_map, branch_support=branch_support,
            )
        return tuple(unique[key] for key in sorted(unique))

    def _anchor_paths(
        self, edges: tuple[StoredEdge, ...], anchors: set[str]
    ) -> tuple[tuple[StoredEdge, ...], ...]:
        successors: dict[str, list[StoredEdge]] = defaultdict(list)
        for edge in edges:
            source, _ = self._causal(edge)
            successors[source].append(edge)
        paths = []
        for source in sorted(anchors):
            queue = deque([(source, -1, (), {source})])
            while queue:
                node, last_time, witness, seen = queue.popleft()
                if node in anchors and node != source and witness:
                    paths.append(witness)
                    break
                if len(witness) >= self.max_bridge_hops:
                    continue
                for edge in successors.get(node, ()):
                    causal_source, target = self._causal(edge)
                    if causal_source != node or edge.timestamp_ns <= last_time or target in seen:
                        continue
                    queue.append((target, edge.timestamp_ns, witness + (edge,), seen | {target}))
        return tuple(paths)


__all__ = ["MotifType", "TemporalCausalMotif", "TemporalCausalMotifBuilder"]
