from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from typing import Iterable

from ..investigation.semantics import InvestigationSemanticsRegistry
from ..models import StoredEdge
from ..store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class CandidateMissRecord:
    node_id: str
    nearest_anchor: str | None
    backward_temporal_path: bool
    forward_temporal_path: bool
    mixed_control_data_path: bool
    minimum_hops: int | None
    minimum_temporal_distance: int | None
    minimum_valid_path: tuple[str, ...]
    relation_sequence: tuple[str, ...]
    taxonomy_labels: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Path:
    nodes: tuple[str, ...]
    edges: tuple[StoredEdge, ...]


class CandidateMissAnalyzer:
    """Post-freeze diagnostic search over the complete provenance store."""

    def __init__(
        self,
        store: ProvenanceStore,
        registry: InvestigationSemanticsRegistry,
        *,
        max_hops: int = 12,
        scan_limit_per_endpoint: int | None = None,
        minimum_time_ns: int | None = None,
    ) -> None:
        if max_hops < 1 or (
            scan_limit_per_endpoint is not None and scan_limit_per_endpoint < 1
        ):
            raise ValueError("search bounds must be positive")
        self.store = store
        self.registry = registry
        self.max_hops = max_hops
        self.scan_limit = scan_limit_per_endpoint
        self.minimum_time_ns = minimum_time_ns
        self._outgoing_cache: dict[tuple[str, int], tuple[StoredEdge, ...]] = {}
        self._incoming_cache: dict[tuple[str, int], tuple[StoredEdge, ...]] = {}

    def _raw_incident(
        self, node: str, *, cutoff_ns: int
    ) -> tuple[StoredEdge, ...]:
        edges = {
            edge.edge_id: edge
            for direction in ("forward", "backward")
            for edge in self.store.get_directional_edges(
                node,
                direction=direction,
                minimum_time_ns=self.minimum_time_ns,
                maximum_time_ns=cutoff_ns,
                scan_limit=self.scan_limit,
            )
        }
        return tuple(sorted(edges.values(), key=lambda edge: (edge.timestamp_ns, edge.edge_id)))

    def _outgoing(self, node: str, *, cutoff_ns: int) -> tuple[StoredEdge, ...]:
        key = (node, cutoff_ns)
        if key not in self._outgoing_cache:
            valid = []
            for edge in self._raw_incident(node, cutoff_ns=cutoff_ns):
                try:
                    source, _ = self.registry.causal_endpoints(edge)
                except ValueError:
                    continue
                if source == node:
                    valid.append(edge)
            self._outgoing_cache[key] = tuple(valid)
        return self._outgoing_cache[key]

    def _incoming(self, node: str, *, cutoff_ns: int) -> tuple[StoredEdge, ...]:
        key = (node, cutoff_ns)
        if key not in self._incoming_cache:
            valid = []
            for edge in self._raw_incident(node, cutoff_ns=cutoff_ns):
                try:
                    _, target = self.registry.causal_endpoints(edge)
                except ValueError:
                    continue
                if target == node:
                    valid.append(edge)
            self._incoming_cache[key] = tuple(valid)
        return self._incoming_cache[key]

    def _shortest(
        self, source: str, targets: set[str], *, cutoff_ns: int, reverse: bool = False
    ) -> _Path | None:
        queue = deque([_Path((source,), ())])
        # Temporal dominance: an earlier forward arrival (or later reverse
        # arrival) at the same entity admits every continuation available to
        # a dominated state, so depth-specific copies only waste memory.
        best_time: dict[str, int] = {}
        while queue:
            path = queue.popleft()
            node = path.nodes[-1]
            if node in targets and path.edges:
                return path
            if len(path.edges) >= self.max_hops:
                continue
            last_time = path.edges[-1].timestamp_ns if path.edges else (
                cutoff_ns + 1 if reverse else -1
            )
            adjacent = (
                self._incoming(node, cutoff_ns=cutoff_ns)
                if reverse else self._outgoing(node, cutoff_ns=cutoff_ns)
            )
            for edge in adjacent:
                if (reverse and edge.timestamp_ns >= last_time) or (
                    not reverse and edge.timestamp_ns <= last_time
                ):
                    continue
                causal_source, causal_target = self.registry.causal_endpoints(edge)
                target = causal_source if reverse else causal_target
                if target in path.nodes:
                    continue
                previous = best_time.get(target)
                if previous is not None:
                    if reverse and previous >= edge.timestamp_ns:
                        continue
                    if not reverse and previous <= edge.timestamp_ns:
                        continue
                best_time[target] = edge.timestamp_ns
                queue.append(_Path(path.nodes + (target,), path.edges + (edge,)))
        return None

    @staticmethod
    def _relation_labels(relations: tuple[str, ...]) -> set[str]:
        labels: set[str] = set()
        control = {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE", "EVENT_EXECUTE"}
        if any(relation in control for relation in relations):
            labels.add("CONTROL_DESCENDANT")
        network = {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_ACCEPT"}
        if any(relation in network for relation in relations):
            labels.add("NETWORK_MEDIATED")
        for left, right in zip(relations, relations[1:]):
            if left in {"EVENT_WRITE", "EVENT_CREATE_OBJECT"} and right == "EVENT_READ":
                labels.add("FILE_WRITE_READ_BRIDGE")
            if left in {"EVENT_WRITE", "EVENT_CREATE_OBJECT"} and right == "EVENT_EXECUTE":
                labels.add("DROP_EXEC_MOTIF")
        return labels

    def analyze(
        self, node_id: str, anchors: Iterable[str], *, cutoff_ns: int
    ) -> CandidateMissRecord:
        anchor_set = {str(anchor) for anchor in anchors if str(anchor) != node_id}
        reverse_path = self._shortest(
            node_id, anchor_set, cutoff_ns=cutoff_ns, reverse=True
        )
        from_anchors = []
        if reverse_path is not None:
            from_anchors.append(_Path(
                tuple(reversed(reverse_path.nodes)),
                tuple(reversed(reverse_path.edges)),
            ))
        to_anchor = self._shortest(node_id, anchor_set, cutoff_ns=cutoff_ns)
        paths = [*from_anchors, *([to_anchor] if to_anchor else [])]
        chosen = min(
            paths,
            key=lambda path: (
                len(path.edges),
                path.edges[-1].timestamp_ns - path.edges[0].timestamp_ns,
                tuple(edge.event_id for edge in path.edges),
            ),
            default=None,
        )
        relations = tuple(edge.relation.upper() for edge in chosen.edges) if chosen else ()
        labels = self._relation_labels(relations)
        if from_anchors or to_anchor:
            labels.add("FORWARD_DESCENDANT")
        mixed = bool(
            set(relations) & {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE", "EVENT_EXECUTE"}
            and set(relations) - {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE", "EVENT_EXECUTE"}
        )
        incident = self._raw_incident(node_id, cutoff_ns=cutoff_ns)
        if any(
            edge.dst == node_id
            and edge.relation.upper() in {"EVENT_FORK", "EVENT_CLONE", "PROCESS_CREATE"}
            for edge in incident
        ):
            labels.add("CONTROL_DESCENDANT")
        if any(
            self._unsupported(edge)
            for edge in incident
        ):
            labels.add("RELATION_UNSUPPORTED")
        if not chosen:
            labels.add("NO_TEMPORAL_PATH")
        nearest = None
        if chosen:
            nearest = chosen.nodes[0] if chosen.nodes[0] in anchor_set else chosen.nodes[-1]
        distance = None
        if chosen:
            distance = chosen.edges[-1].timestamp_ns - chosen.edges[0].timestamp_ns
        return CandidateMissRecord(
            node_id=node_id,
            nearest_anchor=nearest,
            backward_temporal_path=to_anchor is not None,
            forward_temporal_path=bool(from_anchors),
            mixed_control_data_path=mixed,
            minimum_hops=len(chosen.edges) if chosen else None,
            minimum_temporal_distance=distance,
            minimum_valid_path=tuple(edge.event_id for edge in chosen.edges) if chosen else (),
            relation_sequence=relations,
            taxonomy_labels=tuple(sorted(labels)),
        )

    def _unsupported(self, edge: StoredEdge) -> bool:
        try:
            self.registry.resolve(edge)
        except ValueError:
            return True
        return False


__all__ = ["CandidateMissAnalyzer", "CandidateMissRecord"]
