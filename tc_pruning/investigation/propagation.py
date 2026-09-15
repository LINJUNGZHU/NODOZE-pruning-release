from __future__ import annotations

from collections import Counter, defaultdict
import math
from types import MappingProxyType
from typing import Iterable, Mapping

from ..models import StoredEdge
from .graph_views import CleanPropagationConfig, InvestigationGraphs, PropagationEdge
from .semantics import InvestigationSemanticsRegistry


_RELATION_FAMILY = {
    "EVENT_FORK": "CONTROL",
    "EVENT_CLONE": "CONTROL",
    "PROCESS_CREATE": "CONTROL",
    "EVENT_READ": "FILE_READ",
    "EVENT_MMAP": "FILE_READ",
    "EVENT_LOADLIBRARY": "FILE_READ",
    "EVENT_WRITE": "FILE_WRITE",
    "EVENT_CREATE_OBJECT": "FILE_WRITE",
    "EVENT_TRUNCATE": "FILE_WRITE",
    "EVENT_RENAME": "FILE_WRITE",
    "EVENT_LINK": "FILE_WRITE",
    "EVENT_UNLINK": "FILE_WRITE",
    "EVENT_EXECUTE": "EXECUTION",
    "EVENT_RECVFROM": "NETWORK_IN",
    "EVENT_RECVMSG": "NETWORK_IN",
    "EVENT_ACCEPT": "NETWORK_IN",
    "EVENT_READ_SOCKET_PARAMS": "NETWORK_IN",
    "EVENT_CONNECT": "NETWORK_OUT",
    "EVENT_SENDTO": "NETWORK_OUT",
    "EVENT_SENDMSG": "NETWORK_OUT",
}


class CleanPropagationBuilder:
    def __init__(
        self,
        registry: InvestigationSemanticsRegistry,
        config: CleanPropagationConfig,
    ) -> None:
        self.registry = registry
        self.config = config

    def build(
        self,
        edges: Iterable[StoredEdge],
        *,
        cutoff_ns: int,
        historical_frequency: Mapping[str, int] | None = None,
        history_cutoff_ns: int | None = None,
    ) -> InvestigationGraphs:
        if history_cutoff_ns is not None and history_cutoff_ns > cutoff_ns:
            raise ValueError("history cutoff cannot be after query cutoff")
        full = tuple(sorted(edges, key=lambda edge: (edge.timestamp_ns, edge.edge_id)))
        frequency = historical_frequency or {}
        causal = []
        for edge in full:
            if edge.timestamp_ns > cutoff_ns:
                continue
            try:
                source, target = self.registry.causal_endpoints(edge)
            except ValueError:
                continue
            family = _RELATION_FAMILY.get(edge.relation.upper(), "OTHER")
            causal.append((edge, source, target, family))
        fanout = Counter((source, family) for _, source, _, family in causal)
        raw_rows = []
        for edge, source, target, family in causal:
            age = max(0, cutoff_ns - edge.timestamp_ns)
            temporal = math.exp(-age / float(self.config.tau_ns[family]))
            history = (1 + max(0, int(frequency.get(edge.event_id, 0)))) ** (-self.config.alpha)
            degree = (1 + fanout[(source, family)]) ** (-self.config.gamma)
            raw = float(self.config.relation_weights[family]) * temporal * history * degree
            raw_rows.append((edge, source, target, family, raw))
        totals: dict[tuple[str, str], float] = defaultdict(float)
        for _, source, _, family, raw in raw_rows:
            totals[(source, family)] += raw
        propagation = tuple(
            PropagationEdge(
                edge.edge_id,
                edge.event_id,
                source,
                target,
                edge.relation.upper(),
                family,
                edge.timestamp_ns,
                raw,
                raw / totals[(source, family)] if totals[(source, family)] else 0.0,
            )
            for edge, source, target, family, raw in raw_rows
        )
        return InvestigationGraphs(
            full,
            propagation,
            telemetry=MappingProxyType({
                "eligible_full_edges": len(full),
                "propagation_edges": len(propagation),
                "history_cutoff_ns": history_cutoff_ns,
                "cutoff_ns": cutoff_ns,
            }),
        )


__all__ = ["CleanPropagationBuilder"]
