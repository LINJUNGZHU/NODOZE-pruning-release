"""Lossless, deterministic adapter for native KAIROS evidence."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Iterable

from ..models import StoredEdge
from ..store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class NativeKairosEvent:
    native_id: str
    window: str
    timestamp_ns: int
    relation: str
    srcmsg: str
    dstmsg: str
    raw_loss: float
    explicit_event_id: str | None = None
    anomalous_native: bool = True
    queue_ids: tuple[str, ...] = ()
    queue_strength: float = 0.0
    summary_component: str | None = None


@dataclass(frozen=True, slots=True)
class KairosEvidence:
    raw_event_id: str
    src: str
    dst: str
    relation: str
    timestamp_ns: int
    raw_loss: float
    loss_percentile: float
    anomalous_native: bool
    queue_ids: tuple[str, ...]
    queue_strength: float
    summary_membership: bool
    summary_component: str | None
    native_id: str
    window: str
    mapping_tier: str


@dataclass(frozen=True, slots=True)
class KairosMappingAudit:
    native_events: int
    identity_mapped: int
    exact_mapped: int
    tolerant_mapped: int
    ambiguous: int
    unmapped: int
    mapping_rate: float


@dataclass(frozen=True, slots=True)
class KairosEvidenceField:
    evidence: tuple[KairosEvidence, ...]
    audit: KairosMappingAudit
    mapping_sha256: str


def _semantic(message: str) -> tuple[str, str]:
    try:
        value = ast.literal_eval(message)
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"invalid KAIROS node message: {message!r}") from exc
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError(f"invalid KAIROS node message: {message!r}")
    kind, label = next(iter(value.items()))
    normalized = {"subject": "process", "file": "file", "netflow": "socket"}.get(str(kind))
    if normalized is None:
        raise ValueError(f"unsupported KAIROS node kind: {kind}")
    return normalized, str(label)


class NativeKairosAdapter:
    def __init__(self, store: ProvenanceStore, *, tolerance_ns: int = 0) -> None:
        if tolerance_ns < 0:
            raise ValueError("timestamp tolerance must be non-negative")
        self.store = store
        self.tolerance_ns = tolerance_ns

    def _tuple_candidates(self, row: NativeKairosEvent, tolerance: int) -> tuple[StoredEdge, ...]:
        src_type, src_label = _semantic(row.srcmsg)
        dst_type, dst_label = _semantic(row.dstmsg)
        values = self.store.conn.execute(
            """
            SELECT e.id edge_id,e.event_id,e.src,e.dst,e.relation,e.timestamp_ns,e.host,
                   sn.node_type src_type,dn.node_type dst_type,
                   sn.semantic_key src_semantic,dn.semantic_key dst_semantic,e.data_size,
                   sn.label src_label,dn.label dst_label
            FROM edges e JOIN nodes sn ON sn.uuid=e.src JOIN nodes dn ON dn.uuid=e.dst
            WHERE e.relation=? AND e.timestamp_ns BETWEEN ? AND ?
              AND sn.node_type=? AND dn.node_type=? AND sn.label=? AND dn.label=?
            ORDER BY e.event_id
            """,
            (
                row.relation.upper(), row.timestamp_ns - tolerance,
                row.timestamp_ns + tolerance, src_type, dst_type, src_label, dst_label,
            ),
        ).fetchall()
        return tuple(StoredEdge(**{
            key: value[key] for key in (
                "edge_id", "event_id", "src", "dst", "relation", "timestamp_ns",
                "host", "src_type", "dst_type", "src_semantic", "dst_semantic", "data_size",
            )
        }) for value in values)

    def map_records(self, records: Iterable[NativeKairosEvent]) -> KairosEvidenceField:
        rows = tuple(records)
        ordered_losses = sorted(float(row.raw_loss) for row in rows)
        percentile = {
            value: (index + 1) / len(ordered_losses)
            for index, value in enumerate(ordered_losses)
        } if rows else {}
        counts = {"identity": 0, "exact": 0, "tolerant": 0, "ambiguous": 0, "unmapped": 0}
        mapped = []
        for row in rows:
            edge = None
            tier = None
            if row.explicit_event_id:
                edge = self.store.get_edge_by_event_id(row.explicit_event_id)
                if edge is not None:
                    tier = "IDENTITY"
                    counts["identity"] += 1
            if edge is None:
                exact = self._tuple_candidates(row, 0)
                if len(exact) == 1:
                    edge, tier = exact[0], "EXACT"
                    counts["exact"] += 1
                elif len(exact) > 1:
                    counts["ambiguous"] += 1
                    continue
                elif self.tolerance_ns:
                    tolerant = self._tuple_candidates(row, self.tolerance_ns)
                    if len(tolerant) == 1:
                        edge, tier = tolerant[0], "TOLERANT"
                        counts["tolerant"] += 1
                    elif len(tolerant) > 1:
                        counts["ambiguous"] += 1
                        continue
            if edge is None or tier is None:
                counts["unmapped"] += 1
                continue
            mapped.append(KairosEvidence(
                edge.event_id, edge.src, edge.dst, edge.relation.upper(), edge.timestamp_ns,
                float(row.raw_loss), percentile[float(row.raw_loss)], row.anomalous_native,
                tuple(sorted(set(row.queue_ids))), float(row.queue_strength),
                row.summary_component is not None, row.summary_component,
                row.native_id, row.window, tier,
            ))
        evidence = tuple(sorted(mapped, key=lambda item: (item.timestamp_ns, item.native_id)))
        successful = counts["identity"] + counts["exact"] + counts["tolerant"]
        audit = KairosMappingAudit(
            len(rows), counts["identity"], counts["exact"], counts["tolerant"],
            counts["ambiguous"], counts["unmapped"], successful / len(rows) if rows else 1.0,
        )
        canonical = json.dumps(
            {"evidence": [asdict(item) for item in evidence], "audit": asdict(audit)},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return KairosEvidenceField(evidence, audit, hashlib.sha256(canonical).hexdigest())


__all__ = [
    "KairosEvidence", "KairosEvidenceField", "KairosMappingAudit",
    "NativeKairosAdapter", "NativeKairosEvent",
]
