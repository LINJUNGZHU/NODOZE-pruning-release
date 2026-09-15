from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class EvidenceUnit:
    unit_id: str
    unit_type: str
    raw_event_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    branch_ids: frozenset[str]
    anchor_ids: frozenset[str]
    motif_type: str | None
    certificate_types: frozenset[str]
    raw_relevance: float
    normalized_relevance: float
    verification_score: float

    @property
    def raw_event_cost(self) -> int:
        return len(set(self.raw_event_ids))


def ecdf_relevance(scores: Mapping[str, float]) -> dict[str, float]:
    """Return deterministic query-local ECDF percentiles, with ties sharing a rank."""
    if not scores:
        return {}
    ordered = sorted(float(value) for value in scores.values())
    last_rank = {
        value: index / len(ordered)
        for index, value in enumerate(ordered, start=1)
    }
    return {key: last_rank[float(value)] for key, value in scores.items()}


__all__ = ["EvidenceUnit", "ecdf_relevance"]
