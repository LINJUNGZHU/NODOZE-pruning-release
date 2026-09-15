from __future__ import annotations

from dataclasses import dataclass

from ..detectors.kairos_adapter import KairosEvidence
from .causal_corridors import CausalCorridor
from .inverse_coverage import InverseRoot
from .kairos_components import KairosAnchorComponent


@dataclass(frozen=True, slots=True)
class InvestigationEnvelope:
    evidence: tuple[KairosEvidence, ...]
    components: tuple[KairosAnchorComponent, ...]
    roots: tuple[InverseRoot, ...]
    corridors: tuple[CausalCorridor, ...]
    raw_event_ids: tuple[str, ...]

    @classmethod
    def build(cls, evidence, components, roots, corridors):
        event_ids = {
            row.raw_event_id for row in evidence
        } | {
            event for root in roots for event in root.witness_event_ids
        } | {
            event for corridor in corridors for event in corridor.raw_event_ids
        }
        return cls(tuple(evidence), tuple(components), tuple(roots), tuple(corridors), tuple(sorted(event_ids)))


__all__ = ["InvestigationEnvelope"]
