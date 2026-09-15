"""Executable frozen-development Velox profile semantics."""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from ..evidence_candidate_builder import EvidencePriority
from .alert_evidence import AlertEvidence


_PROFILES = frozenset({"VXL-0", "VXL-1", "VXL-2", "VXL-3"})


def apply_velox_profile(evidence: Iterable[AlertEvidence], profile: str, *, frozen_development_percentile_threshold: float | None = None) -> tuple[tuple[AlertEvidence, ...], EvidencePriority]:
    """Return continuous evidence plus optional search-only priority.

    Profile decisions modify only native anchor eligibility.  Every input row is
    retained, and priority maps cannot make a new evidence fact or anchor.
    """
    if profile not in _PROFILES:
        raise ValueError("unknown Velox profile")
    if profile in {"VXL-1", "VXL-3"} and (frozen_development_percentile_threshold is None or not 0.0 <= frozen_development_percentile_threshold <= 1.0):
        raise ValueError("frozen development percentile threshold is required")
    rows = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    if any(item.detector_id.upper() != "VELOX" for item in rows):
        raise ValueError("Velox profile accepts only Velox evidence")
    if profile in {"VXL-1", "VXL-3"}:
        anchored = tuple(replace(item, native_decision=item.calibrated_score >= float(frozen_development_percentile_threshold)) for item in rows)
    else:
        anchored = rows
    if profile == "VXL-2":
        priority = EvidencePriority({event: float(item.raw_score) for item in rows if item.raw_score is not None for event in item.event_ids})
    elif profile == "VXL-3":
        priority = EvidencePriority({event: item.calibrated_score for item in rows for event in item.event_ids})
    else:
        priority = EvidencePriority({})
    return anchored, priority


__all__ = ["apply_velox_profile"]
