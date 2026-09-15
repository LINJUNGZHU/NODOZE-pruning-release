"""Detector-native adapters; these modules must remain Ground-Truth independent."""

from .kairos_adapter import (
    KairosEvidence,
    KairosEvidenceField,
    KairosMappingAudit,
    NativeKairosAdapter,
    NativeKairosEvent,
)

__all__ = [
    "KairosEvidence", "KairosEvidenceField", "KairosMappingAudit",
    "NativeKairosAdapter", "NativeKairosEvent",
]
