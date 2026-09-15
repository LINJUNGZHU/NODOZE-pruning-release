"""Detector-native adapters; these modules must remain Ground-Truth independent."""

from .kairos_adapter import (
    KairosEvidence,
    KairosEvidenceField,
    KairosMappingAudit,
    NativeKairosAdapter,
    NativeKairosEvent,
)
from .alert_evidence import (
    ALERT_EVIDENCE_SCHEMA_VERSION,
    ORTHRUS_ALERTS_PATH,
    AlertEvidence,
    AlertEvidenceProvider,
    CausalAgreement,
    DevelopmentCalibrator,
    EvidenceGranularity,
    KairosEvidenceProvider,
    MappingQuality,
    NODLINKEvidenceAdapter,
    OrthrusEvidenceProvider,
    RCAIDEvidenceAdapter,
    RoleHint,
    VeloxEvidenceAdapter,
    dump_evidence_jsonl,
    fuse_same_object_noisy_or,
    load_evidence_jsonl,
)

__all__ = [
    "KairosEvidence", "KairosEvidenceField", "KairosMappingAudit",
    "NativeKairosAdapter", "NativeKairosEvent",
    "ALERT_EVIDENCE_SCHEMA_VERSION", "ORTHRUS_ALERTS_PATH", "AlertEvidence",
    "AlertEvidenceProvider", "CausalAgreement", "DevelopmentCalibrator",
    "EvidenceGranularity", "KairosEvidenceProvider", "MappingQuality",
    "NODLINKEvidenceAdapter", "OrthrusEvidenceProvider", "RCAIDEvidenceAdapter",
    "RoleHint", "VeloxEvidenceAdapter", "dump_evidence_jsonl",
    "fuse_same_object_noisy_or", "load_evidence_jsonl",
]
