"""Thin label-free PIDSMaker native-output to AlertEvidence export helper."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Mapping

from ..detector_seed_benchmark import _atomic_bytes, _canonical
from .alert_evidence import AlertEvidence, AlertEvidenceProvider


def export_evidence(adapter: AlertEvidenceProvider, native: str | Path | Iterable[Mapping[str, object]], development: str | Path | Iterable[Mapping[str, object]], output: str | Path) -> tuple[AlertEvidence, ...]:
    """Require frozen-development calibration and atomically emit canonical JSONL."""
    rows = adapter.provide(native, development)
    _atomic_bytes(Path(output), b"".join(_canonical(item.to_record()) for item in rows))
    return rows


__all__ = ["export_evidence"]
