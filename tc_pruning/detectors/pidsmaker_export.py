"""Thin label-free PIDSMaker native-output to AlertEvidence export helper."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from ..detector_seed_benchmark import _atomic, _canonical
from .alert_evidence import AlertEvidence, AlertEvidenceProvider


def _native_rows(native: str | Path | Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    if not isinstance(native, (str, Path)): return [dict(row) for row in native]
    source = Path(native); files = (source,) if source.is_file() else tuple(sorted(item for item in source.rglob("*") if item.suffix.lower() in {".csv", ".json"}))
    rows: list[dict[str, object]] = []
    for path in files:
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", newline="") as stream: rows.extend(dict(row) for row in csv.DictReader(stream))
        else:
            payload = json.loads(path.read_text(encoding="utf-8")); rows.extend(dict(row) for row in payload)
    return rows


def export_evidence(adapter: AlertEvidenceProvider, native: str | Path | Iterable[Mapping[str, object]], development: str | Path | Iterable[Mapping[str, object]], output: str | Path) -> tuple[AlertEvidence, ...]:
    """Require frozen-development calibration and atomically emit canonical JSONL."""
    native_rows = _native_rows(native)
    rows = adapter.provide(native_rows, development)
    _atomic(Path(output), b"".join(_canonical(item.to_record()) for item in rows))
    snapshot = Path(output).with_suffix(".native.jsonl")
    _atomic(snapshot, b"".join(_canonical(row) for row in native_rows))
    _atomic(snapshot.with_suffix(snapshot.suffix + ".manifest.json"), _canonical({"artifact_schema": "native-snapshot-v1", "data_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(), "record_count": len(native_rows)}))
    return rows


__all__ = ["export_evidence"]
