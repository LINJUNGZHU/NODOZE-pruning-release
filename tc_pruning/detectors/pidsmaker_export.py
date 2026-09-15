"""Thin label-free PIDSMaker native-output to AlertEvidence export helper."""
from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Iterator, Mapping

from ..detector_seed_benchmark import _atomic, _canonical
from .alert_evidence import AlertEvidence, AlertEvidenceProvider


def _native_rows(native: str | Path | Iterable[Mapping[str, object]]) -> Iterator[dict[str, object]]:
    """Deterministic shard iterator; never reads a detector output wholesale."""
    if not isinstance(native, (str, Path)):
        yield from (dict(row) for row in native)
        return
    source = Path(native); files = (source,) if source.is_file() else tuple(sorted(item for item in source.rglob("*") if item.suffix.lower() in {".csv", ".json"}))
    for path in files:
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", newline="") as stream:
                yield from (dict(row) for row in csv.DictReader(stream))
        else:
            with path.open(encoding="utf-8") as stream:
                payload = json.load(stream)
            if not isinstance(payload, list): raise ValueError("native JSON shard must be an array")
            yield from (dict(row) for row in payload)

def _stream_snapshot(rows: Iterable[Mapping[str, object]], snapshot: Path) -> tuple[int, str]:
    snapshot.parent.mkdir(parents=True, exist_ok=True); fd, temporary = tempfile.mkstemp(prefix=".native.", dir=snapshot.parent); digest, count = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as stream:
            for row in rows:
                line = _canonical(dict(row)); stream.write(line); digest.update(line); count += 1
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, snapshot)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    return count, digest.hexdigest()


def export_evidence(adapter: AlertEvidenceProvider, native: str | Path | Iterable[Mapping[str, object]], development: str | Path | Iterable[Mapping[str, object]], output: str | Path) -> tuple[AlertEvidence, ...]:
    """Require frozen-development calibration and atomically emit canonical JSONL."""
    snapshot = Path(output).with_suffix(".native.jsonl")
    count, digest = _stream_snapshot(_native_rows(native), snapshot)
    # Disk staging gives adapters a replayable stream without retaining all
    # input rows or CSV shard contents in process memory.
    def staged_rows() -> Iterator[dict[str, object]]:
        with snapshot.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip(): yield dict(json.loads(line))
    rows = adapter.provide(staged_rows(), development)
    _atomic(Path(output), b"".join(_canonical(item.to_record()) for item in rows))
    _atomic(snapshot.with_suffix(snapshot.suffix + ".manifest.json"), _canonical({"artifact_schema": "native-snapshot-v1", "data_sha256": digest, "record_count": count}))
    return rows


__all__ = ["export_evidence"]
