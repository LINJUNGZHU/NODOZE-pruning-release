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
    source = Path(native)
    if source.is_dir() and any(item.suffix.lower() == ".json" for item in source.rglob("*")):
        raise ValueError("production native export rejects JSON array shards")
    files = (source,) if source.is_file() else tuple(sorted(item for item in source.rglob("*") if item.suffix.lower() in {".csv", ".jsonl"}))
    if not files: raise ValueError("native export has no CSV/JSONL shards")
    for path in files:
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", newline="") as stream:
                yield from (dict(row) for row in csv.DictReader(stream))
        elif path.suffix.lower() == ".jsonl":
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    if line.strip(): yield dict(json.loads(line))
        else:
            raise ValueError("production native export accepts only CSV or JSONL shards; JSON arrays are not streaming-safe")

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


def export_evidence(adapter: AlertEvidenceProvider, native: str | Path | Iterable[Mapping[str, object]], development: str | Path | Iterable[Mapping[str, object]], output: str | Path) -> None:
    """Require frozen-development calibration and atomically emit canonical JSONL."""
    snapshot = Path(output).with_suffix(".native.jsonl")
    count, digest = _stream_snapshot(_native_rows(native), snapshot)
    if not count: raise ValueError("native export is empty")
    # Disk staging gives adapters a replayable stream without retaining all
    # input rows or CSV shard contents in process memory.
    def staged_rows() -> Iterator[dict[str, object]]:
        with snapshot.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip(): yield dict(json.loads(line))
    rows = adapter.iter_provide(staged_rows(), development) if hasattr(adapter, "iter_provide") else iter(adapter.provide(staged_rows(), development))
    target = Path(output); target.parent.mkdir(parents=True, exist_ok=True); fd, temporary = tempfile.mkstemp(prefix=".evidence.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            for item in rows: stream.write(_canonical(item.to_record()))
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    _atomic(snapshot.with_suffix(snapshot.suffix + ".manifest.json"), _canonical({"artifact_schema": "native-snapshot-v1", "data_sha256": digest, "record_count": count}))
    return None


__all__ = ["export_evidence"]
