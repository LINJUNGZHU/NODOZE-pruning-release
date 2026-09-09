from __future__ import annotations

from dataclasses import dataclass
import gzip
import pickle
from pathlib import Path
import time

from .frequency import FrequencyModel
from .frequency_cache import CACHE_VERSION, DAY_NS, FrequencyCache
from .nodoze import NODOZEFrequencyModel
from .store import ProvenanceStore


SNAPSHOT_VERSION = 1


@dataclass(frozen=True, slots=True)
class FrequencySnapshot:
    cutoff_day_exclusive: int
    cache_version: int
    source_maximum_timestamp_ns: int
    nodoze: NODOZEFrequencyModel
    rarity: FrequencyModel


def default_snapshot_path(database: str | Path, cutoff_day: int) -> Path:
    root = Path(database).resolve().parent / "frequency-models"
    return root / f"before-day-{cutoff_day}.pkl.gz"


def compile_snapshot(
    store: ProvenanceStore, before_timestamp_ns: int, output: str | Path
) -> dict[str, int | float | str]:
    started = time.perf_counter()
    cache = FrequencyCache(store)
    cache.require()
    cutoff_day = int(before_timestamp_ns) // DAY_NS
    maximum = int(store.conn.execute(
        "SELECT value FROM frequency_cache_meta WHERE key='maximum_timestamp_ns'"
    ).fetchone()[0])
    snapshot = FrequencySnapshot(
        cutoff_day_exclusive=cutoff_day,
        cache_version=CACHE_VERSION,
        source_maximum_timestamp_ns=maximum,
        nodoze=NODOZEFrequencyModel.from_cache(
            store, before_timestamp_ns=before_timestamp_ns
        ),
        rarity=FrequencyModel.from_cache(
            store, before_timestamp_ns=before_timestamp_ns
        ),
    )
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(destination, "wb", compresslevel=3) as stream:
        pickle.dump((SNAPSHOT_VERSION, snapshot), stream, protocol=5)
    return {
        "output": str(destination.resolve()),
        "cutoff_day_exclusive": cutoff_day,
        "source_maximum_timestamp_ns": maximum,
        "size_bytes": destination.stat().st_size,
        "elapsed_seconds": time.perf_counter() - started,
    }


def load_snapshot(path: str | Path) -> FrequencySnapshot:
    source = Path(path)
    with gzip.open(source, "rb") as stream:
        version, snapshot = pickle.load(stream)
    if version != SNAPSHOT_VERSION or not isinstance(snapshot, FrequencySnapshot):
        raise ValueError(f"unsupported frequency snapshot: {source}")
    return snapshot


__all__ = [
    "FrequencySnapshot", "compile_snapshot", "default_snapshot_path",
    "load_snapshot",
]
