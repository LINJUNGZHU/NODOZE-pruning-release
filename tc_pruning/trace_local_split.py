"""Label-free chronological splitting for a single-day TRACE capture."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Iterable


def chronological_partition(paths: Iterable[Path]) -> dict[str, list[Path]]:
    ordered = sorted(map(Path, paths), key=lambda path: path.name)
    if len(ordered) < 3:
        raise ValueError("local TRACE split requires at least three graph windows")
    train_end = max(1, int(len(ordered) * 0.25))
    val_end = min(len(ordered) - 1, train_end + max(1, int(len(ordered) * 0.10)))
    return {
        "train": ordered[:train_end],
        "val": ordered[train_end:val_end],
        "test": ordered[val_end:],
    }


def materialize_chronological_split(
    graph_root: str | Path,
    *,
    source_day: str,
    train_day: str,
    val_day: str,
) -> dict:
    root = Path(graph_root)
    source = root / f"graph_{source_day}"
    split = chronological_partition(path for path in source.iterdir() if path.is_file())
    destinations = {
        "train": root / f"graph_{train_day}",
        "val": root / f"graph_{val_day}",
        "test": source,
    }
    for key in ("train", "val"):
        if destinations[key].exists():
            shutil.rmtree(destinations[key])
        destinations[key].mkdir(parents=True)
    for key in ("train", "val"):
        for path in split[key]:
            shutil.move(str(path), destinations[key] / path.name)
    manifest = {
        "protocol": "local-single-day-chronological-25-10-65",
        "source_day": source_day,
        "aliases": {"train": train_day, "val": val_day, "test": source_day},
        "windows": {key: [path.name for path in paths] for key, paths in split.items()},
        "counts": {key: len(paths) for key, paths in split.items()},
    }
    (root / "local-single-day-split.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
