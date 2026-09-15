"""Label-free reconstruction of KAIROS anomalous queues.

This intentionally mirrors the detector's published queue construction while
making the frozen IDF corpus and fixed decision threshold explicit artifacts.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
from pathlib import Path
import statistics
from typing import Iterable


_NOISY_SUBSTRINGS = (
    "netflow", "/home/george/Drafts", "usr", "proc", "var", "cadet",
    "/var/log/debug.log", "/var/log/cron", "/home/charles/Drafts",
    "/etc/ssl/cert.pem", "/tmp/.31.3022e",
)


def _files(directories: Iterable[Path]) -> tuple[Path, ...]:
    return tuple(sorted(
        (path for directory in directories for path in Path(directory).glob("*.txt")),
        key=lambda path: (path.name, str(path.parent)),
    ))


def _rows(path: Path):
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if line.strip():
                yield ast.literal_eval(line)


def _training_document_frequency(paths: tuple[Path, ...]) -> dict[str, int]:
    frequencies: dict[str, int] = {}
    for path in paths:
        observed = set()
        for row in _rows(path):
            if float(row["loss"]) <= 0:
                continue
            for key in ("srcmsg", "dstmsg"):
                node = str(row[key])
                if "netflow" not in node:
                    observed.add(node)
        for node in observed:
            frequencies[node] = frequencies.get(node, 0) + 1
    return frequencies


def _window(path: Path) -> dict:
    rows = tuple(_rows(path))
    losses = tuple(float(row["loss"]) for row in rows)
    if not losses:
        return {"name": path.name, "loss": 0.0, "nodes": [], "anomalous_edges": 0}
    threshold = statistics.fmean(losses) + 1.5 * statistics.pstdev(losses)
    anomalous = tuple(row for row in rows if float(row["loss"]) > threshold)
    nodes = sorted({str(row[key]) for row in anomalous for key in ("srcmsg", "dstmsg")})
    average = statistics.fmean(float(row["loss"]) for row in anomalous) if anomalous else 0.0
    return {
        "name": path.name,
        "loss": average,
        "nodes": nodes,
        "anomalous_edges": len(anomalous),
    }


def _shares_rare_node(
    left: dict, right: dict, frequencies: dict[str, int], training_count: int,
) -> bool:
    for node in set(left["nodes"]).intersection(right["nodes"]):
        if any(token in node for token in _NOISY_SUBSTRINGS):
            continue
        if training_count == 0 or node not in frequencies:
            return True
        idf = math.log(training_count / (frequencies[node] + 1))
        if idf > math.log(training_count * 0.9):
            return True
    return False


def build_native_queues(
    training_directories: Iterable[Path],
    test_directories: Iterable[Path],
    *,
    beta: float = 100.0,
) -> dict:
    """Build detector-native queues without consulting incident labels."""
    training_paths = _files(training_directories)
    frequencies = _training_document_frequency(training_paths)
    windows = tuple(_window(path) for path in _files(test_directories))
    queues: list[list[dict]] = []
    for window in windows:
        matching = next((queue for queue in queues if any(
            _shares_rare_node(window, previous, frequencies, len(training_paths))
            for previous in queue
        )), None)
        if matching is None:
            queues.append([window])
        else:
            matching.append(window)
    serialized = []
    for index, queue in enumerate(queues):
        score = math.prod(item["loss"] + 1.0 for item in queue)
        serialized.append({
            "queue_id": f"queue:{index}",
            "windows": [item["name"] for item in queue],
            "score": score,
            "selected": score > beta,
            "window_details": queue,
        })
    payload = {
        "schema_version": "kairos-native-queues-v1",
        "parameters": {
            "anomalous_edge_sigma": 1.5,
            "beta": float(beta),
            "idf_rareness_fraction": 0.9,
        },
        "training_window_count": len(training_paths),
        "test_window_count": len(windows),
        "queues": serialized,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["content_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


__all__ = ["build_native_queues"]
