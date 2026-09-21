"""Label-free KAIROS queue and POI freezing for current PIDSMaker CSV output."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import statistics
from typing import Iterable, Mapping


_NOISY = (
    "netflow", "/dev/pts", "salt-minion.log", "null", "usr", "proc",
    "firefox", "tmp", "thunderbird", "bin/", "/data/replay_logdb",
    "/stat", "/boot", "qt-opensource-linux-x64", "/eraseme", "675",
)


@dataclass(frozen=True, slots=True)
class TraceLossWindow:
    name: str
    day: str
    start_ns: int
    end_ns: int
    anomaly_loss: float
    anomalous_edges: int
    anomalous_nodes: frozenset[str]
    anomalous_event_keys: tuple[tuple[str, str, int], ...]


def _sha(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def choose_final_epoch(test_losses_dir: str | Path) -> Path:
    root = Path(test_losses_dir)
    candidates = []
    for path in root.glob("model_epoch_*"):
        try:
            epoch = int(path.name.removeprefix("model_epoch_"))
        except ValueError:
            continue
        if path.is_dir():
            candidates.append((epoch, path))
    if not candidates:
        raise ValueError(f"no model epochs under {root}")
    return max(candidates)[1]


def _read_rows(path: Path) -> list[tuple[float, str, str, int]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"loss", "srcnode", "dstnode", "time"}
        if reader.fieldnames is None or not required <= set(reader.fieldnames):
            raise ValueError(f"unsupported PIDSMaker loss CSV: {path}")
        for row in reader:
            rows.append((
                float(row["loss"]), str(row["srcnode"]),
                str(row["dstnode"]), int(row["time"]),
            ))
    return rows


def read_loss_window(path: str | Path) -> TraceLossWindow:
    source = Path(path)
    rows = _read_rows(source)
    if not rows:
        return TraceLossWindow(
            source.name, source.name[:10], 0, 0, 0.0, 0,
            frozenset(), (),
        )
    losses = [row[0] for row in rows]
    threshold = statistics.fmean(losses) + 1.5 * statistics.pstdev(losses)
    anomalous = [row for row in rows if row[0] > threshold]
    nodes = frozenset(node for row in anomalous for node in row[1:3])
    return TraceLossWindow(
        source.name, source.name[:10], min(row[3] for row in rows),
        max(row[3] for row in rows),
        statistics.fmean(row[0] for row in anomalous) if anomalous else 0.0,
        len(anomalous), nodes,
        tuple((row[1], row[2], row[3]) for row in anomalous),
    )


def _document_frequency(documents: Iterable[Iterable[str]]) -> tuple[dict[str, int], int]:
    frequencies: dict[str, int] = {}
    count = 0
    for document in documents:
        count += 1
        for node in set(map(str, document)):
            frequencies[node] = frequencies.get(node, 0) + 1
    return frequencies, count


def group_event_mapping(
    rows: Iterable[tuple[str, str, int, str]],
) -> dict[tuple[str, str, int], tuple[str, ...]]:
    grouped: dict[tuple[str, str, int], set[str]] = {}
    for src, dst, timestamp, event_id in rows:
        grouped.setdefault(
            (str(src), str(dst), int(timestamp)), set(),
        ).add(str(event_id))
    return {key: tuple(sorted(values)) for key, values in sorted(grouped.items())}


def _linked(
    left: TraceLossWindow, right: TraceLossWindow, frequencies: Mapping[str, int],
    document_count: int, labels: Mapping[str, str],
) -> bool:
    for node in left.anomalous_nodes & right.anomalous_nodes:
        label = labels.get(node, node).casefold()
        if any(token.casefold() in label for token in _NOISY):
            continue
        if document_count == 0 or node not in frequencies:
            return True
        idf = math.log(document_count / (frequencies[node] + 1))
        if idf > math.log(document_count * 0.9):
            return True
    return False


def build_native_trace_queues(
    loss_paths: Iterable[str | Path], *,
    training_documents: Iterable[Iterable[str]],
    test_documents: Iterable[Iterable[str]],
    node_labels: Mapping[str, str],
    queue_threshold: float = 20.0,
) -> dict:
    """Reproduce KAIROS queue decisions without consulting incident labels."""
    train_frequency, train_count = _document_frequency(training_documents)
    # Materialize test documents for an auditable corpus count. Queue linkage follows
    # the published training-IDF rule used by the original KAIROS implementation.
    _, test_count = _document_frequency(test_documents)
    windows = tuple(read_loss_window(path) for path in sorted(map(Path, loss_paths)))
    queues: list[list[TraceLossWindow]] = []
    for window in windows:
        queue = next((
            item for item in queues
            if any(_linked(window, previous, train_frequency, train_count, node_labels)
                   for previous in item)
        ), None)
        if queue is None:
            queues.append([window])
        else:
            queue.append(window)
    rendered = []
    for index, queue in enumerate(queues):
        score = math.prod(window.anomaly_loss + 1.0 for window in queue)
        rendered.append({
            "queue_id": f"queue:{index}",
            "windows": [window.name for window in queue],
            "days": sorted({window.day for window in queue}),
            "score": score,
            "selected": score > float(queue_threshold),
            "anomalous_node_ids": sorted({
                node for window in queue for node in window.anomalous_nodes
            }),
            "window_details": [
                {**asdict(window), "anomalous_nodes": sorted(window.anomalous_nodes)}
                for window in queue
            ],
        })
    payload = {
        "schema_version": "trace-e3-kairos-native-queues-v1",
        "parameters": {
            "anomalous_edge_sigma": 1.5,
            "queue_threshold": float(queue_threshold),
            "epoch_policy": "final-generated-epoch",
            "queue_linkage": "published-training-idf",
        },
        "training_window_count": train_count,
        "test_window_count": test_count,
        "queues": rendered,
    }
    payload["content_sha256"] = _sha(payload)
    return payload


def freeze_trace_pois(
    queue_manifest: Mapping[str, object],
    index_to_uuid: Mapping[str, str],
    *,
    event_mapping: Mapping[tuple[str, str, int], Iterable[str]] | None = None,
) -> dict:
    selected = [queue for queue in queue_manifest["queues"] if queue["selected"]]
    indices = sorted({str(node) for queue in selected for node in queue["anomalous_node_ids"]})
    mapped = {node: str(index_to_uuid[node]) for node in indices if node in index_to_uuid}
    mapped_events = {
        (str(src), str(dst), int(timestamp)): tuple(sorted(set(map(str, event_ids))))
        for (src, dst, timestamp), event_ids in (event_mapping or {}).items()
    }
    by_day: dict[str, set[str]] = {}
    events_by_day: dict[str, set[str]] = {}
    observations_by_day: dict[str, list[dict[str, object]]] = {}
    selected_event_keys: set[tuple[str, str, int]] = set()
    for queue in selected:
        for window in queue["window_details"]:
            uuids = {
                mapped[str(node)] for node in window["anomalous_nodes"]
                if str(node) in mapped
            }
            day = str(window["day"])
            by_day.setdefault(day, set()).update(uuids)
            event_keys = {
                (str(src), str(dst), int(timestamp))
                for src, dst, timestamp in window.get("anomalous_event_keys", ())
            }
            selected_event_keys.update(event_keys)
            event_ids = sorted({
                event_id for key in event_keys
                for event_id in mapped_events.get(key, ())
            })
            events_by_day.setdefault(day, set()).update(event_ids)
            if uuids:
                observations_by_day.setdefault(day, []).append({
                    "queue_id": str(queue["queue_id"]),
                    "window": str(window["name"]),
                    "start_ns": int(window["start_ns"]),
                    "end_ns": int(window["end_ns"]),
                    "node_ids": sorted(uuids),
                    "event_ids": event_ids,
                })
    payload = {
        "schema_version": "trace-e3-kairos-poi-seal-v1",
        "detector": "KAIROS",
        "dataset": "TRACE_E3",
        "queue_manifest_sha256": str(queue_manifest["content_sha256"]),
        "selected_queue_ids": [str(queue["queue_id"]) for queue in selected],
        "poi_policy": "UUID endpoints of native anomalous edges in selected KAIROS queues",
        "poi_node_ids": sorted(set(mapped.values())),
        "poi_node_ids_by_day": {day: sorted(values) for day, values in sorted(by_day.items())},
        "poi_event_ids_by_day": {
            day: sorted(values) for day, values in sorted(events_by_day.items())
        },
        "poi_observations_by_day": {
            day: sorted(values, key=lambda row: (
                row["start_ns"], row["end_ns"], row["queue_id"], row["window"]
            ))
            for day, values in sorted(observations_by_day.items())
        },
        "event_mapping": {
            "selected_anomalous_keys": len(selected_event_keys),
            "mapped_anomalous_keys": len(selected_event_keys & mapped_events.keys()),
            "mapped_event_ids": len({
                event_id for key in selected_event_keys
                for event_id in mapped_events.get(key, ())
            }),
            "unmapped_anomalous_keys": [
                [src, dst, timestamp]
                for src, dst, timestamp in sorted(selected_event_keys - mapped_events.keys())
            ],
        },
        "mapping": {
            "selected_index_nodes": len(indices),
            "mapped_index_nodes": len(mapped),
            "unmapped_index_nodes": sorted(set(indices) - mapped.keys()),
        },
    }
    payload["content_sha256"] = _sha(payload)
    return payload


__all__ = [
    "TraceLossWindow", "build_native_trace_queues", "choose_final_epoch",
    "group_event_mapping",
    "freeze_trace_pois", "read_loss_window",
]
