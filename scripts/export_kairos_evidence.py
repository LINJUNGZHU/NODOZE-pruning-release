#!/usr/bin/env python3
"""Export detector-native KAIROS loss/queue layers into a portable document."""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import statistics

from tc_pruning.detectors.kairos_adapter import NativeKairosAdapter, NativeKairosEvent
from tc_pruning.store import ProvenanceStore


def queue_windows(log_path: Path) -> dict[str, tuple[tuple[str, float], ...]]:
    result: dict[str, list[tuple[str, float]]] = {}
    pending = None
    queue_index = 0
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "Anomalous queue:" in line:
            pending = ast.literal_eval(line.split("Anomalous queue:", 1)[1].strip())
        elif pending is not None and "Anomaly score:" in line:
            strength = float(line.split("Anomaly score:", 1)[1].strip())
            queue_id = f"queue:{queue_index}"
            for window in pending:
                result.setdefault(str(window), []).append((queue_id, strength))
            queue_index += 1
            pending = None
    return {window: tuple(values) for window, values in result.items()}


def manifest_windows(path: Path) -> dict[str, tuple[tuple[str, float], ...]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[tuple[str, float]]] = {}
    for queue in payload["queues"]:
        if not queue.get("selected", False):
            continue
        for window in queue["windows"]:
            result.setdefault(str(window), []).append(
                (str(queue["queue_id"]), float(queue["score"]))
            )
    return {window: tuple(sorted(values)) for window, values in result.items()}


def native_records(artifact: Path, queue_manifest: Path | None = None, *, day: int):
    membership = (
        manifest_windows(queue_manifest) if queue_manifest is not None
        else queue_windows(artifact / "evaluation.log")
    )
    paths = sorted((artifact / f"graph_4_{day}").glob("*.txt"))
    pending = []
    for path in paths:
        window = path.name
        queues = membership.get(window, ())
        queue_ids = tuple(queue_id for queue_id, _ in queues)
        strength = max((value for _, value in queues), default=0.0)
        values = [
            ast.literal_eval(line) for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines() if line.strip()
        ]
        losses = [float(value["loss"]) for value in values]
        threshold = statistics.fmean(losses) + 1.5 * statistics.pstdev(losses)
        for line_number, value in enumerate(values, 1):
            anomalous = float(value["loss"]) > threshold
            if anomalous or queue_ids:
                pending.append((
                    f"{window}:{line_number}", window, value, anomalous,
                    queue_ids, strength,
                ))
    summary_winners = {}
    for native_id, _, value, anomalous, queue_ids, _ in pending:
        if not anomalous or not queue_ids:
            continue
        key = (queue_ids, str(value["srcmsg"]), str(value["dstmsg"]), str(value["edge_type"]))
        rank = (float(value["loss"]), native_id)
        if key not in summary_winners or rank > summary_winners[key][0]:
            summary_winners[key] = (rank, native_id)
    winner_ids = {native_id for _, native_id in summary_winners.values()}
    for native_id, window, value, anomalous, queue_ids, strength in pending:
        yield NativeKairosEvent(
            native_id, window, int(value["time"]), str(value["edge_type"]),
            str(value["srcmsg"]), str(value["dstmsg"]), float(value["loss"]),
            anomalous_native=anomalous, queue_ids=queue_ids, queue_strength=strength,
            summary_component=(
                f"summary:{'+'.join(queue_ids)}" if native_id in winner_ids else None
            ),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--queue-manifest")
    parser.add_argument("--day", type=int, choices=(6, 12, 13), required=True)
    parser.add_argument("--tolerance-ns", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    artifact = Path(args.artifact)
    with ProvenanceStore(args.db) as store:
        field = NativeKairosAdapter(store, tolerance_ns=args.tolerance_ns).map_records(
            native_records(
                artifact, Path(args.queue_manifest) if args.queue_manifest else None,
                day=args.day,
            )
        )
    output = {
        "schema_version": "kairos-evidence-field-v1",
        "source_hashes": {
            "queue_source": hashlib.sha256(
                (Path(args.queue_manifest) if args.queue_manifest else artifact / "evaluation.log").read_bytes()
            ).hexdigest(),
        },
        "audit": asdict(field.audit),
        "mapping_sha256": field.mapping_sha256,
        "evidence": [asdict(row) for row in field.evidence],
    }
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output["audit"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
