#!/usr/bin/env python3
"""Export detector-native KAIROS loss/queue layers into a portable document."""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from tc_pruning.detectors.kairos_adapter import NativeKairosAdapter, NativeKairosEvent
from tc_pruning.store import ProvenanceStore


def queue_windows(log_path: Path) -> dict[str, tuple[str, float]]:
    result = {}
    pending = None
    queue_index = 0
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "Anomalous queue:" in line:
            pending = ast.literal_eval(line.split("Anomalous queue:", 1)[1].strip())
        elif pending is not None and "Anomaly score:" in line:
            strength = float(line.split("Anomaly score:", 1)[1].strip())
            queue_id = f"queue:{queue_index}"
            for window in pending:
                result[str(window)] = (queue_id, strength)
            queue_index += 1
            pending = None
    return result


def native_records(artifact: Path):
    membership = queue_windows(artifact / "evaluation.log")
    for window, (queue_id, strength) in sorted(membership.items()):
        day = int(window[8:10])
        path = artifact / f"graph_4_{day}" / window
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            value = ast.literal_eval(line)
            yield NativeKairosEvent(
                f"{window}:{line_number}", window, int(value["time"]), str(value["edge_type"]),
                str(value["srcmsg"]), str(value["dstmsg"]), float(value["loss"]),
                queue_ids=(queue_id,), queue_strength=strength,
                summary_component=queue_id,
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--tolerance-ns", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    artifact = Path(args.artifact)
    with ProvenanceStore(args.db) as store:
        field = NativeKairosAdapter(store, tolerance_ns=args.tolerance_ns).map_records(
            native_records(artifact)
        )
    output = {
        "schema_version": "kairos-evidence-field-v1",
        "source_hashes": {
            "evaluation_log": hashlib.sha256((artifact / "evaluation.log").read_bytes()).hexdigest(),
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
