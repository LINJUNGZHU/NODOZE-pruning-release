#!/usr/bin/env python3
"""CLI for the sealed TRACE E3 KAIROS-POI pruning comparison."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

from tc_pruning.pbr_experiment import _atomic_json
from tc_pruning.trace_kairos_experiment import run_trace_experiment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--poi-seal", required=True)
    parser.add_argument("--queue-manifest", required=True)
    parser.add_argument("--groundtruth", action="append", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--candidate-cap", type=int, default=10_000)
    parser.add_argument("--selection-cap", type=int, default=12_000)
    args = parser.parse_args()
    run_dir = Path(args.run_dir).resolve()
    try:
        result = run_trace_experiment(
            database=args.db, poi_seal_path=args.poi_seal,
            queue_manifest_path=args.queue_manifest,
            groundtruth_paths=args.groundtruth, run_directory=run_dir,
            candidate_cap=args.candidate_cap,
            selection_cap=args.selection_cap,
        )
    except BaseException as error:
        _atomic_json(run_dir / "process-status.json", {
            "status": "FAILED", "pid": os.getpid(), "stage": "PRUNING_OR_EVALUATION",
            "error_type": type(error).__name__, "reason": str(error),
            "updated_ns": time.time_ns(),
        })
        raise
    _atomic_json(run_dir / "process-status.json", {
        "status": "COMPLETED", "pid": os.getpid(), "stage": "COMPLETED",
        "content_sha256": result["content_sha256"], "updated_ns": time.time_ns(),
    })
    print(json.dumps({"status": "COMPLETED", "sha256": result["content_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
