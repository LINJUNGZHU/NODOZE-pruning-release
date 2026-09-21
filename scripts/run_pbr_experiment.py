#!/usr/bin/env python3
"""Run one resumable A_rasp-PBR formal experiment directory."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

from tc_pruning.pbr_experiment import _atomic_json, run_formal_experiment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    run_dir = Path(args.run_dir).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["config_path"] = str(config_path)
    try:
        result = run_formal_experiment(config, run_dir)
    except BaseException as error:
        _atomic_json(run_dir / "process-status.json", {
            "status": "FAILED", "pid": os.getpid(),
            "stage": "FAILED", "error_type": type(error).__name__,
            "reason": str(error), "updated_ns": time.time_ns(),
        })
        raise
    print(json.dumps({
        "status": result["status"], "run_id": result["run_id"],
        "content_sha256": result["content_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
