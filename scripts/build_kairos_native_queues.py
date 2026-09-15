#!/usr/bin/env python3
"""Build KAIROS queues from native loss windows with frozen parameters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.detectors.kairos_queue import build_native_queues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--training-dir", action="append", default=[])
    parser.add_argument("--test-dir", action="append", required=True)
    parser.add_argument("--beta", type=float, default=100.0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = build_native_queues(
        tuple(Path(value) for value in args.training_dir),
        tuple(Path(value) for value in args.test_dir),
        beta=args.beta,
    )
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    selected = sum(queue["selected"] for queue in payload["queues"])
    print(json.dumps({"queues": len(payload["queues"]), "selected": selected}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
