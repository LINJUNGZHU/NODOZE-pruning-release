#!/usr/bin/env python3
"""Offline-only partial-positive evaluation for completed online run directories."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_benchmark_evaluation import evaluate_offline_benchmark


def _ids(path: str) -> list[str]:
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--known-critical-event-ids", required=True)
    parser.add_argument("--known-attack-node-ids", required=True)
    args = parser.parse_args()
    result = evaluate_offline_benchmark(args.run_root, known_critical_event_ids=_ids(args.known_critical_event_ids), known_attack_node_ids=_ids(args.known_attack_node_ids))
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
