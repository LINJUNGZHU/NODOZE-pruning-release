#!/usr/bin/env python3
"""Offline evaluation; all positive authorities enter only this process."""
import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_production_evaluation import evaluate_production


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin", required=True)
    parser.add_argument("--positives", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        positives = json.loads(Path(args.positives).read_text())
        result = evaluate_production(args.pin, positives["event_ids"], positives["node_ids"], args.output)
    except Exception as exc:
        result = {"status": "NOT_COMPLETED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
