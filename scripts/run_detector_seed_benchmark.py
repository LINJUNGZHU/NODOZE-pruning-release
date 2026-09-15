#!/usr/bin/env python3
"""Run the online CADETS_E3 detector seed benchmark from normalized evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_benchmark import run_online_benchmark
from tc_pruning.detectors.alert_evidence import load_evidence_jsonl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--evidence", action="append", required=True, metavar="DETECTOR=JSONL")
    args = parser.parse_args()
    evidence = {}
    for item in args.evidence:
        detector, separator, source = item.partition("=")
        if not separator or not detector or not source:
            parser.error("--evidence must be DETECTOR=JSONL")
        evidence[detector] = load_evidence_jsonl(source)
    result = run_online_benchmark(json.loads(Path(args.config).read_text(encoding="utf-8")), evidence, args.output)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
