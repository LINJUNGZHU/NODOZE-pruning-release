#!/usr/bin/env python3
"""Run the online CADETS_E3 detector seed benchmark from normalized evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_benchmark import _reject_bad, run_online_benchmark
from tc_pruning.detectors.alert_evidence import load_evidence_jsonl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--evidence", action="append", required=True, metavar="RUN_ID=JSONL")
    parser.add_argument("--native-source", action="append", required=True, metavar="RUN_ID=PATH")
    parser.add_argument("--inference-seconds", action="append", default=[], metavar="RUN_ID=SECONDS")
    args = parser.parse_args()
    def mapping(values: list[str], name: str) -> dict[str, str]:
        result = {}
        for item in values:
            key, separator, value = item.partition("=")
            if not separator or not key or not value or key in result: parser.error(f"{name} must be unique RUN_ID=VALUE")
            _reject_bad(value, name); result[key] = value
        return result
    evidence = {}
    for detector, source in mapping(args.evidence, "evidence").items():
        if not Path(source).is_file(): parser.error("evidence path does not exist")
        evidence[detector] = load_evidence_jsonl(source)
    native = mapping(args.native_source, "native-source")
    for source in native.values():
        if not Path(source).exists(): parser.error("native source does not exist")
    timings = {key: float(value) for key, value in mapping(args.inference_seconds, "inference-seconds").items()}
    _reject_bad(args.config, "config")
    result = run_online_benchmark(json.loads(Path(args.config).read_text(encoding="utf-8")), evidence, args.output, native_sources=native, inference_seconds=timings)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
