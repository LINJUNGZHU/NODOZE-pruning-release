#!/usr/bin/env python3
"""Run the online CADETS_E3 detector seed benchmark from normalized evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_benchmark import _atomic, _canonical, _reject_bad, _status, run_online_benchmark
from tc_pruning.detectors.alert_evidence import iter_evidence_jsonl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--evidence", action="append", required=True, metavar="RUN_ID=JSONL")
    parser.add_argument("--native-source", action="append", required=True, metavar="RUN_ID=PATH")
    parser.add_argument("--inference-seconds", action="append", default=[], metavar="RUN_ID=SECONDS")
    parser.add_argument("--write-pin", metavar="PATH", help="write the independent root pin outside the online output")
    args = parser.parse_args()
    def mapping(values: list[str], name: str) -> dict[str, str]:
        result = {}
        for item in values:
            key, separator, value = item.partition("=")
            if not separator or not key or not value or key in result: raise ValueError(f"{name} must be unique RUN_ID=VALUE")
            _reject_bad(value, name); result[key] = value
        return result
    outer = Path(args.output) / ".attempts" / "cli" / f"attempt-{__import__('time').time_ns()}"; outer.mkdir(parents=True, exist_ok=False)
    try:
        _reject_bad(args.config, "config")
        evidence_paths = mapping(args.evidence, "evidence")
        for source in evidence_paths.values():
            _reject_bad(source, "evidence")
            if not Path(source).is_file(): raise ValueError("evidence path does not exist")
        native = mapping(args.native_source, "native-source")
        for source in native.values():
            _reject_bad(source, "native-source")
            if not Path(source).exists(): raise ValueError("native source does not exist")
        timings = {key: float(value) for key, value in mapping(args.inference_seconds, "inference-seconds").items()}
        # Do not open evidence until path authority validation above has passed.
        evidence = {detector: iter_evidence_jsonl(source) for detector, source in evidence_paths.items()}
        result = run_online_benchmark(json.loads(Path(args.config).read_text(encoding="utf-8")), evidence, args.output, native_sources=native, inference_seconds=timings)
        if result["status"] == "COMPLETED" and args.write_pin:
            _atomic(Path(args.write_pin), _canonical({"root_manifest_sha256": result["root_manifest_sha256"]}))
        _status(outer, "COMPLETED" if result["status"] == "COMPLETED" else "NOT_COMPLETED", "complete" if result["status"] == "COMPLETED" else "run", None if result["status"] == "COMPLETED" else "one or more runs failed")
    except Exception as exc:
        _status(outer, "NOT_COMPLETED", "input", f"{type(exc).__name__}: {exc}")
        result = {"status": "NOT_COMPLETED", "stage": "input", "reason": str(exc), "attempt_directory": str(outer)}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
