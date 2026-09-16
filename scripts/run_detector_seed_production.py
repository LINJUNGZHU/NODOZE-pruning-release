#!/usr/bin/env python3
"""Run or render the sealed four-profile Velox CADETS E3 experiment."""
import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_production import current_code_manifest, reject_authorities, run_production, validate_config, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--pin")
    parser.add_argument("--render", action="store_true", help="Seal an actual artifact recipe into runnable config")
    args = parser.parse_args()
    try:
        reject_authorities([args.config, args.output, args.pin])
        if args.render:
            config = json.loads(Path(args.config).read_text())
            config["code"] = current_code_manifest()
            validate_config(config)
            target = Path(args.output)
            if target.exists():
                raise ValueError("refusing to overwrite rendered config")
            target.parent.mkdir(parents=True, exist_ok=True)
            write_json(target, config)
            result = {"status": "COMPLETED", "config": str(target)}
        else:
            if not args.pin:
                raise ValueError("independent --pin is required")
            result = run_production(args.config, args.output, args.pin)
    except Exception as exc:
        result = {"status": "NOT_COMPLETED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
