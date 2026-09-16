#!/usr/bin/env python3
"""Freeze label-free PIDSMaker Velox outputs into a production recipe."""
import argparse
import json

from tc_pruning.velox_production_recipe import render_velox_config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--training-status", required=True)
    parser.add_argument("--identity-manifest", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = render_velox_config(
            artifact_root=args.artifacts, training_status=args.training_status,
            identity_manifest=args.identity_manifest, database=args.database,
            runtime_root=args.runtime_root, output=args.output,
        )
        payload = {"status": "COMPLETED", "config": args.output,
                   "runs": result["runs"]}
    except Exception as exc:
        payload = {"status": "NOT_COMPLETED", "reason": str(exc)}
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
