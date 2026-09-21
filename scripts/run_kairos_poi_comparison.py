#!/usr/bin/env python3
"""Run the sealed KAIROS-K6 POI-conditioned selector comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.kairos_poi_experiment import run_kairos_k6_poi_comparison


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", default="configs/kairos_k6_poi_comparison.json"
    )
    parser.add_argument(
        "--output",
        default="output/kairos-k6-poi-comparison/evaluation.json",
    )
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    result = run_kairos_k6_poi_comparison(config, args.output)
    print(
        json.dumps(
            {
                "status": result["status"],
                "output": str(Path(args.output).resolve()),
                "content_sha256": result["content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
