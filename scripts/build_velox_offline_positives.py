#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from tc_pruning.detector_seed_production import write_json
from tc_pruning.velox_offline_truth import build_offline_positives


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--critical-edges", required=True)
    parser.add_argument("--orthrus-nodes", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise ValueError("refusing to overwrite offline positives")
    result = build_offline_positives(args.critical_edges, args.orthrus_nodes)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, result)
    print(json.dumps({"status": "COMPLETED", "events": len(result["event_ids"]), "nodes": len(result["node_ids"]), "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
