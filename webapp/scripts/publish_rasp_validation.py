"""Attach only completed, same-configuration validation metrics to the UI."""
import argparse
import json
from pathlib import Path

from scripts.run_rasp import write_json


def publish(suite_path, cache_path):
    suite = json.loads(suite_path.read_text())
    cache = json.loads(cache_path.read_text())
    main = cache["rasp_experiment"]
    if suite["completed"] != len(suite["plan"]["cases"]):
        raise ValueError("validation suite is incomplete")
    for case in suite["cases"]:
        if case["config"] != main["config"] or case["implementation_sha256"] != main["implementation_sha256"]:
            raise ValueError("validation and displayed run use different algorithms")
    cache["rasp_validation"] = suite
    write_json(cache_path, cache)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path("webapp/runtime/theia-case3-demo.json"))
    args = parser.parse_args()
    publish(args.suite, args.cache)
