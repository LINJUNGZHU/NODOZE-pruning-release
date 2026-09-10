"""Run the unchanged RASP configuration across declared development cases."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from scripts.run_rasp import write_json


def run(plan_path, output):
    plan = json.loads(plan_path.read_text())
    output.mkdir(parents=True, exist_ok=False)
    config_copy = output/"config.json"
    write_json(config_copy, json.loads(Path(plan["scoring_config"]).read_text()))
    reports = []
    for case in plan["cases"]:
        base = Path(case["scenario"])
        ledger_dir = base / f"poi-prefix-{case['prefix']}-ledger"
        manifest = json.loads((ledger_dir/"manifest.json").read_text())
        if not manifest.get("complete"):
            raise ValueError(f"Incomplete source ledger: {ledger_dir}")
        case_dir = output/case["name"]
        command = [sys.executable, "-u", "-m", "scripts.run_rasp", "--ledger", str(ledger_dir/"edge-scores.jsonl.gz"),
                   "--reference", str(base/"fixed-reference.json"), "--output", str(case_dir), "--config", str(config_copy)]
        print(f"START {case['name']} {' '.join(command)}", flush=True)
        subprocess.run(command, check=True)
        report = json.loads((case_dir/"comparison.json").read_text())
        reports.append({"case": case["name"], "poi_count": case["prefix"], **report})
        write_json(output/"suite.json", {"plan": plan, "completed": len(reports), "cases": reports})
        print(f"FINISHED {case['name']}", flush=True)
    print(f"SUITE COMPLETE {output}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=Path("configs/rasp_cadets_validation.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.plan, args.output)
