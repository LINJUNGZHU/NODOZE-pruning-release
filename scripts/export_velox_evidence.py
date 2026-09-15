#!/usr/bin/env python3
from __future__ import annotations
import argparse
from tc_pruning.detectors.alert_evidence import VeloxEvidenceAdapter
from tc_pruning.detectors.pidsmaker_export import export_evidence

def main() -> int:
    parser = argparse.ArgumentParser(description="Export Velox edge loss evidence with frozen development calibration")
    parser.add_argument("--native", required=True); parser.add_argument("--development", required=True); parser.add_argument("--version", required=True); parser.add_argument("--output", required=True)
    args = parser.parse_args(); export_evidence(VeloxEvidenceAdapter(version=args.version), args.native, args.development, args.output); return 0

if __name__ == "__main__": raise SystemExit(main())
