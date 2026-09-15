#!/usr/bin/env python3
from __future__ import annotations
import argparse
from tc_pruning.detectors.alert_evidence import NODLINKEvidenceAdapter
from tc_pruning.detectors.pidsmaker_export import export_evidence

parser = argparse.ArgumentParser(description="Export NODLINK node evidence with frozen development calibration")
parser.add_argument("--native", required=True); parser.add_argument("--development", required=True); parser.add_argument("--version", required=True); parser.add_argument("--output", required=True)
args = parser.parse_args()
export_evidence(NODLINKEvidenceAdapter(version=args.version), args.native, args.development, args.output)
