#!/usr/bin/env python3
"""Regenerate the offline scenario-13 audit from a completed PBR run."""
from __future__ import annotations

import argparse
from dataclasses import fields
import json
from pathlib import Path

from tc_pruning.models import StoredEdge
from tc_pruning.pbr_audit import audit_scenario13_bridges, render_audit_markdown
from tc_pruning.pbr_experiment import _atomic_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_directory")
    args = parser.parse_args()
    root = Path(args.run_directory).resolve()
    online = json.loads((root / "online-scenario-13.json").read_text(encoding="utf-8"))
    offline = json.loads((root / "offline-scenario-13.json").read_text(encoding="utf-8"))
    names = {item.name for item in fields(StoredEdge)}
    candidate = tuple(StoredEdge(**{key: value for key, value in row.items() if key in names}) for row in online["candidate_edges"])
    largest = max(online["C_branch_fair"], key=lambda row: row["actual_raw_events"])
    audit = audit_scenario13_bridges(
        candidate_edges=candidate,
        a_selected_event_ids=frozenset(online["A_rasp"]["selected_raw_event_ids"]),
        c_selected_event_ids=frozenset(largest["selected_raw_event_ids"]),
        evaluation=offline["A_rasp"],
        poi_node_ids=frozenset(online["poi_node_ids"]),
        a_evidence=online["a_rasp_evidence"], c_relevance={},
        branch_provenance=online["branch_provenance"],
    )
    _atomic_json(root / "scenario13_bridge_audit.json", audit)
    (root / "scenario13_bridge_audit.md").write_text(render_audit_markdown(audit), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
