"""Offline-only assembly of PDF critical events and ORTHRUS node positives."""
from __future__ import annotations

import json
from pathlib import Path

from .detector_seed_production import file_pin
from .orthrus_groundtruth import load_orthrus_groundtruth


def build_offline_positives(critical_edges: str | Path, orthrus_node_csvs) -> dict:
    critical_path = Path(critical_edges).resolve()
    payload = json.loads(critical_path.read_text())
    events = sorted({str(row["event_id"]) for row in payload["critical_edges"]})
    nodes = set()
    sources = []
    for path in orthrus_node_csvs:
        loaded = load_orthrus_groundtruth(path)
        nodes.update(loaded["node_ids"])
        sources.append(file_pin(path))
    return {
        "schema_version": "velox-offline-positives-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "groundtruth_semantics": "PARTIAL_POSITIVE_GT",
        "event_semantics": "PDF-derived known critical events",
        "node_semantics": "ORTHRUS-distributed attack entity labels",
        "event_ids": events,
        "node_ids": sorted(nodes),
        "sources": {"critical_edges": file_pin(critical_path), "orthrus_node_csvs": sources},
    }


__all__ = ["build_offline_positives"]
