from __future__ import annotations

import json
from pathlib import Path

from .store import ProvenanceStore


def prepare_groundtruth_manifest(
    store: ProvenanceStore,
    groundtruth_path: str | Path,
    *,
    output_path: str | Path | None = None,
) -> dict:
    source = Path(groundtruth_path)
    groundtruth_ids = sorted(
        {
            line.strip()
            for line in source.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    )
    store.conn.execute("DROP TABLE IF EXISTS temp.groundtruth_ids")
    store.conn.execute(
        "CREATE TEMP TABLE groundtruth_ids(uuid TEXT PRIMARY KEY)"
    )
    store.conn.executemany(
        "INSERT OR IGNORE INTO groundtruth_ids VALUES (?)",
        ((uuid,) for uuid in groundtruth_ids),
    )
    attack_nodes = sorted(
        row[0]
        for row in store.conn.execute(
            "SELECT n.uuid FROM groundtruth_ids g JOIN nodes n ON n.uuid=g.uuid"
        )
    )
    attack_edges = list(
        store.conn.execute(
            """
            SELECT e.event_id, e.src, e.dst, e.timestamp_ns
            FROM groundtruth_ids g
            JOIN edges e INDEXED BY idx_edges_src ON e.src=g.uuid
            WHERE EXISTS(
                SELECT 1 FROM groundtruth_ids h WHERE h.uuid=e.dst
            )
            ORDER BY e.timestamp_ns, e.id
            """
        )
    )
    if not attack_edges:
        raise ValueError("ground truth does not contain an internal event to use as alert")
    seed_event, seed_src, seed_dst, seed_time = attack_edges[0]
    manifest = {
        "name": "DARPA TC groundtruth-derived NODOZE alert case",
        "seed_event_ids": [seed_event],
        "seed_uuids": sorted({seed_src, seed_dst}),
        "attack_event_ids": sorted(row[0] for row in attack_edges),
        "attack_node_uuids": attack_nodes,
        "metadata": {
            "groundtruth_source": str(source),
            "groundtruth_uuid_count": len(groundtruth_ids),
            "matched_attack_node_count": len(attack_nodes),
            "derived_attack_event_count": len(attack_edges),
            "attack_event_rule": "event src and dst are both ground-truth nodes",
            "seed_rule": "earliest derived internal attack event",
            "seed_timestamp_ns": int(seed_time),
            "warning": "seed event is a groundtruth-derived proxy alert",
        },
    }
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return manifest


__all__ = ["prepare_groundtruth_manifest"]
