from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from .cdm import READ_LIKE_EVENTS
from .store import ProvenanceStore


SCHEMA_VERSION = "kairos-alerts/v1"


def _message_value(message: Any) -> str:
    value = message
    if isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value.strip()
        value = parsed
    if isinstance(value, dict) and len(value) == 1:
        value = next(iter(value.values()))
    return str(value).strip()


def _semantic_values(row: Any, prefix: str) -> set[str]:
    label = str(row[f"{prefix}_label"] or "").strip()
    semantic = str(row[f"{prefix}_semantic"] or "").strip()
    values = {label, semantic}
    if ":" in semantic:
        values.add(semantic.split(":", 1)[1])
    try:
        properties = json.loads(row[f"{prefix}_properties"] or "{}")
    except json.JSONDecodeError:
        properties = {}
    if isinstance(properties, dict):
        values.update(str(item).strip() for item in properties.values())
    return {value for value in values if value}


def _candidate_rows(store: ProvenanceStore, timestamp_ns: int, relation: str) -> list[Any]:
    return list(
        store.conn.execute(
            """
            SELECT e.event_id, e.src, e.dst,
                   sn.label AS src_label, sn.semantic_key AS src_semantic,
                   sn.properties_json AS src_properties,
                   dn.label AS dst_label, dn.semantic_key AS dst_semantic,
                   dn.properties_json AS dst_properties
            FROM edges e INDEXED BY idx_edges_time
            JOIN nodes sn ON sn.uuid=e.src
            JOIN nodes dn ON dn.uuid=e.dst
            WHERE e.timestamp_ns=? AND e.relation=?
            ORDER BY e.id
            """,
            (timestamp_ns, relation),
        )
    )


def _match_edge(store: ProvenanceStore, edge: dict) -> tuple[Any | None, str | None, list[str]]:
    timestamp_ns = int(edge["timestamp_ns"])
    relation = str(edge["relation"])
    candidates = _candidate_rows(store, timestamp_ns, relation)
    candidate_ids = [str(row["event_id"]) for row in candidates]
    if not candidates:
        return None, "no_match", candidate_ids

    src_value = _message_value(edge.get("srcmsg", ""))
    dst_value = _message_value(edge.get("dstmsg", ""))
    semantic_matches = []
    for row in candidates:
        direct = (
            src_value in _semantic_values(row, "src")
            and dst_value in _semantic_values(row, "dst")
        )
        swapped = relation in READ_LIKE_EVENTS and (
            src_value in _semantic_values(row, "dst")
            and dst_value in _semantic_values(row, "src")
        )
        if direct or swapped:
            semantic_matches.append(row)
    if len(semantic_matches) == 1:
        return semantic_matches[0], None, candidate_ids
    if not semantic_matches:
        return None, "semantic_mismatch", candidate_ids
    return None, "ambiguous_match", candidate_ids


def _edge_identity(edge: dict) -> tuple[object, ...]:
    return (
        int(edge["timestamp_ns"]),
        str(edge["relation"]),
        edge.get("srcnode"),
        edge.get("dstnode"),
        _message_value(edge.get("srcmsg", "")),
        _message_value(edge.get("dstmsg", "")),
    )


def prepare_kairos_alert_manifest(
    store: ProvenanceStore,
    input_path: str | Path,
    *,
    output_path: str | Path | None = None,
) -> dict:
    source = Path(input_path)
    document = json.loads(source.read_text(encoding="utf-8"))
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported KAIROS alert schema: {document.get('schema_version')!r}"
        )
    if not isinstance(document.get("alerts"), list):
        raise ValueError("KAIROS alert document must contain an alerts list")

    seed_events: set[str] = set()
    seed_nodes: set[str] = set()
    unmatched: list[dict] = []
    mapped_alerts: list[dict] = []
    seed_event_groups: list[dict] = []
    input_edge_count = 0
    unique_edge_count = 0
    duplicate_edge_count = 0
    for alert in document["alerts"]:
        mapped_ids: list[str] = []
        edges = alert.get("edges", [])
        if not isinstance(edges, list):
            raise ValueError(f"alert {alert.get('window')!r} has a non-list edges field")
        input_edge_count += len(edges)
        unique_edges: list[tuple[int, dict]] = []
        seen_edges: set[tuple[object, ...]] = set()
        for index, edge in enumerate(edges):
            identity = _edge_identity(edge)
            if identity in seen_edges:
                duplicate_edge_count += 1
                continue
            seen_edges.add(identity)
            unique_edges.append((index, edge))
        unique_edge_count += len(unique_edges)
        for index, edge in unique_edges:
            matched, reason, candidate_ids = _match_edge(store, edge)
            if matched is None:
                unmatched.append(
                    {
                        "window": alert.get("window"),
                        "edge_index": index,
                        "reason": reason,
                        "candidate_event_ids": candidate_ids,
                        "edge": edge,
                    }
                )
                continue
            event_id = str(matched["event_id"])
            seed_events.add(event_id)
            seed_nodes.update((str(matched["src"]), str(matched["dst"])))
            mapped_ids.append(event_id)
        mapped_alerts.append(
            {
                "window": alert.get("window"),
                "queue_score": alert.get("queue_score"),
                "threshold": alert.get("threshold"),
                "input_edge_count": len(edges),
                "unique_input_edge_count": len(unique_edges),
                "matched_event_ids": sorted(set(mapped_ids)),
            }
        )
        seed_event_groups.append(
            {
                "group_id": str(alert.get("window") or f"window-{len(seed_event_groups)}"),
                "window": alert.get("window"),
                "queue_score": alert.get("queue_score"),
                "seed_event_ids": sorted(set(mapped_ids)),
            }
        )

    manifest = {
        "name": "KAIROS CADETS E3 detector alerts for NODOZE",
        "seed_event_ids": sorted(seed_events),
        "seed_event_groups": seed_event_groups,
        "seed_uuids": sorted(seed_nodes),
        "attack_event_ids": [],
        "attack_node_uuids": [],
        "alerts": mapped_alerts,
        "unmatched_alert_edges": unmatched,
        "metadata": {
            "source": "KAIROS",
            "dataset": document.get("dataset", "CADETS_E3"),
            "input_file": str(source),
            "input_schema_version": document["schema_version"],
            "threshold_rule": document.get("threshold_rule"),
            "alert_window_count": len(document["alerts"]),
            "input_alert_edge_count": input_edge_count,
            "unique_alert_edge_count": unique_edge_count,
            "duplicate_alert_edge_count": duplicate_edge_count,
            "matched_alert_edge_count": unique_edge_count - len(unmatched),
            "unmatched_alert_edge_count": len(unmatched),
            "matching_rule": (
                "exact timestamp and relation plus endpoint semantics; reversed endpoint "
                "semantics are allowed only for read-like information-flow events"
            ),
            "warning": "KAIROS detector alerts are seeds, not attack ground truth",
        },
    }
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


__all__ = ["prepare_kairos_alert_manifest"]
