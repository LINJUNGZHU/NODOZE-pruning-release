#!/usr/bin/env python3
"""Freeze detector-native TRACE E3 KAIROS queues and POIs before GT is loaded."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from tc_pruning.trace_kairos import (
    build_native_trace_queues,
    choose_final_epoch,
    freeze_trace_pois,
    group_event_mapping,
)


def _atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _graph_paths(root: Path, dates) -> tuple[Path, ...]:
    return tuple(sorted(
        path for day in dates for path in (root / f"graph_{day}").glob("*") if path.is_file()
    ))


def _graph_documents(paths):
    import torch
    for path in paths:
        graph = torch.load(path)
        yield set(map(str, graph.nodes))


def _node_labels(path: Path) -> dict[str, str]:
    import torch
    value = torch.load(path)
    return {str(key): " ".join(map(str, row)) for key, row in value.items()}


def _uuid_mapping(indices, *, host, port, user, password, database):
    import psycopg2
    wanted = sorted(set(map(str, indices)))
    result = {}
    with psycopg2.connect(host=host, port=port, user=user, password=password, dbname=database) as conn:
        with conn.cursor() as cursor:
            for table in ("subject_node_table", "file_node_table", "netflow_node_table"):
                cursor.execute(
                    f"SELECT index_id::text,node_uuid FROM {table} WHERE index_id::text = ANY(%s)",
                    (wanted,),
                )
                for index_id, uuid in cursor.fetchall():
                    result[str(index_id)] = str(uuid)
    return result


def _event_mapping(keys, *, host, port, user, password, database):
    import psycopg2
    from psycopg2.extras import execute_values

    wanted = sorted({(str(src), str(dst), int(timestamp)) for src, dst, timestamp in keys})
    if not wanted:
        return {}
    with psycopg2.connect(
        host=host, port=port, user=user, password=password, dbname=database,
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "CREATE TEMP TABLE wanted_kairos_events "
                "(src_index_id TEXT, dst_index_id TEXT, timestamp_rec BIGINT) "
                "ON COMMIT DROP"
            )
            execute_values(
                cursor,
                "INSERT INTO wanted_kairos_events "
                "(src_index_id,dst_index_id,timestamp_rec) VALUES %s",
                wanted,
                page_size=1_000,
            )
            cursor.execute(
                "SELECT wanted.src_index_id,wanted.dst_index_id,"
                "wanted.timestamp_rec,event.event_uuid "
                "FROM wanted_kairos_events wanted JOIN event_table event "
                "ON event.timestamp_rec=wanted.timestamp_rec "
                "AND event.src_index_id=wanted.src_index_id "
                "AND event.dst_index_id=wanted.dst_index_id"
            )
            return group_event_mapping(cursor.fetchall())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--training-status", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--database-host", default="127.0.0.1")
    parser.add_argument("--database-port", type=int, default=5432)
    parser.add_argument("--database-user", default="postgres")
    parser.add_argument("--database-password", default="postgres")
    parser.add_argument("--database-name", default="trace_e3")
    parser.add_argument("--queue-threshold", type=float, default=20.0)
    args = parser.parse_args()
    status_path = Path(args.training_status).resolve()
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("status") != "COMPLETED" or status.get("dataset") != "TRACE_E3":
        raise ValueError("TRACE E3 KAIROS training is not complete")
    edge_losses = Path(status["paths"]["edge_losses_dir"])
    epoch = choose_final_epoch(edge_losses / "test")
    loss_paths = tuple(sorted(epoch.glob("*.csv")))
    if not loss_paths:
        raise ValueError(f"no current-format loss CSVs in {epoch}")
    graph_root = Path(status["paths"]["graphs_dir"])
    construction = Path(status["paths"]["construction_path"])
    index_path = construction / "indexid2msg" / "indexid2msg.pkl"
    labels = _node_labels(index_path)
    train_graphs = _graph_paths(graph_root, status["split"]["train_dates"])
    test_graphs = _graph_paths(graph_root, status["split"]["test_dates"])
    queues = build_native_trace_queues(
        loss_paths,
        training_documents=_graph_documents(train_graphs),
        test_documents=_graph_documents(test_graphs),
        node_labels=labels, queue_threshold=args.queue_threshold,
    )
    indices = {
        str(node) for queue in queues["queues"] if queue["selected"]
        for node in queue["anomalous_node_ids"]
    }
    event_keys = {
        (str(src), str(dst), int(timestamp))
        for queue in queues["queues"] if queue["selected"]
        for window in queue["window_details"]
        for src, dst, timestamp in window["anomalous_event_keys"]
    }
    mapping = _uuid_mapping(
        indices, host=args.database_host, port=args.database_port,
        user=args.database_user, password=args.database_password,
        database=args.database_name,
    )
    event_mapping = _event_mapping(
        event_keys, host=args.database_host, port=args.database_port,
        user=args.database_user, password=args.database_password,
        database=args.database_name,
    )
    frozen = freeze_trace_pois(
        queues, mapping, event_mapping=event_mapping,
    )
    output = Path(args.output_dir).resolve()
    _atomic(output / "native-queues.json", queues)
    _atomic(output / "kairos-poi-seal.json", frozen)
    _atomic(output / "detector-run.json", {
        "training_status": str(status_path), "model_epoch": epoch.name,
        "queue_manifest_sha256": queues["content_sha256"],
        "poi_seal_sha256": frozen["content_sha256"],
    })
    print(json.dumps({
        "epoch": epoch.name, "selected_queues": len(frozen["selected_queue_ids"]),
        "pois": len(frozen["poi_node_ids"]), "sha256": frozen["content_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
