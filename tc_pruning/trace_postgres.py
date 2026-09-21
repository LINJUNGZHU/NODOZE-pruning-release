"""Build PIDSMaker's TRACE E3 PostgreSQL input from the local normalized store."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import sqlite3
from typing import Callable, Iterable, Iterator, Sequence


KAIROS_RELATIONS = (
    "EVENT_CONNECT",
    "EVENT_EXECUTE",
    "EVENT_OPEN",
    "EVENT_READ",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_SENDMSG",
    "EVENT_SENDTO",
    "EVENT_WRITE",
    "EVENT_CLONE",
)
SUPPORTED_NODE_TYPES = ("process", "file", "socket")


def _properties(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def node_rows(
    rows: Iterable[Sequence], node_type: str, *, index_start: int | None = None
) -> Iterator[tuple]:
    """Convert normalized nodes to PIDSMaker's three table layouts."""
    dense_index = index_start
    for index_id, uuid, actual_type, label, properties_json in rows:
        if actual_type != node_type:
            continue
        if dense_index is not None:
            index_id = dense_index
            dense_index += 1
        properties = _properties(properties_json)
        if node_type == "process":
            path = str(properties.get("path") or label or "null")
            cmd = str(
                properties.get("cmdLine")
                or properties.get("command")
                or properties.get("exec")
                or label
                or "null"
            )
            yield uuid, uuid, path, cmd, index_id
        elif node_type == "file":
            yield uuid, uuid, str(properties.get("path") or label or "null"), index_id
        elif node_type == "socket":
            yield (
                uuid,
                uuid,
                str(properties.get("localAddress", "null")),
                str(properties.get("localPort", "null")),
                str(properties.get("remoteAddress", "null")),
                str(properties.get("remotePort", "null")),
                index_id,
            )
        else:
            raise ValueError(f"unsupported node type: {node_type}")


def event_rows(rows: Iterable[Sequence]) -> Iterator[tuple]:
    """Emit only KAIROS relations, retaining the store's PIDSMaker-compatible direction."""
    allowed = set(KAIROS_RELATIONS)
    for _id, event_uuid, src, src_index, relation, dst, dst_index, timestamp_ns in rows:
        if relation in allowed:
            yield src, src_index, relation, dst, dst_index, event_uuid, timestamp_ns


class CopyTextStream(io.TextIOBase):
    """Expose an iterable of rows as a bounded-memory PostgreSQL COPY stream."""

    def __init__(self, rows: Iterable[Sequence]):
        self._rows = iter(rows)
        self._buffer = ""
        self.rows_read = 0

    def readable(self) -> bool:
        return True

    @staticmethod
    def _encode(row: Sequence) -> str:
        output = io.StringIO(newline="")
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        writer.writerow([r"\N" if value is None else value for value in row])
        return output.getvalue()

    def read(self, size: int = -1) -> str:
        if size == 0:
            return ""
        if size < 0:
            chunks = [self._buffer]
            self._buffer = ""
            for row in self._rows:
                chunks.append(self._encode(row))
                self.rows_read += 1
            return "".join(chunks)
        while len(self._buffer) < size:
            try:
                row = next(self._rows)
            except StopIteration:
                break
            self._buffer += self._encode(row)
            self.rows_read += 1
        result, self._buffer = self._buffer[:size], self._buffer[size:]
        return result


def _copy(cursor, table: str, columns: str, rows: Iterable[Sequence]) -> int:
    stream = CopyTextStream(rows)
    cursor.copy_expert(
        f"COPY {table} ({columns}) FROM STDIN "
        "WITH (FORMAT CSV, DELIMITER E'\\t', NULL '\\N')",
        stream,
        size=1024 * 1024,
    )
    return stream.rows_read


def build_database(
    sqlite_path: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 5432,
    user: str = "postgres",
    password: str = "postgres",
    database: str = "trace_e3",
    progress: Callable[[str, int], None] | None = None,
) -> dict:
    """Create or reuse a complete TRACE E3 database for PIDSMaker."""
    import psycopg2
    from psycopg2 import sql

    source = Path(sqlite_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    fingerprint = f"dense-v2:{source.stat().st_size}:{source.stat().st_mtime_ns}"
    notify = progress or (lambda _stage, _rows: None)

    admin = psycopg2.connect(host=host, port=port, user=user, password=password, dbname="postgres")
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,))
        if cursor.fetchone() is None:
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    admin.close()

    target = psycopg2.connect(host=host, port=port, user=user, password=password, dbname=database)
    source_db = sqlite3.connect(f"file:{source}?mode=ro&immutable=1", uri=True)
    try:
        with target.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(hashtext('trace-e3-local-import'))")
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS trace_import_metadata "
                "(source_path TEXT, fingerprint TEXT, status TEXT, imported_at TIMESTAMPTZ DEFAULT now())"
            )
            cursor.execute(
                "SELECT status FROM trace_import_metadata "
                "WHERE source_path=%s AND fingerprint=%s ORDER BY imported_at DESC LIMIT 1",
                (str(source), fingerprint),
            )
            found = cursor.fetchone()
            if found == ("COMPLETED",):
                target.commit()
                return {"status": "REUSED", "source": str(source), "fingerprint": fingerprint}

            cursor.execute(
                "DROP TABLE IF EXISTS event_table, subject_node_table, file_node_table, "
                "netflow_node_table CASCADE"
            )
            cursor.execute(
                "CREATE TABLE subject_node_table "
                "(node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL, path VARCHAR, cmd VARCHAR, "
                "index_id BIGINT, PRIMARY KEY(node_uuid, hash_id))"
            )
            cursor.execute(
                "CREATE TABLE file_node_table "
                "(node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL, path VARCHAR, "
                "index_id BIGINT, PRIMARY KEY(node_uuid, hash_id))"
            )
            cursor.execute(
                "CREATE TABLE netflow_node_table "
                "(node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL, src_addr VARCHAR, "
                "src_port VARCHAR, dst_addr VARCHAR, dst_port VARCHAR, index_id BIGINT, "
                "PRIMARY KEY(node_uuid, hash_id))"
            )
            cursor.execute(
                "CREATE TABLE event_table "
                "(src_node VARCHAR, src_index_id VARCHAR, operation VARCHAR, dst_node VARCHAR, "
                "dst_index_id VARCHAR, event_uuid VARCHAR NOT NULL, timestamp_rec BIGINT, "
                "_id BIGSERIAL PRIMARY KEY)"
            )
            cursor.execute("DELETE FROM trace_import_metadata")
            cursor.execute(
                "INSERT INTO trace_import_metadata(source_path,fingerprint,status) VALUES (%s,%s,'RUNNING')",
                (str(source), fingerprint),
            )
            target.commit()

            counts = {}
            node_specs = (
                ("process", "subject_node_table", "node_uuid,hash_id,path,cmd,index_id"),
                ("file", "file_node_table", "node_uuid,hash_id,path,index_id"),
                ("socket", "netflow_node_table", "node_uuid,hash_id,src_addr,src_port,dst_addr,dst_port,index_id"),
            )
            next_index = 0
            for node_type, table, columns in node_specs:
                query = source_db.execute(
                    "SELECT rowid,uuid,node_type,label,properties_json FROM nodes WHERE node_type=?",
                    (node_type,),
                )
                counts[table] = _copy(
                    cursor, table, columns,
                    node_rows(query, node_type, index_start=next_index),
                )
                next_index += counts[table]
                target.commit()
                notify(table, counts[table])

            cursor.execute(
                "CREATE TEMP TABLE node_index_map "
                "(node_uuid VARCHAR PRIMARY KEY, index_id BIGINT) ON COMMIT PRESERVE ROWS"
            )
            cursor.execute(
                "INSERT INTO node_index_map "
                "SELECT node_uuid,index_id FROM subject_node_table UNION ALL "
                "SELECT node_uuid,index_id FROM file_node_table UNION ALL "
                "SELECT node_uuid,index_id FROM netflow_node_table"
            )
            target.commit()

            placeholders = ",".join("?" for _ in KAIROS_RELATIONS)
            event_query = source_db.execute(
                "SELECT e.id,e.original_event_id,e.src,src.rowid,e.relation,e.dst,dst.rowid,e.timestamp_ns "
                "FROM edges e JOIN nodes src ON src.uuid=e.src JOIN nodes dst ON dst.uuid=e.dst "
                f"WHERE e.relation IN ({placeholders}) "
                "AND src.node_type IN ('process','file','socket') "
                "AND dst.node_type IN ('process','file','socket') ORDER BY e.id",
                KAIROS_RELATIONS,
            )
            counts["event_table"] = _copy(
                cursor,
                "event_table",
                "src_node,src_index_id,operation,dst_node,dst_index_id,event_uuid,timestamp_rec",
                event_rows(event_query),
            )
            cursor.execute(
                "UPDATE event_table event SET src_index_id=nodes.index_id::text "
                "FROM node_index_map nodes WHERE event.src_node=nodes.node_uuid"
            )
            cursor.execute(
                "UPDATE event_table event SET dst_index_id=nodes.index_id::text "
                "FROM node_index_map nodes WHERE event.dst_node=nodes.node_uuid"
            )
            target.commit()
            notify("event_table", counts["event_table"])
            cursor.execute("CREATE INDEX event_table_timestamp_idx ON event_table(timestamp_rec)")
            cursor.execute("CREATE INDEX event_table_timestamp_uuid_idx ON event_table(timestamp_rec,event_uuid)")
            cursor.execute("ANALYZE")
            cursor.execute(
                "UPDATE trace_import_metadata SET status='COMPLETED', imported_at=now() "
                "WHERE source_path=%s AND fingerprint=%s",
                (str(source), fingerprint),
            )
            target.commit()
            notify("indexes", 0)
            return {
                "status": "COMPLETED",
                "source": str(source),
                "fingerprint": fingerprint,
                "rows": counts,
            }
    finally:
        source_db.close()
        target.close()
