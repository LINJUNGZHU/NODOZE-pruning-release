from __future__ import annotations

import sqlite3
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .models import EdgeRecord, Neighborhood, NodeRecord, Observation, StoredEdge


@dataclass(slots=True)
class IngestStats:
    nodes_seen: int = 0
    edges_seen: int = 0
    edges_inserted: int = 0


class ProvenanceStore:
    """Disk-backed provenance graph suitable for streaming TC ingestion."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._node_record_cache: dict[str, NodeRecord] = {}
        self._create_schema()

    def __enter__(self) -> "ProvenanceStore":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS nodes (
                uuid TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                host TEXT NOT NULL,
                semantic_key TEXT NOT NULL DEFAULT '',
                properties_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                original_event_id TEXT NOT NULL DEFAULT '',
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                relation TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                host TEXT NOT NULL,
                data_size INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
            CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
            CREATE INDEX IF NOT EXISTS idx_edges_time ON edges(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_edges_src_time ON edges(src, timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_edges_dst_time ON edges(dst, timestamp_ns);
            """
        )
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(nodes)")
        }
        if "semantic_key" not in columns:
            self.conn.execute(
                "ALTER TABLE nodes ADD COLUMN semantic_key TEXT NOT NULL DEFAULT ''"
            )
            self.conn.execute(
                "UPDATE nodes SET semantic_key=label WHERE semantic_key=''"
            )
        if "properties_json" not in columns:
            self.conn.execute(
                "ALTER TABLE nodes ADD COLUMN properties_json TEXT NOT NULL DEFAULT '{}'"
            )
        edge_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(edges)")
        }
        if "original_event_id" not in edge_columns:
            self.conn.execute(
                "ALTER TABLE edges ADD COLUMN original_event_id TEXT NOT NULL DEFAULT ''"
            )
            self.conn.execute(
                "UPDATE edges SET original_event_id=event_id WHERE original_event_id=''"
            )
        if "data_size" not in edge_columns:
            self.conn.execute("ALTER TABLE edges ADD COLUMN data_size INTEGER")
        self.conn.commit()

    def ingest(self, observations: Iterable[Observation], batch_size: int = 10_000) -> IngestStats:
        stats = IngestStats()
        pending = 0
        for observation in observations:
            if isinstance(observation, NodeRecord):
                stats.nodes_seen += 1
                self._upsert_node(observation)
            elif isinstance(observation, EdgeRecord):
                stats.edges_seen += 1
                self._ensure_placeholder(observation.src, observation.host)
                self._ensure_placeholder(observation.dst, observation.host)
                before = self.conn.total_changes
                self._insert_edge(observation)
                if self.conn.total_changes > before:
                    stats.edges_inserted += 1
            pending += 1
            if pending >= batch_size:
                self.conn.commit()
                pending = 0
        self.conn.commit()
        if stats.edges_inserted and self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='frequency_cache_meta'"
        ).fetchone():
            self.conn.execute(
                "INSERT OR REPLACE INTO frequency_cache_meta(key,value) VALUES ('stale','1')"
            )
            self.conn.commit()
        return stats

    @staticmethod
    def _collision_event_id(edge: EdgeRecord) -> str:
        identity = "\x1f".join(
            (
                edge.event_id,
                edge.src,
                edge.dst,
                edge.relation,
                str(edge.timestamp_ns),
                edge.host,
            )
        ).encode("utf-8")
        return f"{edge.event_id}#{hashlib.sha256(identity).hexdigest()[:16]}"

    def _insert_edge(self, edge: EdgeRecord) -> None:
        existing = self.conn.execute(
            """
            SELECT src, dst, relation, timestamp_ns, host, data_size
            FROM edges WHERE event_id=?
            """,
            (edge.event_id,),
        ).fetchone()
        stored_event_id = edge.event_id
        if existing is not None:
            existing_identity = (
                existing["src"],
                existing["dst"],
                existing["relation"],
                int(existing["timestamp_ns"]),
                existing["host"],
                existing["data_size"],
            )
            incoming_identity = (
                edge.src,
                edge.dst,
                edge.relation,
                int(edge.timestamp_ns),
                edge.host,
                edge.data_size,
            )
            if existing_identity == incoming_identity:
                return
            stored_event_id = self._collision_event_id(edge)
        self.conn.execute(
            """
            INSERT OR IGNORE INTO edges
            (event_id, original_event_id, src, dst, relation, timestamp_ns, host, data_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored_event_id,
                edge.event_id,
                edge.src,
                edge.dst,
                edge.relation,
                edge.timestamp_ns,
                edge.host,
                edge.data_size,
            ),
        )

    def _ensure_placeholder(self, uuid: str, host: str) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO nodes
            (uuid, node_type, label, host, semantic_key, properties_json)
            VALUES (?, 'unknown', ?, ?, ?, '{}')
            """,
            (uuid, uuid, host, uuid),
        )

    def _upsert_node(self, node: NodeRecord) -> None:
        self.conn.execute(
            """
            INSERT INTO nodes
            (uuid, node_type, label, host, semantic_key, properties_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(uuid) DO UPDATE SET
                node_type=excluded.node_type,
                label=CASE WHEN excluded.label != '' THEN excluded.label ELSE nodes.label END,
                host=CASE WHEN excluded.host != '' THEN excluded.host ELSE nodes.host END,
                semantic_key=CASE
                    WHEN excluded.semantic_key != '' THEN excluded.semantic_key
                    ELSE nodes.semantic_key
                END,
                properties_json=CASE
                    WHEN excluded.properties_json != '{}' THEN excluded.properties_json
                    ELSE nodes.properties_json
                END
            WHERE nodes.node_type != excluded.node_type
               OR (excluded.label != '' AND nodes.label != excluded.label)
               OR (excluded.host != '' AND nodes.host != excluded.host)
               OR (excluded.semantic_key != '' AND nodes.semantic_key != excluded.semantic_key)
               OR (
                    excluded.properties_json != '{}'
                    AND nodes.properties_json != excluded.properties_json
               )
            """,
            (
                node.uuid,
                node.node_type,
                node.label,
                node.host,
                node.semantic_key,
                json.dumps(node.properties, ensure_ascii=False, sort_keys=True),
            ),
        )

    def node_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0])

    def edge_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0])

    def get_node(self, uuid: str) -> NodeRecord | None:
        if uuid in self._node_record_cache:
            return self._node_record_cache[uuid]
        row = self.conn.execute(
            "SELECT uuid, node_type, label, host, semantic_key, properties_json FROM nodes WHERE uuid=?",
            (uuid,),
        ).fetchone()
        if row is None:
            return None
        node = self._row_to_node(row)
        self._node_record_cache[uuid] = node
        return node

    def _materialize_raw_edges(self, rows: Iterable[sqlite3.Row]) -> list[StoredEdge]:
        materialized = list(rows)
        missing = sorted({
            endpoint for row in materialized for endpoint in (row["src"], row["dst"])
            if endpoint not in self._node_record_cache
        })
        for chunk in self._chunks(missing):
            placeholders = ",".join("?" for _ in chunk)
            for row in self.conn.execute(
                "SELECT uuid,node_type,label,host,semantic_key,properties_json "
                f"FROM nodes WHERE uuid IN ({placeholders})",
                tuple(chunk),
            ):
                self._node_record_cache[row["uuid"]] = self._row_to_node(row)
        result = []
        for row in materialized:
            src = self._node_record_cache.get(row["src"], NodeRecord(row["src"], "unknown", ""))
            dst = self._node_record_cache.get(row["dst"], NodeRecord(row["dst"], "unknown", ""))
            result.append(StoredEdge(
                edge_id=row["id"], event_id=row["event_id"], src=row["src"], dst=row["dst"],
                relation=row["relation"], timestamp_ns=row["timestamp_ns"], host=row["host"],
                src_type=src.node_type, dst_type=dst.node_type,
                src_semantic=src.semantic_key, dst_semantic=dst.semantic_key,
                data_size=row["data_size"],
            ))
        return result

    @staticmethod
    def _row_to_edge(row: sqlite3.Row) -> StoredEdge:
        return StoredEdge(
            edge_id=row["id"],
            event_id=row["event_id"],
            src=row["src"],
            dst=row["dst"],
            relation=row["relation"],
            timestamp_ns=row["timestamp_ns"],
            host=row["host"],
            src_type=row["src_type"],
            dst_type=row["dst_type"],
            src_semantic=row["src_semantic"],
            dst_semantic=row["dst_semantic"],
            data_size=row["data_size"],
        )

    @staticmethod
    def _edge_select() -> str:
        return """
            SELECT e.*,
                   ns.node_type AS src_type,
                   nd.node_type AS dst_type,
                   ns.semantic_key AS src_semantic,
                   nd.semantic_key AS dst_semantic
            FROM edges e
            JOIN nodes ns ON ns.uuid=e.src
            JOIN nodes nd ON nd.uuid=e.dst
        """

    def get_edge_by_event_id(self, event_id: str) -> StoredEdge | None:
        row = self.conn.execute(
            self._edge_select() + " WHERE e.event_id=?", (event_id,)
        ).fetchone()
        return self._row_to_edge(row) if row else None

    def get_directional_edges(
        self,
        node_uuid: str,
        *,
        direction: str,
        minimum_time_ns: int | None,
        maximum_time_ns: int | None,
        scan_limit: int | None = None,
    ) -> list[StoredEdge]:
        if direction not in {"backward", "forward"}:
            raise ValueError("direction must be backward or forward")
        endpoint = "dst" if direction == "backward" else "src"
        clauses = [f"e.{endpoint}=?"]
        parameters: list[object] = [node_uuid]
        if minimum_time_ns is not None:
            clauses.append("e.timestamp_ns>=?")
            parameters.append(minimum_time_ns)
        if maximum_time_ns is not None:
            clauses.append("e.timestamp_ns<=?")
            parameters.append(maximum_time_ns)
        order = "DESC" if direction == "backward" else "ASC"
        limit_clause = ""
        if scan_limit is not None:
            parameters.append(max(1, int(scan_limit)))
            limit_clause = " LIMIT ?"
        rows = self.conn.execute(
            "SELECT e.* FROM edges e"
            + f" WHERE {' AND '.join(clauses)} ORDER BY e.timestamp_ns {order}, e.id"
            + limit_clause,
            tuple(parameters),
        )
        return self._materialize_raw_edges(rows)

    def iter_edges_by_time(
        self, minimum_time_ns: int, maximum_time_ns: int, *, page_size: int = 5000
    ) -> Iterator[list[StoredEdge]]:
        """Yield an inclusive time range with keyset pagination."""
        if minimum_time_ns > maximum_time_ns:
            raise ValueError("minimum_time_ns must not exceed maximum_time_ns")
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        last_time = minimum_time_ns
        last_id = 0
        while True:
            rows = list(self.conn.execute(
                "SELECT e.* FROM edges e INDEXED BY idx_edges_time "
                "WHERE e.timestamp_ns>=? AND e.timestamp_ns<=? "
                "AND (e.timestamp_ns>? OR (e.timestamp_ns=? AND e.id>?)) "
                "ORDER BY e.timestamp_ns,e.id LIMIT ?",
                (
                    minimum_time_ns, maximum_time_ns, last_time, last_time,
                    last_id, page_size,
                ),
            ))
            # Include rows exactly at the lower boundary on the first page.
            if not rows and last_id == 0:
                rows = list(self.conn.execute(
                    "SELECT e.* FROM edges e INDEXED BY idx_edges_time "
                    "WHERE e.timestamp_ns>=? AND e.timestamp_ns<=? "
                    "ORDER BY e.timestamp_ns,e.id LIMIT ?",
                    (minimum_time_ns, maximum_time_ns, page_size),
                ))
            if not rows:
                break
            yield self._materialize_raw_edges(rows)
            last_time = int(rows[-1]["timestamp_ns"])
            last_id = int(rows[-1]["id"])
            if len(rows) < page_size:
                break

    def neighborhood_from_edges(self, edges: Iterable[StoredEdge]) -> Neighborhood:
        unique = {edge.edge_id: edge for edge in edges}
        node_ids = sorted(
            {endpoint for edge in unique.values() for endpoint in (edge.src, edge.dst)}
        )
        nodes: dict[str, NodeRecord] = {}
        for chunk in self._chunks(node_ids):
            placeholders = ",".join("?" for _ in chunk)
            for row in self.conn.execute(
                f"""
                SELECT uuid, node_type, label, host, semantic_key, properties_json
                FROM nodes WHERE uuid IN ({placeholders})
                """,
                tuple(chunk),
            ):
                nodes[row["uuid"]] = self._row_to_node(row)
        return Neighborhood(nodes, list(unique.values()))

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> NodeRecord:
        try:
            properties = json.loads(row["properties_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            properties = {}
        return NodeRecord(
            row["uuid"],
            row["node_type"],
            row["label"],
            row["host"],
            row["semantic_key"],
            properties,
        )

    @staticmethod
    def _chunks(values: Sequence[str], size: int = 400) -> Iterator[Sequence[str]]:
        for start in range(0, len(values), size):
            yield values[start : start + size]

    def extract_neighborhood(
        self,
        seeds: Iterable[str],
        *,
        max_hops: int = 6,
        max_edges: int = 200_000,
    ) -> Neighborhood:
        visited_nodes = set(seeds)
        frontier = set(visited_nodes)
        edge_rows: dict[int, sqlite3.Row] = {}

        for _ in range(max_hops):
            if not frontier or len(edge_rows) >= max_edges:
                break
            next_frontier: set[str] = set()
            ordered_frontier = sorted(frontier)
            for chunk in self._chunks(ordered_frontier):
                placeholders = ",".join("?" for _ in chunk)
                rows = self.conn.execute(
                    f"SELECT * FROM edges WHERE src IN ({placeholders}) OR dst IN ({placeholders}) ORDER BY id",
                    tuple(chunk) + tuple(chunk),
                )
                for row in rows:
                    if row["id"] in edge_rows:
                        continue
                    edge_rows[row["id"]] = row
                    next_frontier.add(row["src"])
                    next_frontier.add(row["dst"])
                    if len(edge_rows) >= max_edges:
                        break
                if len(edge_rows) >= max_edges:
                    break
            next_frontier -= visited_nodes
            visited_nodes.update(next_frontier)
            frontier = next_frontier

        nodes: dict[str, NodeRecord] = {}
        for chunk in self._chunks(sorted(visited_nodes)):
            placeholders = ",".join("?" for _ in chunk)
            for row in self.conn.execute(
                f"""
                SELECT uuid, node_type, label, host, semantic_key, properties_json
                FROM nodes WHERE uuid IN ({placeholders})
                """,
                tuple(chunk),
            ):
                nodes[row["uuid"]] = self._row_to_node(row)

        edges: list[StoredEdge] = []
        for row in edge_rows.values():
            src_type = nodes.get(row["src"], NodeRecord("", "unknown", "")).node_type
            dst_type = nodes.get(row["dst"], NodeRecord("", "unknown", "")).node_type
            src_semantic = nodes.get(
                row["src"], NodeRecord("", "unknown", "")
            ).semantic_key
            dst_semantic = nodes.get(
                row["dst"], NodeRecord("", "unknown", "")
            ).semantic_key
            edges.append(
                StoredEdge(
                    edge_id=row["id"],
                    event_id=row["event_id"],
                    src=row["src"],
                    dst=row["dst"],
                    relation=row["relation"],
                    timestamp_ns=row["timestamp_ns"],
                    host=row["host"],
                    src_type=src_type,
                    dst_type=dst_type,
                    src_semantic=src_semantic,
                    dst_semantic=dst_semantic,
                    data_size=row["data_size"],
                )
            )
        return Neighborhood(nodes=nodes, edges=edges)


__all__ = ["IngestStats", "ProvenanceStore"]
