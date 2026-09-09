from __future__ import annotations

from dataclasses import dataclass
import time

from .store import ProvenanceStore


DAY_NS = 86_400_000_000_000
CACHE_VERSION = 1


@dataclass(slots=True)
class FrequencyCache:
    """Persistent NoDoze-style event-frequency database built offline."""

    store: ProvenanceStore

    def build(self) -> dict[str, int | float]:
        started = time.perf_counter()
        conn = self.store.conn
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS frequency_cache_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS freq_event_daily (
                day INTEGER NOT NULL, host TEXT NOT NULL,
                src_pattern TEXT NOT NULL, dst_pattern TEXT NOT NULL,
                relation TEXT NOT NULL, event_count INTEGER NOT NULL,
                PRIMARY KEY(day,host,src_pattern,dst_pattern,relation)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_src_rel_daily (
                day INTEGER NOT NULL, host TEXT NOT NULL,
                src_pattern TEXT NOT NULL, relation TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                PRIMARY KEY(day,host,src_pattern,relation)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_type_event_daily (
                day INTEGER NOT NULL, host TEXT NOT NULL,
                src_type TEXT NOT NULL, dst_type TEXT NOT NULL,
                relation TEXT NOT NULL, event_count INTEGER NOT NULL,
                PRIMARY KEY(day,host,src_type,dst_type,relation)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_type_src_rel_daily (
                day INTEGER NOT NULL, host TEXT NOT NULL,
                src_type TEXT NOT NULL, relation TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                PRIMARY KEY(day,host,src_type,relation)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_entity_daily (
                day INTEGER NOT NULL, host TEXT NOT NULL,
                semantic_key TEXT NOT NULL, node_type TEXT NOT NULL,
                direction TEXT NOT NULL, event_count INTEGER NOT NULL,
                PRIMARY KEY(day,host,semantic_key,direction)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_relation_daily (
                day INTEGER NOT NULL, relation TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                PRIMARY KEY(day,relation)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_pattern_daily (
                day INTEGER NOT NULL, src_type TEXT NOT NULL,
                relation TEXT NOT NULL, dst_type TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                PRIMARY KEY(day,src_type,relation,dst_type)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS freq_node_type_first_daily (
                day INTEGER NOT NULL, node_type TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                PRIMARY KEY(day,node_type)
            ) WITHOUT ROWID;
            """
        )
        tables = (
            "freq_event_daily", "freq_src_rel_daily", "freq_type_event_daily",
            "freq_type_src_rel_daily", "freq_entity_daily",
            "freq_relation_daily", "freq_pattern_daily", "freq_node_type_first_daily",
        )
        with conn:
            for table in tables:
                conn.execute(f"DELETE FROM {table}")
            day = f"CAST(e.timestamp_ns / {DAY_NS} AS INTEGER)"
            conn.execute(f"""
                INSERT INTO freq_event_daily
                SELECT {day},e.host,ns.semantic_key,nd.semantic_key,e.relation,COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src JOIN nodes nd ON nd.uuid=e.dst
                GROUP BY 1,2,3,4,5
            """)
            conn.execute(f"""
                INSERT INTO freq_src_rel_daily
                SELECT {day},e.host,ns.semantic_key,e.relation,COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src GROUP BY 1,2,3,4
            """)
            conn.execute(f"""
                INSERT INTO freq_type_event_daily
                SELECT {day},e.host,ns.node_type,nd.node_type,e.relation,COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src JOIN nodes nd ON nd.uuid=e.dst
                GROUP BY 1,2,3,4,5
            """)
            conn.execute(f"""
                INSERT INTO freq_type_src_rel_daily
                SELECT {day},e.host,ns.node_type,e.relation,COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src GROUP BY 1,2,3,4
            """)
            conn.execute(f"""
                INSERT INTO freq_entity_daily
                SELECT {day},e.host,ns.semantic_key,ns.node_type,'out',COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src GROUP BY 1,2,3,4
            """)
            conn.execute(f"""
                INSERT INTO freq_entity_daily
                SELECT {day},e.host,nd.semantic_key,nd.node_type,'in',COUNT(*)
                FROM edges e JOIN nodes nd ON nd.uuid=e.dst GROUP BY 1,2,3,4
            """)
            conn.execute(f"""
                INSERT INTO freq_relation_daily
                SELECT {day},relation,COUNT(*) FROM edges e GROUP BY 1,2
            """)
            conn.execute(f"""
                INSERT INTO freq_pattern_daily
                SELECT {day},ns.node_type,e.relation,nd.node_type,COUNT(*)
                FROM edges e JOIN nodes ns ON ns.uuid=e.src JOIN nodes nd ON nd.uuid=e.dst
                GROUP BY 1,2,3,4
            """)
            conn.execute(f"""
                INSERT INTO freq_node_type_first_daily
                SELECT first_day,node_type,COUNT(*) FROM (
                    SELECT uuid,node_type,MIN(day) AS first_day FROM (
                        SELECT e.src AS uuid,ns.node_type,{day} AS day
                        FROM edges e JOIN nodes ns ON ns.uuid=e.src
                        UNION ALL
                        SELECT e.dst AS uuid,nd.node_type,{day} AS day
                        FROM edges e JOIN nodes nd ON nd.uuid=e.dst
                    ) GROUP BY uuid,node_type
                ) GROUP BY first_day,node_type
            """)
            source_edges = int(conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0])
            maximum_timestamp = conn.execute("SELECT MAX(timestamp_ns) FROM edges").fetchone()[0]
            metadata = {
                "version": str(CACHE_VERSION),
                "source_edges": str(source_edges),
                "maximum_timestamp_ns": str(maximum_timestamp or 0),
                "day_ns": str(DAY_NS),
                "stale": "0",
            }
            conn.executemany(
                "INSERT OR REPLACE INTO frequency_cache_meta(key,value) VALUES (?,?)",
                metadata.items(),
            )
        return {
            "source_edges": source_edges,
            "maximum_timestamp_ns": int(maximum_timestamp or 0),
            "elapsed_seconds": time.perf_counter() - started,
        }

    def require(self) -> None:
        try:
            row = self.store.conn.execute(
                "SELECT value FROM frequency_cache_meta WHERE key='version'"
            ).fetchone()
        except Exception as exc:
            raise RuntimeError(
                "frequency cache is missing; run build-frequency-cache first"
            ) from exc
        if row is None or int(row[0]) != CACHE_VERSION:
            raise RuntimeError(
                "frequency cache is missing or obsolete; run the build-frequency-cache command"
            )
        stale = self.store.conn.execute(
            "SELECT value FROM frequency_cache_meta WHERE key='stale'"
        ).fetchone()
        if stale is not None and stale[0] != "0":
            raise RuntimeError(
                "frequency cache is stale after ingestion; rebuild it offline"
            )

    def explain_online_queries(self) -> dict[str, list[str]]:
        self.require()
        statements = {
            "nodoze_event": (
                "SELECT src_pattern,dst_pattern,relation,COUNT(*) "
                "FROM freq_event_daily WHERE day < ? GROUP BY 1,2,3"
            ),
            "rarity_pattern": (
                "SELECT src_type,relation,dst_type,SUM(event_count) "
                "FROM freq_pattern_daily WHERE day < ? GROUP BY 1,2,3"
            ),
        }
        cutoff = int(
            self.store.conn.execute(
                "SELECT COALESCE(MAX(day)+1,0) FROM freq_relation_daily"
            ).fetchone()[0]
        )
        return {
            name: [str(row[3]) for row in self.store.conn.execute(
                "EXPLAIN QUERY PLAN " + sql, (cutoff,)
            )]
            for name, sql in statements.items()
        }

    @staticmethod
    def cutoff_day(before_timestamp_ns: int | None) -> int | None:
        return None if before_timestamp_ns is None else int(before_timestamp_ns) // DAY_NS


__all__ = ["CACHE_VERSION", "DAY_NS", "FrequencyCache"]
