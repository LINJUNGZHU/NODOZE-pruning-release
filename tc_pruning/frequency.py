from __future__ import annotations

import math
from dataclasses import dataclass

from .models import StoredEdge
from .store import ProvenanceStore
from .frequency_cache import FrequencyCache


@dataclass(slots=True)
class FrequencyModel:
    node_type_counts: dict[str, int]
    relation_counts: dict[str, int]
    pattern_counts: dict[tuple[str, str, str], int]
    node_weight: float = 0.2
    relation_weight: float = 0.3
    pattern_weight: float = 0.5

    @classmethod
    def from_store(
        cls,
        store: ProvenanceStore,
        *,
        before_timestamp_ns: int | None = None,
    ) -> "FrequencyModel":
        where_clause = "WHERE e.timestamp_ns < ?" if before_timestamp_ns is not None else ""
        parameters = (int(before_timestamp_ns),) if before_timestamp_ns is not None else ()
        node_counts = {
            row[0]: int(row[1])
            for row in store.conn.execute(
                f"""
                SELECT node_type, COUNT(DISTINCT uuid)
                FROM (
                    SELECT ns.uuid, ns.node_type
                    FROM edges e JOIN nodes ns ON ns.uuid=e.src
                    {where_clause}
                    UNION ALL
                    SELECT nd.uuid, nd.node_type
                    FROM edges e JOIN nodes nd ON nd.uuid=e.dst
                    {where_clause}
                )
                GROUP BY node_type
                """,
                parameters + parameters,
            )
        }
        relation_counts = {
            row[0]: int(row[1])
            for row in store.conn.execute(
                f"SELECT relation, COUNT(*) FROM edges e {where_clause} GROUP BY relation",
                parameters,
            )
        }
        pattern_counts = {
            (row[0], row[1], row[2]): int(row[3])
            for row in store.conn.execute(
                f"""
                SELECT ns.node_type, e.relation, nd.node_type, COUNT(*)
                FROM edges e
                JOIN nodes ns ON ns.uuid=e.src
                JOIN nodes nd ON nd.uuid=e.dst
                {where_clause}
                GROUP BY ns.node_type, e.relation, nd.node_type
                """,
                parameters,
            )
        }
        return cls(node_counts, relation_counts, pattern_counts)

    @classmethod
    def from_cache(
        cls, store: ProvenanceStore, *, before_timestamp_ns: int | None = None
    ) -> "FrequencyModel":
        cache = FrequencyCache(store)
        cache.require()
        cutoff = cache.cutoff_day(before_timestamp_ns)
        where = "WHERE day < ?" if cutoff is not None else ""
        params = (cutoff,) if cutoff is not None else ()
        conn = store.conn
        nodes = {
            str(kind): int(count) for kind, count in conn.execute(
                f"SELECT node_type,SUM(node_count) FROM freq_node_type_first_daily {where} GROUP BY 1",
                params,
            )
        }
        relations = {
            str(rel): int(count) for rel, count in conn.execute(
                f"SELECT relation,SUM(event_count) FROM freq_relation_daily {where} GROUP BY 1",
                params,
            )
        }
        patterns = {
            (str(src), str(rel), str(dst)): int(count)
            for src, rel, dst, count in conn.execute(
                f"SELECT src_type,relation,dst_type,SUM(event_count) FROM freq_pattern_daily {where} GROUP BY 1,2,3",
                params,
            )
        }
        return cls(nodes, relations, patterns)

    @staticmethod
    def _rarity(count: int, maximum: int) -> float:
        if maximum <= 0 or count <= 0:
            return 1.0
        if maximum == 1:
            return 0.0
        value = 1.0 - math.log1p(count) / math.log1p(maximum)
        return min(1.0, max(0.0, value))

    def edge_rarity(self, edge: StoredEdge) -> float:
        return float(self.edge_rarity_evidence(edge)["score"])

    def edge_rarity_evidence(self, edge: StoredEdge) -> dict[str, object]:
        """Return the complete frequency evidence behind one edge score."""
        max_node = max(self.node_type_counts.values(), default=0)
        max_relation = max(self.relation_counts.values(), default=0)
        max_pattern = max(self.pattern_counts.values(), default=0)
        src_count = self.node_type_counts.get(edge.src_type, 0)
        dst_count = self.node_type_counts.get(edge.dst_type, 0)
        relation_count = self.relation_counts.get(edge.relation, 0)
        node_rarity = (
            self._rarity(src_count, max_node)
            + self._rarity(dst_count, max_node)
        ) / 2.0
        relation_rarity = self._rarity(relation_count, max_relation)
        pattern = (edge.src_type, edge.relation, edge.dst_type)
        pattern_count = self.pattern_counts.get(pattern, 0)
        pattern_rarity = self._rarity(pattern_count, max_pattern)
        total_weight = self.node_weight + self.relation_weight + self.pattern_weight
        if total_weight <= 0:
            raise ValueError("rarity weights must sum to a positive value")
        score = (
            self.node_weight * node_rarity
            + self.relation_weight * relation_rarity
            + self.pattern_weight * pattern_rarity
        ) / total_weight
        score = min(1.0, max(0.0, score))
        return {
            "src_type": edge.src_type,
            "dst_type": edge.dst_type,
            "relation": edge.relation,
            "pattern": list(pattern),
            "src_type_count": src_count,
            "dst_type_count": dst_count,
            "relation_count": relation_count,
            "pattern_count": pattern_count,
            "max_node_type_count": max_node,
            "max_relation_count": max_relation,
            "max_pattern_count": max_pattern,
            "node_rarity": node_rarity,
            "relation_rarity": relation_rarity,
            "pattern_rarity": pattern_rarity,
            "weights": {
                "node": self.node_weight,
                "relation": self.relation_weight,
                "pattern": self.pattern_weight,
            },
            "score": score,
        }


__all__ = ["FrequencyModel"]
