from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
from typing import Iterable, Sequence

from .models import StoredEdge
from .store import ProvenanceStore
from .frequency_cache import FrequencyCache


DAY_NS = 86_400_000_000_000


@dataclass(frozen=True, slots=True)
class PathScore:
    event_ids: tuple[str, ...]
    regularity: float
    anomaly: float


@dataclass(slots=True)
class PathScoringResult:
    path_scores: list[PathScore]
    edge_importance: dict[int, float]


@dataclass(slots=True)
class NODOZEFrequencyModel:
    exact_counts: dict[tuple[str, str, str], int]
    source_relation_counts: dict[tuple[str, str], int]
    total_days: int
    incoming_active_days: dict[str, int] | None = None
    outgoing_active_days: dict[str, int] | None = None
    semantic_types: dict[str, str] | None = None
    probability_floor: float = 1e-6
    type_exact_counts: dict[tuple[str, str, str], int] | None = None
    type_source_relation_counts: dict[tuple[str, str], int] | None = None
    backoff_discount: float = 0.1
    stability_floor: float = 0.05

    def __post_init__(self) -> None:
        self.total_days = max(1, int(self.total_days))
        if not 0.0 < self.probability_floor < 1.0:
            raise ValueError("probability_floor must be in (0, 1)")
        if not 0.0 < self.backoff_discount <= 1.0:
            raise ValueError("backoff_discount must be in (0, 1]")
        if not 0.0 < self.stability_floor < 1.0:
            raise ValueError("stability_floor must be in (0, 1)")
        if self.incoming_active_days is None:
            self.incoming_active_days = {}
        if self.outgoing_active_days is None:
            self.outgoing_active_days = {}
        if self.semantic_types is None:
            self.semantic_types = {}
        if self.type_exact_counts is None:
            self.type_exact_counts = {}
        if self.type_source_relation_counts is None:
            self.type_source_relation_counts = {}

    @classmethod
    def from_store(
        cls,
        store: ProvenanceStore,
        *,
        before_timestamp_ns: int | None = None,
    ) -> "NODOZEFrequencyModel":
        day_expression = f"CAST(e.timestamp_ns / {DAY_NS} AS INTEGER)"
        where_clause = (
            "WHERE e.timestamp_ns < ?" if before_timestamp_ns is not None else ""
        )
        parameters = (
            (int(before_timestamp_ns),) if before_timestamp_ns is not None else ()
        )
        exact_counts = {
            (str(row[0]), str(row[1]), str(row[2])): int(row[3])
            for row in store.conn.execute(
                f"""
                SELECT src_semantic, dst_semantic, relation, COUNT(*)
                FROM (
                    SELECT ns.semantic_key AS src_semantic,
                           nd.semantic_key AS dst_semantic,
                           e.relation AS relation,
                           e.host AS host,
                           {day_expression} AS day
                    FROM edges e
                    JOIN nodes ns ON ns.uuid=e.src
                    JOIN nodes nd ON nd.uuid=e.dst
                    {where_clause}
                    GROUP BY src_semantic, dst_semantic, relation, e.host, day
                )
                GROUP BY src_semantic, dst_semantic, relation
                """
            , parameters)
        }
        source_relation_counts = {
            (str(row[0]), str(row[1])): int(row[2])
            for row in store.conn.execute(
                f"""
                SELECT src_semantic, relation, COUNT(*)
                FROM (
                    SELECT ns.semantic_key AS src_semantic,
                           e.relation AS relation,
                           e.host AS host,
                           {day_expression} AS day
                    FROM edges e
                    JOIN nodes ns ON ns.uuid=e.src
                    {where_clause}
                    GROUP BY src_semantic, relation, e.host, day
                )
                GROUP BY src_semantic, relation
                """
            , parameters)
        }
        type_exact_counts = {
            (str(row[0]), str(row[1]), str(row[2])): int(row[3])
            for row in store.conn.execute(
                f"""
                SELECT src_type, dst_type, relation, COUNT(*)
                FROM (
                    SELECT ns.node_type AS src_type,
                           nd.node_type AS dst_type,
                           e.relation AS relation,
                           e.host AS host,
                           {day_expression} AS day
                    FROM edges e
                    JOIN nodes ns ON ns.uuid=e.src
                    JOIN nodes nd ON nd.uuid=e.dst
                    {where_clause}
                    GROUP BY src_type, dst_type, relation, e.host, day
                )
                GROUP BY src_type, dst_type, relation
                """,
                parameters,
            )
        }
        type_source_relation_counts = {
            (str(row[0]), str(row[1])): int(row[2])
            for row in store.conn.execute(
                f"""
                SELECT src_type, relation, COUNT(*)
                FROM (
                    SELECT ns.node_type AS src_type,
                           e.relation AS relation,
                           e.host AS host,
                           {day_expression} AS day
                    FROM edges e
                    JOIN nodes ns ON ns.uuid=e.src
                    {where_clause}
                    GROUP BY src_type, relation, e.host, day
                )
                GROUP BY src_type, relation
                """,
                parameters,
            )
        }
        bounds = store.conn.execute(
            f"SELECT MIN({day_expression}), MAX({day_expression}) FROM edges e {where_clause}",
            parameters,
        ).fetchone()
        total_days = (
            int(bounds[1]) - int(bounds[0]) + 1
            if bounds and bounds[0] is not None and bounds[1] is not None
            else 1
        )
        outgoing_active_days = {
            str(row[0]): int(row[1])
            for row in store.conn.execute(
                f"""
                SELECT ns.semantic_key, COUNT(DISTINCT {day_expression})
                FROM edges e JOIN nodes ns ON ns.uuid=e.src
                {where_clause}
                GROUP BY ns.semantic_key
                """
            , parameters)
        }
        incoming_active_days = {
            str(row[0]): int(row[1])
            for row in store.conn.execute(
                f"""
                SELECT nd.semantic_key, COUNT(DISTINCT {day_expression})
                FROM edges e JOIN nodes nd ON nd.uuid=e.dst
                {where_clause}
                GROUP BY nd.semantic_key
                """
            , parameters)
        }
        semantic_types = {
            str(row[0]): str(row[1])
            for row in store.conn.execute(
                """
                SELECT semantic_key, MIN(node_type)
                FROM nodes
                GROUP BY semantic_key
                """
            )
        }
        return cls(
            exact_counts,
            source_relation_counts,
            total_days,
            incoming_active_days,
            outgoing_active_days,
            semantic_types,
            type_exact_counts=type_exact_counts,
            type_source_relation_counts=type_source_relation_counts,
        )

    @classmethod
    def from_cache(
        cls, store: ProvenanceStore, *, before_timestamp_ns: int | None = None
    ) -> "NODOZEFrequencyModel":
        cache = FrequencyCache(store)
        cache.require()
        cutoff = cache.cutoff_day(before_timestamp_ns)
        where = "WHERE day < ?" if cutoff is not None else ""
        params = (cutoff,) if cutoff is not None else ()
        conn = store.conn
        exact = {
            (str(a), str(b), str(r)): int(c)
            for a, b, r, c in conn.execute(
                f"SELECT src_pattern,dst_pattern,relation,COUNT(*) FROM freq_event_daily {where} GROUP BY 1,2,3",
                params,
            )
        }
        source_rel = {
            (str(a), str(r)): int(c)
            for a, r, c in conn.execute(
                f"SELECT src_pattern,relation,COUNT(*) FROM freq_src_rel_daily {where} GROUP BY 1,2",
                params,
            )
        }
        type_exact = {
            (str(a), str(b), str(r)): int(c)
            for a, b, r, c in conn.execute(
                f"SELECT src_type,dst_type,relation,COUNT(*) FROM freq_type_event_daily {where} GROUP BY 1,2,3",
                params,
            )
        }
        type_source_rel = {
            (str(a), str(r)): int(c)
            for a, r, c in conn.execute(
                f"SELECT src_type,relation,COUNT(*) FROM freq_type_src_rel_daily {where} GROUP BY 1,2",
                params,
            )
        }
        entity_where = (where + (" AND" if where else " WHERE"))
        incoming = {
            str(key): int(days) for key, days in conn.execute(
                f"SELECT semantic_key,COUNT(*) FROM freq_entity_daily {entity_where} direction='in' GROUP BY 1",
                params,
            )
        }
        outgoing = {
            str(key): int(days) for key, days in conn.execute(
                f"SELECT semantic_key,COUNT(*) FROM freq_entity_daily {entity_where} direction='out' GROUP BY 1",
                params,
            )
        }
        bounds = conn.execute(
            f"SELECT MIN(day),MAX(day) FROM freq_relation_daily {where}", params
        ).fetchone()
        total_days = int(bounds[1]) - int(bounds[0]) + 1 if bounds and bounds[0] is not None else 1
        semantic_types = {
            str(row[0]): str(row[1])
            for row in conn.execute("SELECT semantic_key,MIN(node_type) FROM freq_entity_daily GROUP BY 1")
        }
        return cls(
            exact, source_rel, total_days, incoming, outgoing, semantic_types,
            type_exact_counts=type_exact,
            type_source_relation_counts=type_source_rel,
        )

    @staticmethod
    def _semantic(edge: StoredEdge, endpoint: str) -> str:
        semantic = edge.src_semantic if endpoint == "src" else edge.dst_semantic
        return semantic or (edge.src if endpoint == "src" else edge.dst)

    def transition_probability(self, edge: StoredEdge) -> float:
        src = self._semantic(edge, "src")
        dst = self._semantic(edge, "dst")
        numerator = self.exact_counts.get((src, dst, edge.relation), 0)
        denominator = self.source_relation_counts.get((src, edge.relation), 0)
        if numerator > 0 and denominator > 0:
            return min(1.0, max(self.probability_floor, numerator / denominator))
        type_numerator = self.type_exact_counts.get(
            (edge.src_type, edge.dst_type, edge.relation), 0
        )
        type_denominator = self.type_source_relation_counts.get(
            (edge.src_type, edge.relation), 0
        )
        if type_numerator > 0 and type_denominator > 0:
            backed_off = self.backoff_discount * type_numerator / type_denominator
            return min(1.0, max(self.probability_floor, backed_off))
        return self.probability_floor

    def in_score(self, semantic_key: str) -> float:
        data_score = self._data_entity_score(semantic_key)
        if data_score is not None:
            return data_score
        active = self.incoming_active_days.get(semantic_key, 0)
        return min(1.0, max(0.0, 1.0 - active / self.total_days))

    def out_score(self, semantic_key: str) -> float:
        data_score = self._data_entity_score(semantic_key)
        if data_score is not None:
            return data_score
        active = self.outgoing_active_days.get(semantic_key, 0)
        return min(1.0, max(0.0, 1.0 - active / self.total_days))

    def _data_entity_score(self, semantic_key: str) -> float | None:
        node_type = self.semantic_types.get(semantic_key)
        if node_type == "socket":
            return 0.5
        if node_type != "file":
            return None
        lowered = semantic_key.lower()
        if lowered.endswith((".exe", ".dll", ".so", ".sh", ".ps1", ".bat")):
            return 0.1
        incoming = self.incoming_active_days.get(semantic_key, 0)
        outgoing = self.outgoing_active_days.get(semantic_key, 0)
        if incoming > 0 and outgoing == 0:
            return 1.0
        return 0.5

    def edge_anomaly(self, edge: StoredEdge) -> float:
        return 1.0 - self.transition_probability(edge)

    def score_path(
        self,
        path: Sequence[StoredEdge],
        *,
        decay: float = 1.0,
        excluded_event_ids: set[str] | None = None,
    ) -> PathScore:
        if not 0.0 < decay <= 1.0:
            raise ValueError("decay must be in (0, 1]")
        excluded_event_ids = excluded_event_ids or set()
        event_regularities: list[float] = []
        for edge in path:
            if edge.event_id in excluded_event_ids:
                continue
            src = self._semantic(edge, "src")
            dst = self._semantic(edge, "dst")
            event_regularity = (
                max(self.stability_floor, self.in_score(src))
                * self.transition_probability(edge)
                * max(self.stability_floor, self.out_score(dst))
            )
            event_regularities.append(max(self.probability_floor, event_regularity))
        if event_regularities:
            mean_log_regularity = sum(
                math.log(value) for value in event_regularities
            ) / len(event_regularities)
            regularity = math.exp(mean_log_regularity) * decay
        else:
            regularity = 1.0
        regularity = min(1.0, max(0.0, regularity))
        return PathScore(
            tuple(edge.event_id for edge in path),
            regularity,
            1.0 - regularity,
        )

    def score_paths(
        self,
        paths: Iterable[Sequence[StoredEdge]],
        *,
        decay: float = 1.0,
        excluded_event_ids: set[str] | None = None,
    ) -> PathScoringResult:
        path_scores: list[PathScore] = []
        edge_importance: dict[int, float] = defaultdict(float)
        for path in paths:
            materialized = list(path)
            score = self.score_path(
                materialized,
                decay=decay,
                excluded_event_ids=excluded_event_ids,
            )
            path_scores.append(score)
            for edge in materialized:
                edge_importance[edge.edge_id] = max(
                    edge_importance[edge.edge_id], score.anomaly
                )
        return PathScoringResult(path_scores, dict(edge_importance))


__all__ = [
    "NODOZEFrequencyModel",
    "PathScore",
    "PathScoringResult",
]
