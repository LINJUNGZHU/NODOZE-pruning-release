from __future__ import annotations

from collections.abc import Iterable, Sequence

from .models import StoredEdge


def reconstruct_retained_paths(
    candidate_paths: Iterable[Sequence[StoredEdge]],
    kept_edges: Iterable[StoredEdge],
    anomaly_scores: Sequence[float] | None = None,
    *,
    max_paths: int | None = None,
) -> list[dict]:
    kept_ids = {edge.edge_id for edge in kept_edges}
    scores = list(anomaly_scores or [])
    reconstructed: list[dict] = []
    for index, path in enumerate(candidate_paths):
        materialized = list(path)
        if not materialized or any(edge.edge_id not in kept_ids for edge in materialized):
            continue
        node_uuids = [materialized[0].src]
        node_uuids.extend(edge.dst for edge in materialized)
        reconstructed.append(
            {
                "event_ids": [edge.event_id for edge in materialized],
                "node_uuids": node_uuids,
                "anomaly_score": scores[index] if index < len(scores) else None,
            }
        )
        if max_paths is not None and len(reconstructed) >= max_paths:
            break
    reconstructed.sort(
        key=lambda item: (
            -(item["anomaly_score"] if item["anomaly_score"] is not None else -1.0),
            item["event_ids"],
        )
    )
    return reconstructed


__all__ = ["reconstruct_retained_paths"]
