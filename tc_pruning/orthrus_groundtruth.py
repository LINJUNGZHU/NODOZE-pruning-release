"""Offline evaluation against the node-level ground truth distributed with ORTHRUS."""

from __future__ import annotations

import ast
import csv
import hashlib
from itertools import groupby
from pathlib import Path
from typing import Any, Iterable, Mapping


_NODE_TYPES = {"subject": "process", "file": "file", "netflow": "socket"}


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def load_orthrus_groundtruth(path: str | Path) -> dict[str, Any]:
    """Load one official ORTHRUS/PIDSMaker per-attack node CSV."""
    source = Path(path)
    nodes: dict[str, dict[str, Any]] = {}
    with source.open("r", encoding="utf-8-sig", newline="") as stream:
        for line_number, row in enumerate(csv.reader(stream), 1):
            if len(row) != 3:
                raise ValueError(f"invalid ORTHRUS ground-truth row {line_number}")
            node_id = row[0].strip()
            attributes = ast.literal_eval(row[1])
            if not node_id or not isinstance(attributes, dict) or len(attributes) != 1:
                raise ValueError(f"invalid ORTHRUS ground-truth node {line_number}")
            raw_type = str(next(iter(attributes)))
            if raw_type not in _NODE_TYPES:
                raise ValueError(f"unsupported ORTHRUS node type: {raw_type}")
            folded = node_id.casefold()
            if folded in nodes:
                raise ValueError(f"duplicate ORTHRUS ground-truth node: {node_id}")
            nodes[folded] = {
                "node_id": node_id,
                "node_type": _NODE_TYPES[raw_type],
                "attributes": attributes,
                "index_id": int(row[2]),
            }
    type_counts = {
        node_type: sum(item["node_type"] == node_type for item in nodes.values())
        for node_type in ("file", "process", "socket")
    }
    type_counts = {key: value for key, value in type_counts.items() if value}
    return {
        "source": str(source.resolve()),
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "semantics": "ORTHRUS node-level ground truth",
        "node_ids": sorted(item["node_id"] for item in nodes.values()),
        "node_type_counts": type_counts,
        "nodes": sorted(nodes.values(), key=lambda item: item["node_id"]),
    }


def _strict_temporal_paths(
    edges: Iterable[Mapping[str, Any]], groundtruth_node_ids: set[str],
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Return one deterministic earliest-arrival path for every reachable GT pair."""
    truth = {str(node).casefold() for node in groundtruth_node_ids}
    ordered = sorted(
        edges,
        key=lambda edge: (
            int(edge["timestamp_ns"]), int(edge["edge_id"]), str(edge["event_id"]),
        ),
    )
    paths: dict[tuple[str, str], tuple[str, ...]] = {}
    for source in sorted(truth):
        # node -> (arrival timestamp, event-ID path); source is reachable before all events.
        best: dict[str, tuple[float | int, tuple[str, ...]]] = {
            source: (float("-inf"), ()),
        }
        for raw_time, group in groupby(ordered, key=lambda edge: int(edge["timestamp_ns"])):
            updates: dict[str, tuple[int, tuple[str, ...]]] = {}
            for edge in group:
                src = str(edge["src"]).casefold()
                dst = str(edge["dst"]).casefold()
                origin = best.get(src)
                if origin is None or origin[0] >= raw_time or dst == source:
                    continue
                candidate = (raw_time, origin[1] + (str(edge["event_id"]),))
                current = best.get(dst)
                pending = updates.get(dst)
                if current is not None and current[0] < raw_time:
                    continue
                if pending is None or (len(candidate[1]), candidate[1]) < (
                    len(pending[1]), pending[1]
                ):
                    updates[dst] = candidate
            for node, candidate in updates.items():
                current = best.get(node)
                if current is None or (candidate[0], len(candidate[1]), candidate[1]) < (
                    current[0], len(current[1]), current[1]
                ):
                    best[node] = candidate
        for target in sorted(truth - {source}):
            if target in best:
                paths[(source, target)] = best[target][1]
    return paths


def evaluate_groundtruth_retention(
    *, candidate_edges: Iterable[Mapping[str, Any]],
    selected_event_ids: set[str], groundtruth_node_ids: set[str],
) -> dict[str, Any]:
    """Count ORTHRUS GT nodes and derived strict-time paths after pruning."""
    candidate = list(candidate_edges)
    selected = [
        edge for edge in candidate if str(edge["event_id"]) in selected_event_ids
    ]
    truth_by_fold = {
        str(node).casefold(): str(node) for node in groundtruth_node_ids
    }
    candidate_nodes = {
        str(endpoint).casefold()
        for edge in candidate for endpoint in (edge["src"], edge["dst"])
    }
    retained_nodes = {
        str(endpoint).casefold()
        for edge in selected for endpoint in (edge["src"], edge["dst"])
    }
    candidate_truth = candidate_nodes & truth_by_fold.keys()
    retained_truth = retained_nodes & truth_by_fold.keys()
    candidate_paths = _strict_temporal_paths(candidate, set(truth_by_fold))
    retained_paths = _strict_temporal_paths(selected, set(truth_by_fold))
    canonical_retained = sum(
        set(path) <= selected_event_ids for path in candidate_paths.values()
    )
    return {
        "groundtruth_semantics": "ORTHRUS node labels; paths derived offline from the full candidate graph",
        "path_semantics": (
            "ordered ORTHRUS-GT node pairs connected by a directed path with strictly "
            "increasing event timestamps; one deterministic earliest-arrival path per pair"
        ),
        "groundtruth_nodes": len(truth_by_fold),
        "candidate_groundtruth_nodes": len(candidate_truth),
        "retained_groundtruth_nodes": len(retained_truth),
        "candidate_groundtruth_node_ids": sorted(
            truth_by_fold[node] for node in candidate_truth
        ),
        "retained_groundtruth_node_ids": sorted(
            truth_by_fold[node] for node in retained_truth
        ),
        "candidate_strict_temporal_paths": len(candidate_paths),
        "retained_strict_temporal_paths": len(retained_paths),
        "canonical_candidate_paths_fully_retained": canonical_retained,
        "candidate_groundtruth_node_coverage": _ratio(
            len(candidate_truth), len(truth_by_fold)
        ),
        "groundtruth_node_retention_after_pruning": _ratio(
            len(retained_truth), len(candidate_truth)
        ),
        "strict_temporal_path_reachability_retention": _ratio(
            len(retained_paths), len(candidate_paths)
        ),
        "canonical_path_event_retention": _ratio(
            canonical_retained, len(candidate_paths)
        ),
    }


_TIME_BUCKETS = (
    ("<=1m", 60_000_000_000),
    ("<=10m", 600_000_000_000),
    ("<=1h", 3_600_000_000_000),
    ("<=6h", 21_600_000_000_000),
    ("<=1d", 86_400_000_000_000),
    (">1d", None),
)
_LENGTH_BUCKETS = (
    ("1-2", 1, 2),
    ("3-5", 3, 5),
    ("6-10", 6, 10),
    (">10", 11, None),
)


def _exclusive_time_bucket(interval_ns: int) -> str:
    for name, upper in _TIME_BUCKETS:
        if upper is None or interval_ns <= upper:
            return name
    raise AssertionError("unreachable time bucket")


def _exclusive_length_bucket(length: int) -> str:
    for name, lower, upper in _LENGTH_BUCKETS:
        if length >= lower and (upper is None or length <= upper):
            return name
    raise ValueError("a strict temporal path must contain at least one edge")


def _path_metric(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    materialized = list(rows)
    exact = sum(bool(row["canonical_complete"]) for row in materialized)
    reachable = sum(bool(row["strict_reachable"]) for row in materialized)
    return {
        "eligible_paths": len(materialized),
        "canonical_complete_paths": exact,
        "strict_reachable_pairs": reachable,
        "canonical_path_retention": _ratio(exact, len(materialized)),
        "strict_temporal_reachability_retention": _ratio(
            reachable, len(materialized)
        ),
    }


def _distribution(values: Iterable[int]) -> dict[str, int | float | None]:
    ordered = sorted(values)
    if not ordered:
        return {"minimum": None, "median": None, "maximum": None}
    middle = len(ordered) // 2
    median = (
        ordered[middle]
        if len(ordered) % 2
        else (ordered[middle - 1] + ordered[middle]) / 2
    )
    return {"minimum": ordered[0], "median": median, "maximum": ordered[-1]}


def evaluate_poi_scoped_retention(
    *,
    candidate_edges: Iterable[Mapping[str, Any]],
    selected_event_ids: set[str],
    groundtruth_node_ids: set[str],
    poi_node_ids: set[str],
) -> dict[str, Any]:
    """Evaluate only strict attack paths whose endpoint set touches a POI.

    ORTHRUS provides node positives rather than complete malicious-edge labels.
    The canonical reference paths are therefore derived offline from the frozen
    candidate envelope.  A path between two non-POI attack nodes is deliberately
    excluded: it cannot be reconstructed from the query represented by this POI.
    """
    candidate = [dict(edge) for edge in candidate_edges]
    selected_ids = {str(event_id) for event_id in selected_event_ids}
    truth = {str(node).casefold() for node in groundtruth_node_ids}
    pois = {str(node).casefold() for node in poi_node_ids}
    if not pois:
        raise ValueError("POI-scoped evaluation requires at least one POI")
    if not pois <= truth:
        raise ValueError("every evaluation POI must be an ORTHRUS attack node")

    event_by_id = {str(edge["event_id"]): edge for edge in candidate}
    if len(event_by_id) != len(candidate):
        raise ValueError("candidate event IDs must be unique")
    candidate_ids = set(event_by_id)
    if not selected_ids <= candidate_ids:
        raise ValueError("selected events must be contained in the K6 envelope")
    selected = [event_by_id[event_id] for event_id in selected_ids]

    all_paths = _strict_temporal_paths(candidate, truth)
    selected_paths = _strict_temporal_paths(selected, truth)
    eligible = {
        pair: path
        for pair, path in all_paths.items()
        if pair[0] in pois or pair[1] in pois
    }
    rows: list[dict[str, Any]] = []
    for (source, target), path in sorted(eligible.items()):
        path_edges = [event_by_id[event_id] for event_id in path]
        interval = int(path_edges[-1]["timestamp_ns"]) - int(
            path_edges[0]["timestamp_ns"]
        )
        if source not in pois and target in pois:
            family = "backward_path"
        elif source in pois and target not in pois:
            family = "forward_path"
        else:
            family = "poi_to_poi_path"
        rows.append(
            {
                "source": source,
                "target": target,
                "event_ids": list(path),
                "family": family,
                "time_interval_ns": interval,
                "path_length": len(path),
                "time_bucket": _exclusive_time_bucket(interval),
                "length_bucket": _exclusive_length_bucket(len(path)),
                "canonical_complete": set(path) <= selected_ids,
                "strict_reachable": (source, target) in selected_paths,
            }
        )

    families = {
        name: _path_metric(row for row in rows if row["family"] == name)
        for name in ("backward_path", "forward_path", "poi_to_poi_path")
    }
    families["anomaly_path"] = _path_metric(rows)
    time_groups = {
        name: _path_metric(row for row in rows if row["time_bucket"] == name)
        for name, _ in _TIME_BUCKETS
    }
    length_groups = {
        name: _path_metric(row for row in rows if row["length_bucket"] == name)
        for name, _, _ in _LENGTH_BUCKETS
    }
    anomaly_time = {
        f"{time_name}|{length_name}": _path_metric(
            row
            for row in rows
            if row["time_bucket"] == time_name
            and row["length_bucket"] == length_name
        )
        for time_name, _ in _TIME_BUCKETS
        for length_name, _, _ in _LENGTH_BUCKETS
    }

    reference_event_ids = {
        event_id for row in rows for event_id in row["event_ids"]
    }
    local_truth_nodes = set(pois)
    for row in rows:
        local_truth_nodes.update((row["source"], row["target"]))
    candidate_nodes = {
        str(endpoint).casefold()
        for edge in candidate
        for endpoint in (edge["src"], edge["dst"])
    }
    selected_nodes = {
        str(endpoint).casefold()
        for edge in selected
        for endpoint in (edge["src"], edge["dst"])
    }
    tp = len(selected_ids & reference_event_ids)
    non_poi_truth_nodes = local_truth_nodes - pois
    non_poi_node_tp = len(selected_nodes & non_poi_truth_nodes)
    contexts_aligned = {
        "reference_subgraph_nodes": len(local_truth_nodes),
        "reference_subgraph_edges": len(reference_event_ids),
        "candidate_nodes": len(candidate_nodes),
        "candidate_edges": len(candidate_ids),
        "output_nodes": len(selected_nodes),
        "output_edges": len(selected_ids),
        "node_tp": len(selected_nodes & local_truth_nodes),
        "node_tpr": _ratio(
            len(selected_nodes & local_truth_nodes), len(local_truth_nodes)
        ),
        "non_poi_reference_nodes": len(non_poi_truth_nodes),
        "non_poi_node_tp": non_poi_node_tp,
        "non_poi_node_recall": _ratio(non_poi_node_tp, len(non_poi_truth_nodes)),
        "tp": tp,
        "tpr": _ratio(tp, len(reference_event_ids)),
        "unlabeled_output_edges": len(selected_ids - reference_event_ids),
        "fp": None,
        "fpr": None,
        "precision": None,
        "f1": None,
        "negative_label_status": "NOT_AVAILABLE_PARTIAL_POSITIVE_GT",
    }
    return {
        "groundtruth_semantics": (
            "ORTHRUS node positives; strict temporal reference paths derived "
            "offline from the frozen common POI candidate"
        ),
        "poi_scope_semantics": (
            "only attack-node pairs with at least one K6-derived POI endpoint"
        ),
        "scope": {
            "groundtruth_nodes": len(truth),
            "poi_nodes": len(pois),
            "all_attack_pair_paths": len(all_paths),
            "eligible_poi_paths": len(rows),
            "excluded_non_poi_paths": len(all_paths) - len(rows),
        },
        "path_families": families,
        "time_path": {
            "by_time_interval": time_groups,
            "by_path_length": length_groups,
            "time_interval_ns": _distribution(
                int(row["time_interval_ns"]) for row in rows
            ),
            "path_length_edges": _distribution(
                int(row["path_length"]) for row in rows
            ),
        },
        "anomaly_time": anomaly_time,
        "contexts_aligned": contexts_aligned,
        "paths": rows,
    }


__all__ = [
    "evaluate_groundtruth_retention",
    "evaluate_poi_scoped_retention",
    "load_orthrus_groundtruth",
]
