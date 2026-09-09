from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable

from .cdm import event_backward_anchor
from .models import Neighborhood, StoredEdge


CONTROL_RELATIONS = frozenset(
    {
        "EVENT_CLONE",
        "EVENT_EXECUTE",
        "EVENT_EXIT",
        "EVENT_FORK",
    }
)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _precision(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _f1(precision: float, recall: float | None) -> float | None:
    if recall is None:
        return None
    return 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0


def _is_control(edge: StoredEdge) -> bool:
    return edge.relation in CONTROL_RELATIONS


def associate_groundtruth_components(
    *,
    group_id: str,
    alert_edges: Iterable[StoredEdge],
    groundtruth_edges: Iterable[StoredEdge],
    groundtruth_node_ids: set[str],
) -> dict:
    """Select only ground-truth components touched by one alert group."""
    alerts = list(alert_edges)
    truth = list(groundtruth_edges)
    truth_event_ids = {edge.event_id for edge in truth}
    alert_event_ids = {edge.event_id for edge in alerts}
    anchor_event_ids = sorted(alert_event_ids & truth_event_ids)
    alert_node_ids = {
        endpoint for edge in alerts for endpoint in (edge.src, edge.dst)
    }
    anchor_node_ids = sorted(alert_node_ids & groundtruth_node_ids)
    if not anchor_event_ids and not anchor_node_ids:
        return {
            "group_id": group_id,
            "associated": False,
            "association_status": "none",
            "association_method": None,
            "anchor_event_ids": [],
            "anchor_node_ids": [],
            "attack_event_ids": [],
            "attack_node_ids": [],
        }

    adjacency: dict[str, set[str]] = defaultdict(set)
    event_by_id: dict[str, StoredEdge] = {}
    for edge in truth:
        event_by_id[edge.event_id] = edge
        adjacency[edge.src].add(edge.dst)
        adjacency[edge.dst].add(edge.src)

    starts = set(anchor_node_ids)
    for event_id in anchor_event_ids:
        edge = event_by_id[event_id]
        starts.update((edge.src, edge.dst))
    selected_nodes = set(starts)
    frontier = deque(starts)
    while frontier:
        node = frontier.popleft()
        for neighbor in adjacency.get(node, set()):
            if neighbor not in selected_nodes:
                selected_nodes.add(neighbor)
                frontier.append(neighbor)

    selected_edges = [
        edge
        for edge in truth
        if edge.src in selected_nodes and edge.dst in selected_nodes
    ]
    if anchor_event_ids and anchor_node_ids:
        method = "event_and_node"
    elif anchor_event_ids:
        method = "event"
    else:
        method = "node"
    status = "strong" if anchor_event_ids else "weak"
    return {
        "group_id": group_id,
        "associated": status == "strong",
        "association_status": status,
        "association_method": method,
        "anchor_event_ids": anchor_event_ids,
        "anchor_node_ids": anchor_node_ids,
        "attack_event_ids": sorted({edge.event_id for edge in selected_edges}),
        "attack_node_ids": sorted(selected_nodes & groundtruth_node_ids),
    }


def time_respecting_groundtruth_context(
    alert_edges: Iterable[StoredEdge], groundtruth_edges: Iterable[StoredEdge]
) -> set[str]:
    """Offline-only causal subset used to audit the legacy undirected labels."""
    alerts = list(alert_edges)
    truth = list(groundtruth_edges)
    alert_dependency_keys = {
        (edge.src, edge.dst, edge.relation, edge.timestamp_ns) for edge in alerts
    }
    selected = {
        edge.event_id for edge in truth
        if (edge.src, edge.dst, edge.relation, edge.timestamp_ns)
        in alert_dependency_keys
    } | {edge.event_id for edge in alerts}
    expanded: set[tuple[str, str, int]] = set()
    frontier = deque(
        [
            ("backward", event_backward_anchor(edge), edge.timestamp_ns)
            for edge in alerts
        ]
        + [("forward", edge.dst, edge.timestamp_ns) for edge in alerts]
    )
    while frontier:
        direction, node, anchor = frontier.popleft()
        state = (direction, node, anchor)
        if state in expanded:
            continue
        expanded.add(state)
        for edge in truth:
            if direction == "backward":
                if edge.dst != node or edge.timestamp_ns > anchor:
                    continue
                next_state = (direction, edge.src, edge.timestamp_ns)
            else:
                if edge.src != node or edge.timestamp_ns < anchor:
                    continue
                next_state = (direction, edge.dst, edge.timestamp_ns)
            selected.add(edge.event_id)
            if next_state not in expanded:
                frontier.append(next_state)

    # A POI process and a malicious sibling need not lie on one directed path.
    # If backward tracing proves a process-lineage ancestor, expand forward from
    # that process's creation time to include its other descendant branches.
    lineage_relations = {"EVENT_CLONE", "EVENT_EXECUTE", "EVENT_FORK"}
    event_by_id = {edge.event_id: edge for edge in truth}
    cone_frontier = deque(
        (edge.dst, edge.timestamp_ns)
        for event_id in selected
        if (edge := event_by_id.get(event_id)) is not None
        and edge.relation.upper() in lineage_relations
        and edge.dst_type == "process"
    )
    cone_expanded: set[tuple[str, int]] = set()
    while cone_frontier:
        node, anchor = cone_frontier.popleft()
        state = (node, anchor)
        if state in cone_expanded:
            continue
        cone_expanded.add(state)
        for edge in truth:
            if edge.src != node or edge.timestamp_ns < anchor:
                continue
            selected.add(edge.event_id)
            next_state = (edge.dst, edge.timestamp_ns)
            if next_state not in cone_expanded:
                cone_frontier.append(next_state)
    return selected


def _dependency_metrics(
    *,
    candidate_edges: list[StoredEdge],
    kept_edges: list[StoredEdge],
    truth_edges: list[StoredEdge],
    control: bool,
) -> dict:
    candidate = [edge for edge in candidate_edges if _is_control(edge) is control]
    kept = [edge for edge in kept_edges if _is_control(edge) is control]
    truth_ids = {
        edge.event_id for edge in truth_edges if _is_control(edge) is control
    }
    candidate_ids = {edge.event_id for edge in candidate}
    kept_ids = {edge.event_id for edge in kept}
    true_positive = len(kept_ids & truth_ids)
    false_positive = len(kept_ids - truth_ids)
    false_candidate = len(candidate_ids - truth_ids)
    recall = _ratio(true_positive, len(truth_ids))
    precision = _precision(true_positive, len(kept_ids))
    return {
        "groundtruth_edges": len(truth_ids),
        "candidate_edges": len(candidate_ids),
        "kept_edges": len(kept_ids),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "recall": recall,
        "precision": precision,
        "false_positive_rate": (
            false_positive / false_candidate if false_candidate else 0.0
        ),
    }


def evaluate_alert_context(
    *,
    candidate_graph: Neighborhood,
    kept_edges: Iterable[StoredEdge],
    association: dict,
    groundtruth_edges: Iterable[StoredEdge],
    groundtruth_paths: Iterable[tuple[str, ...]] = (),
) -> dict:
    """Compare one retained alert context with its associated attack graph."""
    if not association.get("attack_event_ids") and not association.get(
        "attack_node_ids"
    ):
        raise ValueError("cannot evaluate an alert without associated ground truth")
    candidate_edges = list(candidate_graph.edges)
    candidate_edge_ids = {edge.edge_id for edge in candidate_edges}
    retained = [edge for edge in kept_edges if edge.edge_id in candidate_edge_ids]
    truth_event_ids = set(association["attack_event_ids"])
    truth_node_ids = set(association["attack_node_ids"])
    local_truth_edges = [
        edge for edge in groundtruth_edges if edge.event_id in truth_event_ids
    ]

    candidate_event_ids = {edge.event_id for edge in candidate_edges}
    kept_event_ids = {edge.event_id for edge in retained}
    candidate_node_ids = set(candidate_graph.nodes)
    kept_node_ids = {
        endpoint for edge in retained for endpoint in (edge.src, edge.dst)
    }
    candidate_true_events = candidate_event_ids & truth_event_ids
    kept_true_events = kept_event_ids & truth_event_ids
    anchor_event_ids = set(association.get("anchor_event_ids", []))
    context_truth_event_ids = truth_event_ids - anchor_event_ids
    candidate_context_event_ids = candidate_event_ids - anchor_event_ids
    kept_context_event_ids = kept_event_ids - anchor_event_ids
    candidate_true_context_events = (
        candidate_context_event_ids & context_truth_event_ids
    )
    kept_true_context_events = kept_context_event_ids & context_truth_event_ids
    candidate_true_nodes = candidate_node_ids & truth_node_ids
    kept_true_nodes = kept_node_ids & truth_node_ids

    edge_recall = _ratio(len(kept_true_events), len(truth_event_ids))
    node_recall = _ratio(len(kept_true_nodes), len(truth_node_ids))
    edge_precision = _precision(len(kept_true_events), len(kept_event_ids))
    node_precision = _precision(len(kept_true_nodes), len(kept_node_ids))
    context_edge_recall = _ratio(
        len(kept_true_context_events), len(context_truth_event_ids)
    )
    context_edge_precision = _precision(
        len(kept_true_context_events), len(kept_context_event_ids)
    )
    conditional_edge_recall = _ratio(
        len(kept_true_events), len(candidate_true_events)
    )
    local_paths = [
        tuple(path) for path in groundtruth_paths
        if path and set(path) <= truth_event_ids
    ]
    critical_event_ids = {event_id for path in local_paths for event_id in path}
    candidate_complete_paths = [
        path for path in local_paths if set(path) <= candidate_event_ids
    ]
    kept_complete_paths = [path for path in local_paths if set(path) <= kept_event_ids]
    edge_by_event = {edge.event_id: edge for edge in local_truth_edges}
    reachable_pairs = 0
    for path in local_paths:
        first = edge_by_event.get(path[0])
        last = edge_by_event.get(path[-1])
        if first is None or last is None:
            continue
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in retained:
            adjacency[edge.src].add(edge.dst)
        reached = {first.src}
        frontier = deque(reached)
        while frontier:
            node = frontier.popleft()
            for neighbor in adjacency.get(node, set()):
                if neighbor not in reached:
                    reached.add(neighbor)
                    frontier.append(neighbor)
        reachable_pairs += last.dst in reached
    return {
        **association,
        "candidate_nodes": len(candidate_node_ids),
        "candidate_edges": len(candidate_event_ids),
        "kept_nodes": len(kept_node_ids),
        "kept_edges": len(kept_event_ids),
        "candidate_attack_node_recall": _ratio(
            len(candidate_true_nodes), len(truth_node_ids)
        ),
        "candidate_attack_edge_recall": _ratio(
            len(candidate_true_events), len(truth_event_ids)
        ),
        "pruned_attack_node_recall": node_recall,
        "pruned_attack_edge_recall": edge_recall,
        "conditional_attack_node_retention": _ratio(
            len(kept_true_nodes), len(candidate_true_nodes)
        ),
        "conditional_attack_edge_retention": _ratio(
            len(kept_true_events), len(candidate_true_events)
        ),
        "conditional_pruning_edge_recall": conditional_edge_recall,
        "critical_edge_recall": _ratio(
            len(kept_event_ids & critical_event_ids), len(critical_event_ids)
        ),
        "entry_to_poi_reachability": _ratio(reachable_pairs, len(local_paths)),
        "complete_path_retention": _ratio(len(kept_complete_paths), len(local_paths)),
        "candidate_complete_path_recall": _ratio(
            len(candidate_complete_paths), len(local_paths)
        ),
        "candidate_context_edge_recall": _ratio(
            len(candidate_true_context_events), len(context_truth_event_ids)
        ),
        "pruned_context_edge_recall": context_edge_recall,
        "conditional_context_edge_retention": _ratio(
            len(kept_true_context_events), len(candidate_true_context_events)
        ),
        "pruned_context_edge_precision": context_edge_precision,
        "pruned_context_edge_f1": _f1(
            context_edge_precision, context_edge_recall
        ),
        "pruned_node_precision": node_precision,
        "pruned_edge_precision": edge_precision,
        "pruned_node_f1": _f1(node_precision, node_recall),
        "pruned_edge_f1": _f1(edge_precision, edge_recall),
        "control_dependency": _dependency_metrics(
            candidate_edges=candidate_edges,
            kept_edges=retained,
            truth_edges=local_truth_edges,
            control=True,
        ),
        "data_dependency": _dependency_metrics(
            candidate_edges=candidate_edges,
            kept_edges=retained,
            truth_edges=local_truth_edges,
            control=False,
        ),
        "counts": {
            "groundtruth_nodes": len(truth_node_ids),
            "groundtruth_edges": len(truth_event_ids),
            "candidate_groundtruth_nodes": len(candidate_true_nodes),
            "candidate_groundtruth_edges": len(candidate_true_events),
            "kept_groundtruth_nodes": len(kept_true_nodes),
            "kept_groundtruth_edges": len(kept_true_events),
            "groundtruth_context_edges": len(context_truth_event_ids),
            "candidate_groundtruth_context_edges": len(
                candidate_true_context_events
            ),
            "kept_groundtruth_context_edges": len(kept_true_context_events),
            "kept_context_edges": len(kept_context_event_ids),
            "critical_edges": len(critical_event_ids),
            "kept_critical_edges": len(kept_event_ids & critical_event_ids),
            "groundtruth_paths": len(local_paths),
            "candidate_complete_paths": len(candidate_complete_paths),
            "kept_complete_paths": len(kept_complete_paths),
            "reachable_entry_poi_pairs": reachable_pairs,
        },
    }


def aggregate_alert_metrics(alerts: Iterable[dict]) -> dict:
    materialized = list(alerts)
    associated = [item for item in materialized if item.get("associated")]
    macro_keys = (
        "candidate_attack_node_recall",
        "candidate_attack_edge_recall",
        "pruned_attack_node_recall",
        "pruned_attack_edge_recall",
        "conditional_attack_node_retention",
        "conditional_attack_edge_retention",
        "conditional_pruning_edge_recall",
        "critical_edge_recall",
        "entry_to_poi_reachability",
        "complete_path_retention",
        "candidate_complete_path_recall",
        "candidate_context_edge_recall",
        "pruned_context_edge_recall",
        "conditional_context_edge_retention",
        "pruned_context_edge_precision",
        "pruned_context_edge_f1",
        "pruned_node_precision",
        "pruned_edge_precision",
        "pruned_node_f1",
        "pruned_edge_f1",
    )
    macro = {}
    for key in macro_keys:
        values = [item[key] for item in associated if item.get(key) is not None]
        macro[key] = sum(values) / len(values) if values else None

    totals = {
        key: sum(item["counts"].get(key, 0) for item in associated)
        for key in (
            "groundtruth_nodes",
            "groundtruth_edges",
            "candidate_groundtruth_nodes",
            "candidate_groundtruth_edges",
            "kept_groundtruth_nodes",
            "kept_groundtruth_edges",
            "groundtruth_context_edges",
            "candidate_groundtruth_context_edges",
            "kept_groundtruth_context_edges",
            "kept_context_edges",
            "critical_edges",
            "kept_critical_edges",
            "groundtruth_paths",
            "candidate_complete_paths",
            "kept_complete_paths",
            "reachable_entry_poi_pairs",
        )
    }
    totals["kept_nodes"] = sum(item["kept_nodes"] for item in associated)
    totals["kept_edges"] = sum(item["kept_edges"] for item in associated)
    micro_node_recall = _ratio(
        totals["kept_groundtruth_nodes"], totals["groundtruth_nodes"]
    )
    micro_edge_recall = _ratio(
        totals["kept_groundtruth_edges"], totals["groundtruth_edges"]
    )
    micro_node_precision = _precision(
        totals["kept_groundtruth_nodes"], totals["kept_nodes"]
    )
    micro_edge_precision = _precision(
        totals["kept_groundtruth_edges"], totals["kept_edges"]
    )
    micro_context_recall = _ratio(
        totals["kept_groundtruth_context_edges"],
        totals["groundtruth_context_edges"],
    )
    micro_context_precision = _precision(
        totals["kept_groundtruth_context_edges"], totals["kept_context_edges"]
    )
    micro = {
        "candidate_attack_node_recall": _ratio(
            totals["candidate_groundtruth_nodes"], totals["groundtruth_nodes"]
        ),
        "candidate_attack_edge_recall": _ratio(
            totals["candidate_groundtruth_edges"], totals["groundtruth_edges"]
        ),
        "pruned_attack_node_recall": micro_node_recall,
        "pruned_attack_edge_recall": micro_edge_recall,
        "conditional_attack_node_retention": _ratio(
            totals["kept_groundtruth_nodes"], totals["candidate_groundtruth_nodes"]
        ),
        "conditional_attack_edge_retention": _ratio(
            totals["kept_groundtruth_edges"], totals["candidate_groundtruth_edges"]
        ),
        "conditional_pruning_edge_recall": _ratio(
            totals["kept_groundtruth_edges"], totals["candidate_groundtruth_edges"]
        ),
        "critical_edge_recall": _ratio(
            totals["kept_critical_edges"], totals["critical_edges"]
        ),
        "entry_to_poi_reachability": _ratio(
            totals["reachable_entry_poi_pairs"], totals["groundtruth_paths"]
        ),
        "complete_path_retention": _ratio(
            totals["kept_complete_paths"], totals["groundtruth_paths"]
        ),
        "candidate_complete_path_recall": _ratio(
            totals["candidate_complete_paths"], totals["groundtruth_paths"]
        ),
        "candidate_context_edge_recall": _ratio(
            totals["candidate_groundtruth_context_edges"],
            totals["groundtruth_context_edges"],
        ),
        "pruned_context_edge_recall": micro_context_recall,
        "conditional_context_edge_retention": _ratio(
            totals["kept_groundtruth_context_edges"],
            totals["candidate_groundtruth_context_edges"],
        ),
        "pruned_context_edge_precision": micro_context_precision,
        "pruned_context_edge_f1": _f1(
            micro_context_precision, micro_context_recall
        ),
        "pruned_node_precision": micro_node_precision,
        "pruned_edge_precision": micro_edge_precision,
        "pruned_node_f1": _f1(micro_node_precision, micro_node_recall),
        "pruned_edge_f1": _f1(micro_edge_precision, micro_edge_recall),
    }
    return {
        "associated_alert_groups": len(associated),
        "weakly_associated_alert_groups": sum(
            item.get("association_status") == "weak" for item in materialized
        ),
        "unassociated_alert_groups": sum(
            item.get("association_status") == "none" for item in materialized
        ),
        "macro": macro,
        "micro": micro,
        "counts": totals,
    }


__all__ = [
    "CONTROL_RELATIONS",
    "aggregate_alert_metrics",
    "associate_groundtruth_components",
    "evaluate_alert_context",
    "time_respecting_groundtruth_context",
]
