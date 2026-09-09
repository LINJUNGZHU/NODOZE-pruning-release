from __future__ import annotations

import hashlib
from collections import defaultdict
from statistics import fmean
from typing import Iterable, Mapping

from .models import Neighborhood, StoredEdge


ENTRY_RANK_PROTOCOL = "depimpact-table8-entry-rank-v1"


def entry_category(node_type: str) -> str | None:
    value = str(node_type).strip().lower()
    if any(token in value for token in ("socket", "netflow", "network")):
        return "network"
    if "file" in value:
        return "file"
    if any(token in value for token in ("process", "subject")):
        return "process"
    return None


def discover_candidate_entries(graph: Neighborhood) -> set[str]:
    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: set[str] = set()
    for edge in graph.edges:
        outgoing.add(edge.src)
        incoming[edge.dst].add(edge.src)

    def system_library(node: str) -> bool:
        record = graph.nodes.get(node)
        if record is None or entry_category(record.node_type) != "file":
            return False
        label = (record.label or record.semantic_key).lower()
        return any(marker in label for marker in ("/lib/", "/lib64/", "/usr/lib/"))

    entries: set[str] = set()
    for node, record in graph.nodes.items():
        category = entry_category(record.node_type)
        parents = incoming.get(node, set())
        # CADETS reuses one UUID for both directions of a network flow.  A
        # later SEND therefore creates an apparent incoming edge even when an
        # earlier RECEIVE made the flow an external entry.  Treat every
        # network-flow object as an entry candidate in this non-versioned CDM.
        if category == "network":
            entries.add(node)
        elif category == "file" and not parents and not system_library(node):
            entries.add(node)
        elif category == "process" and (
            not parents or all(system_library(parent) for parent in parents)
        ):
            entries.add(node)
    return entries


def discover_attack_entries(
    graph: Neighborhood, attack_node_uuids: set[str]
) -> set[str]:
    """Apply the paper's entry predicate, then attach labels offline."""
    return discover_candidate_entries(graph) & set(attack_node_uuids)


def noisy_or_node_scores(
    score_maps: Iterable[Mapping[str, float]],
) -> dict[str, float]:
    complements: dict[str, float] = {}
    for scores in score_maps:
        for node, raw in scores.items():
            value = min(1.0, max(0.0, float(raw)))
            complements[node] = complements.get(node, 1.0) * (1.0 - value)
    return {node: 1.0 - value for node, value in complements.items()}


def _random_score(seed: int, node: str) -> float:
    digest = hashlib.sha256(f"{seed}:{node}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(2**64)


def _midranks(scores: Mapping[str, float], nodes: list[str]) -> dict[str, float]:
    ordered = sorted(nodes, key=lambda node: (-float(scores.get(node, 0.0)), node))
    ranks: dict[str, float] = {}
    start = 0
    while start < len(ordered):
        value = float(scores.get(ordered[start], 0.0))
        end = start + 1
        while end < len(ordered) and float(scores.get(ordered[end], 0.0)) == value:
            end += 1
        rank = ((start + 1) + end) / 2.0
        for node in ordered[start:end]:
            ranks[node] = rank
        start = end
    return ranks


def evaluate_entry_ranks(
    graph: Neighborhood,
    *,
    method_node_scores: Mapping[str, Mapping[str, float]],
    attack_entry_nodes: set[str],
    random_seed: int = 0,
) -> dict:
    entries = discover_candidate_entries(graph)
    by_category: dict[str, list[str]] = defaultdict(list)
    for node in entries:
        category = entry_category(graph.nodes[node].node_type)
        if category is not None:
            by_category[category].append(node)
    covered = entries & attack_entry_nodes
    methods = dict(method_node_scores)
    methods["uniform_random"] = {
        node: _random_score(random_seed, node) for node in entries
    }
    method_results: dict[str, dict] = {}
    for method, scores in methods.items():
        ranks: dict[str, float] = {}
        all_candidate_ranks: dict[str, float] = {}
        for category in ("network", "file", "process"):
            category_ranks = _midranks(scores, sorted(by_category.get(category, [])))
            all_candidate_ranks.update(category_ranks)
            for node in covered:
                if node in category_ranks:
                    ranks[node] = category_ranks[node]
        values = list(ranks.values())
        method_results[method] = {
            "average_rank": fmean(values) if values else None,
            "mean_reciprocal_rank": fmean(1.0 / value for value in values) if values else None,
            "evaluated_attack_entries": len(values),
            "ranks_by_node": dict(sorted(ranks.items())),
            "candidate_entry_scores": {
                node: float(scores.get(node, 0.0)) for node in sorted(entries)
            },
            "candidate_entry_ranks": dict(sorted(all_candidate_ranks.items())),
        }
    return {
        "schema_version": ENTRY_RANK_PROTOCOL,
        "candidate_entry_definition": (
            "DEPIMPACT Section 4.3.2 adapted to non-versioned CADETS: all "
            "network-flow objects (UUIDs are direction-reused), non-library "
            "files without incoming edges, and processes with no parents or "
            "only system-library parents"
        ),
        "attack_entry_definition": (
            "offline manually annotated attack node satisfying the same "
            "online entry predicate"
        ),
        "category_policy": "rank independently within network, file, and process",
        "tie_policy": "descending score with deterministic midrank",
        "random_policy": "SHA-256(seed,node) deterministic uniform score",
        "random_seed": random_seed,
        "candidate_entry_count": len(entries),
        "candidate_entry_counts_by_category": {
            category: len(by_category.get(category, []))
            for category in ("network", "file", "process")
        },
        "attack_entry_count": len(attack_entry_nodes),
        "covered_attack_entry_count": len(covered),
        "attack_entry_coverage": (
            len(covered) / len(attack_entry_nodes) if attack_entry_nodes else None
        ),
        "attack_entry_nodes": sorted(attack_entry_nodes),
        "covered_attack_entry_nodes": sorted(covered),
        "methods": method_results,
        "online_uses_groundtruth": False,
    }


__all__ = [
    "ENTRY_RANK_PROTOCOL", "discover_attack_entries",
    "discover_candidate_entries", "entry_category", "evaluate_entry_ranks",
    "noisy_or_node_scores",
]
