from __future__ import annotations

import heapq
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True, slots=True)
class ProgressiveSelection:
    selected_edge_ids: frozenset[int]
    audit: dict[int, dict[str, object]]
    removal_rounds: int
    examined_groups: int
    budget_feasible: bool


def progressive_select(
    *,
    edge_scores: Mapping[int, float],
    groups: Iterable[tuple[int, ...]],
    budget_edges: int,
    mandatory_edge_ids: set[int] | None = None,
    eligible_edge_ids: set[int] | None = None,
    dependencies: Mapping[tuple[int, ...], Iterable[tuple[int, ...]]] | None = None,
    previous_edge_ids: set[int] | None = None,
    max_removed_previous_edges: int | None = None,
    edge_evidence: Mapping[int, Mapping[str, object]] | None = None,
    config: Mapping[str, object] | None = None,
) -> ProgressiveSelection:
    """Remove low-utility atomic groups while preserving fixed certificates.

    The selector is label-free. Costs and churn are always counted in raw edge
    IDs, even when several events form one atomic group.
    """
    if budget_edges < 0:
        raise ValueError("budget_edges must be non-negative")
    cfg = dict(config or {})
    unknown_config = set(cfg) - {"consistency_weight", "redundancy_weight"}
    if unknown_config:
        raise ValueError(
            "unknown progressive config fields: "
            + ", ".join(sorted(unknown_config))
        )
    consistency_weight = float(cfg.get("consistency_weight", 0.1))
    redundancy_weight = float(cfg.get("redundancy_weight", 0.02))
    if not 0.0 <= consistency_weight <= 1.0:
        raise ValueError("consistency_weight must be in [0, 1]")
    if not 0.0 <= redundancy_weight <= 0.25:
        raise ValueError("redundancy_weight must be in [0, 0.25]")

    eligible = set(edge_scores) if eligible_edge_ids is None else set(eligible_edge_ids)
    eligible.update(mandatory_edge_ids or set())
    if not eligible <= set(edge_scores):
        raise ValueError("eligible edges must be scored")
    canonical = sorted({
        tuple(sorted(set(group)))
        for group in groups
        if group and set(group) & eligible
    })
    owner: dict[int, tuple[int, ...]] = {}
    for group in canonical:
        for edge_id in group:
            if edge_id not in edge_scores:
                raise ValueError("groups must contain only scored edges")
            if edge_id in owner and owner[edge_id] != group:
                raise ValueError("progressive groups must be disjoint")
            owner[edge_id] = group
    for edge_id in sorted(eligible):
        if edge_id not in owner:
            group = (edge_id,)
            canonical.append(group)
            owner[edge_id] = group
    canonical.sort()
    canonical_set = set(canonical)

    mandatory_by_id = {
        owner[edge_id][0]: owner[edge_id]
        for edge_id in (mandatory_edge_ids or set()) if edge_id in owner
    }
    mandatory_groups = set(mandatory_by_id.values())
    normalized_dependencies: dict[tuple[int, ...], set[tuple[int, ...]]] = {}
    for dependent, required in (dependencies or {}).items():
        dependent_group = tuple(sorted(set(dependent)))
        if dependent_group not in canonical_set:
            raise ValueError("dependency dependent group is unknown")
        required_groups = {tuple(sorted(set(group))) for group in required}
        if not required_groups <= canonical_set:
            raise ValueError("dependency required group is unknown")
        normalized_dependencies[dependent_group] = required_groups
    reverse_dependencies: dict[
        tuple[int, ...], set[tuple[int, ...]]
    ] = defaultdict(set)
    for dependent, required_groups in normalized_dependencies.items():
        for required in required_groups:
            reverse_dependencies[required].add(dependent)

    evidence = edge_evidence or {}
    redundancy_key: dict[tuple[int, ...], str | None] = {}
    for group in canonical:
        keys = [
            str(evidence.get(edge_id, {}).get("redundancy_key"))
            for edge_id in group
            if evidence.get(edge_id, {}).get("redundancy_key") is not None
        ]
        redundancy_key[group] = min(keys) if keys else None
    selected = set(canonical)
    selected_key_counts = Counter(
        key for group, key in redundancy_key.items() if key is not None
    )
    groups_by_key: dict[str, set[tuple[int, ...]]] = defaultdict(set)
    for group, key in redundancy_key.items():
        if key is not None:
            groups_by_key[key].add(group)

    def consistency_for(edge_id: int) -> float:
        row = evidence.get(edge_id, {})
        for name in (
            "consistency", "diffusion_verified", "roundtrip_verification_score"
        ):
            if name in row:
                return float(row[name])
        return 0.0

    def utility(group: tuple[int, ...]) -> float:
        base = max(float(edge_scores[edge_id]) for edge_id in group)
        consistency = max(consistency_for(edge_id) for edge_id in group)
        if not math.isfinite(base) or not math.isfinite(consistency):
            raise ValueError("progressive utility inputs must be finite")
        key = redundancy_key[group]
        redundant = key is not None and selected_key_counts[key] > 1
        return (
            base
            + consistency_weight * consistency
            - redundancy_weight * float(redundant)
        ) / len(group)

    versions = {group: 0 for group in canonical}
    heap = [
        (utility(group), group, 0)
        for group in canonical if group not in mandatory_groups
    ]
    heapq.heapify(heap)
    audit: dict[int, dict[str, object]] = {}
    removed_previous = 0
    removal_round = 0
    examined = 0
    rejected: dict[tuple[int, ...], str] = {}
    selected_cost = sum(len(group) for group in selected)
    for group in mandatory_groups:
        group_utility = utility(group)
        current_group_id = group[0]
        for edge_id in group:
            audit[edge_id] = {
                "group_id": current_group_id, "raw_cost": len(group),
                "removal_priority": group_utility, "removal_attempted": False,
                "attempt_count": 0, "removal_allowed": False,
                "removal_round": None,
                "rejection_reason": "protected_evidence",
            }

    while selected_cost > budget_edges and heap:
        priority, group, version = heapq.heappop(heap)
        if group not in selected or group in rejected or version != versions[group]:
            continue
        current_utility = utility(group)
        if abs(current_utility - priority) > 1e-15:
            versions[group] += 1
            heapq.heappush(heap, (current_utility, group, versions[group]))
            continue
        examined += 1
        reason = ""
        group_ids = set(group)
        previous_cost = len(group_ids & (previous_edge_ids or set()))
        if any(dependent in selected for dependent in reverse_dependencies[group]):
            reason = "required_dependency"
        elif (
            max_removed_previous_edges is not None
            and removed_previous + previous_cost > max_removed_previous_edges
        ):
            reason = "prefix_churn"
        if reason:
            rejected[group] = reason
        else:
            selected.remove(group)
            selected_cost -= len(group)
            removed_previous += previous_cost
            removal_round += 1
            for required in normalized_dependencies.get(group, set()):
                if rejected.get(required) == "required_dependency":
                    del rejected[required]
                    versions[required] += 1
                    heapq.heappush(
                        heap, (utility(required), required, versions[required])
                    )
            key = redundancy_key[group]
            if key is not None:
                selected_key_counts[key] -= 1
                if selected_key_counts[key] == 1:
                    for peer in groups_by_key[key] & selected:
                        versions[peer] += 1
                        heapq.heappush(
                            heap, (utility(peer), peer, versions[peer])
                        )
        current_group_id = group[0]
        for edge_id in group:
            audit[edge_id] = {
                "group_id": current_group_id, "raw_cost": len(group),
                "removal_priority": current_utility, "removal_attempted": True,
                "attempt_count": int(
                    audit.get(edge_id, {}).get("attempt_count", 0)
                ) + 1,
                "removal_allowed": not reason,
                "removal_round": removal_round if not reason else None,
                "rejection_reason": reason or None,
            }

    for group in canonical:
        missing_edges = [edge_id for edge_id in group if edge_id not in audit]
        if not missing_edges:
            continue
        group_utility = utility(group)
        current_group_id = group[0]
        for edge_id in missing_edges:
            audit[edge_id] = {
                "group_id": current_group_id, "raw_cost": len(group),
                "removal_priority": group_utility, "removal_attempted": False,
                "attempt_count": 0,
                "removal_allowed": False, "removal_round": None,
                "rejection_reason": None,
            }
    selected_ids = frozenset(edge_id for group in selected for edge_id in group)
    return ProgressiveSelection(
        selected_ids, audit, removal_round, examined,
        len(selected_ids) <= budget_edges,
    )


__all__ = ["ProgressiveSelection", "progressive_select"]
