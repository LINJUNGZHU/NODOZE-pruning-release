from __future__ import annotations

import math
import heapq
from collections import Counter
from dataclasses import dataclass

from .cdm import event_investigation_anchor
from .diffusion import DiffusionResult
from .models import Neighborhood, StoredEdge
from .rdp_guard import fuse_rarity_diffusion


@dataclass(slots=True)
class PruningResult:
    kept_edges: list[StoredEdge]
    edge_scores: dict[int, float]
    threshold: float
    requested_keep_ratio: float
    actual_keep_ratio: float
    selection_mode: str = "ratio"
    edge_score_components: dict[int, dict[str, float]] | None = None
    connectivity_added_edges: int = 0
    budget_edges: int = 0
    budget_rounding_policy: str = "floor_hard_cap_minimum_one"
    minimum_required_edges: int = 0
    budget_feasible: bool = True
    budget_overflow_edges: int = 0
    stage_pairs: int = 0
    connected_stage_pairs: int = 0
    retained_stage_pairs: int = 0
    selection_candidate_edges_examined: int = 0
    scoring_mode: str = "additive"
    score_mass_retained: float = 0.0
    certificate_poi_edges: int = 0
    certificate_retained_poi_edges: int = 0
    path_certificate_valid: bool = False
    path_certificate_status: str = "missing_poi"
    strict_multistage_certificate_valid: bool = False
    causal_path_cover_certificate_valid: bool = False
    certificate_topology: str = "unordered"
    certificate_branch_count: int = 0
    candidate_disconnected_stage_pairs: tuple[tuple[int, int], ...] = ()
    stage_path_witnesses: tuple[tuple[int, int, tuple[int, ...]], ...] = ()
    edge_selection_reasons: dict[int, tuple[str, ...]] | None = None
    previous_candidate_edges: int = 0
    retained_previous_edges: int = 0
    added_edges: int = 0
    removed_previous_edges: int = 0
    declared_allowed_removed_previous_edges: int = 0
    allowed_removed_previous_edges: int = 0
    budget_contraction_edges: int = 0
    atomicity_churn_slack_edges: int = 0
    churn_bound_satisfied: bool = True
    churn_constraint_status: str = "not_applicable"
    prefix_jaccard: float | None = None
    unused_budget_edges: int = 0
    zero_score_fill_stopped: bool = False
    escape_budget_edges: int = 0
    escape_selected_edges: int = 0


def _bounded_atomic_subset(
    groups: list[tuple[int, ...]],
    *,
    capacity: int,
    minimum_edges: int,
) -> tuple[int, set[tuple[int, ...]]]:
    """Choose a deterministic feasible prior-group packing with bitset DP."""
    if capacity <= 0 or not groups:
        return 0, set()
    groups_by_size: dict[int, list[tuple[int, ...]]] = {}
    for members in groups:
        groups_by_size.setdefault(len(members), []).append(members)
    for members_by_size in groups_by_size.values():
        members_by_size.sort()

    mask = (1 << (capacity + 1)) - 1
    reachable = 1
    history: list[tuple[int, int, int]] = []
    # Binary decomposition turns each repeated group size into O(log count)
    # bounded-subset updates while retaining enough history to reconstruct.
    for size in sorted(groups_by_size):
        remaining = len(groups_by_size[size])
        chunk = 1
        while remaining:
            take = min(chunk, remaining)
            shift = size * take
            before = reachable
            reachable = (reachable | (reachable << shift)) & mask
            history.append((before, size, take))
            remaining -= take
            chunk <<= 1

    maximum = reachable.bit_length() - 1
    lower = min(maximum, max(0, minimum_edges))
    available = reachable >> lower
    offset = ((available & -available).bit_length() - 1) if available else 0
    target = lower + offset
    selected_counts: Counter[int] = Counter()
    for before, size, take in reversed(history):
        if (before >> target) & 1:
            continue
        shift = size * take
        if target < shift or not ((before >> (target - shift)) & 1):
            raise RuntimeError("failed to reconstruct atomic churn packing")
        selected_counts[size] += take
        target -= shift
    selected = {
        members
        for size, count in selected_counts.items()
        for members in groups_by_size[size][:count]
    }
    return maximum, selected


def _directed_connectivity_backbone(
    graph: Neighborhood,
    edge_scores: dict[int, float],
    core_edge_ids: set[int],
    target_edge_ids: set[int],
) -> set[int]:
    """Return minimum-cost, time-respecting bridges from core edges to POIs."""
    paths = _directed_connectivity_paths(graph, edge_scores, target_edge_ids)
    return {
        bridge
        for edge_id in core_edge_ids
        for bridge in paths.get(edge_id, ())
    } | {
        edge_id for edge_id in target_edge_ids
        if any(edge.edge_id == edge_id for edge in graph.edges)
    }


def _directed_connectivity_paths(
    graph: Neighborhood,
    edge_scores: dict[int, float],
    target_edge_ids: set[int],
) -> dict[int, tuple[int, ...]]:
    """Plan strict time-respecting edge-to-target bridges in one DAG pass.

    Processing events in descending canonical order makes ``best[node]`` the
    cheapest continuation whose first edge is strictly later than the edge
    currently being queried.  This avoids the node-only timestamp ambiguity
    of an ordinary reverse shortest-path traversal.
    """
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    paths: dict[int, tuple[int, ...]] = {}
    # Value is (total bridge cost, lexicographically deterministic edge path).
    best: dict[str, tuple[float, tuple[int, ...]]] = {}

    def improve(node: str, candidate: tuple[float, tuple[int, ...]]) -> None:
        incumbent = best.get(node)
        if incumbent is None or candidate < incumbent:
            best[node] = candidate

    target_ids_present = set(target_edge_ids) & set(edge_by_id)
    for edge in sorted(
        graph.edges,
        key=lambda item: (item.timestamp_ns, item.edge_id),
        reverse=True,
    ):
        if edge.edge_id in target_ids_present:
            paths[edge.edge_id] = ()
            improve(edge.src, (0.0, ()))
            improve(edge.dst, (0.0, ()))
            continue
        continuation = best.get(edge.dst)
        if continuation is None:
            continue
        paths[edge.edge_id] = continuation[1]
        edge_cost = max(1e-9, 1.0 - edge_scores.get(edge.edge_id, 0.0))
        improve(
            edge.src,
            (edge_cost + continuation[0], (edge.edge_id, *continuation[1])),
        )
    return paths


def _ordered_path_cover_backbone(
    graph: Neighborhood,
    edge_scores: dict[int, float],
    ordered_edge_sequences: tuple[tuple[int, ...], ...],
) -> tuple[
    set[int],
    int,
    int,
    tuple[tuple[int, int, tuple[int, ...]], ...],
    tuple[tuple[int, int], ...],
]:
    """Return strict bridges for every declared path in a causal path cover.

    Separate sequences are separate causal branches.  We never manufacture a
    bridge across a branch boundary, and every adjacent pair declared within a
    sequence must be observable in the candidate graph for the certificate to
    be valid.
    """
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    backbone = {
        edge_id
        for sequence in ordered_edge_sequences
        for edge_id in sequence
        if edge_id in edge_by_id
    }
    stage_pairs = sum(max(0, len(sequence) - 1) for sequence in ordered_edge_sequences)
    connected_pairs = 0
    witnesses: list[tuple[int, int, tuple[int, ...]]] = []
    disconnected: list[tuple[int, int]] = []
    for sequence in ordered_edge_sequences:
        for start_id, target_id in zip(sequence, sequence[1:]):
            start = edge_by_id.get(start_id)
            target = edge_by_id.get(target_id)
            if start is None or target is None:
                continue
            if (target.timestamp_ns, target.edge_id) <= (
                start.timestamp_ns, start.edge_id
            ):
                disconnected.append((start_id, target_id))
                continue
            path = _time_respecting_stage_path(
                graph, edge_scores, start=start, target=target
            )
            if path is None:
                disconnected.append((start_id, target_id))
                continue
            connected_pairs += 1
            backbone.update(path)
            witnesses.append((start_id, target_id, path))
    return (
        backbone,
        stage_pairs,
        connected_pairs,
        tuple(witnesses),
        tuple(disconnected),
    )


def _causal_endpoints(edge: StoredEdge) -> tuple[str, str]:
    if edge.relation.upper() == "EVENT_EXECUTE":
        return edge.dst, edge.src
    return edge.src, edge.dst


def _time_respecting_stage_path(
    graph: Neighborhood,
    edge_scores: dict[int, float],
    *,
    start: StoredEdge,
    target: StoredEdge,
) -> tuple[int, ...] | None:
    """Find a deterministic minimum-cost witness in the timestamp DAG.

    Each update stores its own predecessor state. A later, cheaper arrival at
    the same node can therefore never corrupt a witness that used an earlier
    arrival, which is the failure mode of a node-only reverse predecessor map.
    """
    _, start_target = _causal_endpoints(start)
    target_source, _ = _causal_endpoints(target)
    start_nodes = {start_target, event_investigation_anchor(start)}
    target_nodes = {target_source, event_investigation_anchor(target)}
    if start_nodes & target_nodes or start.edge_id == target.edge_id:
        return ()
    # State tuple: (cost, arrival timestamp, arrival edge ID, state index).
    best: dict[str, tuple[float, int, int, int]] = {
        node: (0.0, start.timestamp_ns, start.edge_id, -1)
        for node in start_nodes
    }
    # Each state is (parent state index, edge ID, reached node).
    states: list[tuple[int, int, str]] = []
    start_key = (start.timestamp_ns, start.edge_id)
    target_key = (target.timestamp_ns, target.edge_id)
    for edge in sorted(
        (
            edge for edge in graph.edges
            if start_key < (edge.timestamp_ns, edge.edge_id) < target_key
            and edge.edge_id not in {start.edge_id, target.edge_id}
        ),
        key=lambda item: (item.timestamp_ns, item.edge_id),
    ):
        source, destination = _causal_endpoints(edge)
        source_state = best.get(source)
        if source_state is None:
            continue
        edge_key = (edge.timestamp_ns, edge.edge_id)
        if edge_key <= (source_state[1], source_state[2]):
            continue
        candidate_cost = source_state[0] + max(
            1e-9, 1.0 - edge_scores.get(edge.edge_id, 0.0)
        )
        candidate_key = (candidate_cost, edge.timestamp_ns, edge.edge_id)
        incumbent = best.get(destination)
        if incumbent is not None and candidate_key >= incumbent[:3]:
            continue
        state_index = len(states)
        states.append((source_state[3], edge.edge_id, destination))
        best[destination] = (*candidate_key, state_index)
    reachable = [best[node] for node in target_nodes if node in best]
    if not reachable:
        return None
    state_index = min(reachable)[3]
    path: list[int] = []
    while state_index >= 0:
        parent, edge_id, _ = states[state_index]
        path.append(edge_id)
        state_index = parent
    return tuple(reversed(path))


def adaptive_prune(
    graph: Neighborhood,
    edge_rarity: dict[int, float],
    diffusion: DiffusionResult,
    *,
    seeds: set[str],
    keep_ratio: float,
    rarity_weight: float = 0.6,
    path_importance: dict[int, float] | None = None,
    path_weight: float = 0.0,
    impact_importance: dict[int, float] | None = None,
    impact_weight: float = 0.0,
    behavior_importance: dict[int, float] | None = None,
    behavior_weight: float = 0.0,
    protected_edge_ids: set[int] | None = None,
    selection_mode: str = "ratio",
    protect_seed_incident_edges: bool = True,
    atomic_edge_groups: dict[int, tuple[int, ...]] | None = None,
    connectivity_target_edge_ids: set[int] | None = None,
    ordered_connectivity_edge_ids: tuple[int, ...] | None = None,
    ordered_connectivity_edge_sequences: (
        tuple[tuple[int, ...], ...] | None
    ) = None,
    certificate_poi_edge_ids: set[int] | None = None,
    certificate_expected_poi_count: int | None = None,
    fusion_mode: str = "additive",
    edge_scores_override: dict[int, float] | None = None,
    edge_score_components_override: dict[int, dict[str, float]] | None = None,
    previous_kept_edge_ids: set[int] | None = None,
    churn_slack_ratio: float = 0.0,
    positive_score_only: bool = False,
    escape_importance: dict[int, float] | None = None,
    escape_eligible_edge_ids: set[int] | None = None,
    escape_quota_ratio: float = 0.0,
    escape_threshold: float = 0.0,
) -> PruningResult:
    """Keep high joint-score edges plus the causal backbone to alert seeds."""
    if not 0.0 < keep_ratio <= 1.0:
        raise ValueError("keep_ratio must be in (0, 1]")
    if not 0.0 <= rarity_weight <= 1.0:
        raise ValueError("rarity_weight must be in [0, 1]")
    if not 0.0 <= path_weight <= 1.0:
        raise ValueError("path_weight must be in [0, 1]")
    if not 0.0 <= impact_weight <= 1.0:
        raise ValueError("impact_weight must be in [0, 1]")
    if not 0.0 <= behavior_weight <= 1.0:
        raise ValueError("behavior_weight must be in [0, 1]")
    if rarity_weight + path_weight + impact_weight + behavior_weight > 1.0:
        raise ValueError("scoring weights must sum to <= 1")
    if selection_mode not in {"ratio", "adaptive", "rdp_guard"}:
        raise ValueError("selection_mode must be ratio, adaptive, or rdp_guard")
    if fusion_mode not in {"additive", "rdp_guard"}:
        raise ValueError("fusion_mode must be additive or rdp_guard")
    if not 0.0 <= churn_slack_ratio <= 1.0:
        raise ValueError("churn_slack_ratio must be in [0, 1]")
    if not 0.0 <= escape_quota_ratio <= 1.0:
        raise ValueError("escape_quota_ratio must be in [0, 1]")
    if not 0.0 <= escape_threshold <= 1.0:
        raise ValueError("escape_threshold must be in [0, 1]")
    if (
        ordered_connectivity_edge_ids is not None
        and ordered_connectivity_edge_sequences is not None
    ):
        raise ValueError(
            "supply ordered_connectivity_edge_ids or "
            "ordered_connectivity_edge_sequences, not both"
        )
    ordered_path_cover = (
        tuple(tuple(sequence) for sequence in ordered_connectivity_edge_sequences)
        if ordered_connectivity_edge_sequences is not None
        else ((tuple(ordered_connectivity_edge_ids),)
              if ordered_connectivity_edge_ids else ())
    )
    if any(not sequence for sequence in ordered_path_cover):
        raise ValueError("ordered connectivity sequences must not be empty")
    declared_ordered_ids = [
        edge_id for sequence in ordered_path_cover for edge_id in sequence
    ]
    if len(declared_ordered_ids) != len(set(declared_ordered_ids)):
        raise ValueError(
            "each POI edge must occur exactly once in the causal path cover"
        )
    if not graph.edges:
        return PruningResult([], {}, 1.0, keep_ratio, 0.0, selection_mode, {})

    path_importance = path_importance or {}
    impact_importance = impact_importance or {}
    behavior_importance = behavior_importance or {}
    escape_importance = escape_importance or {}
    escape_eligible_edge_ids = escape_eligible_edge_ids or set()
    if any(
        not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0
        for score in escape_importance.values()
    ):
        raise ValueError("escape importance values must be finite and in [0, 1]")
    protected_edge_ids = protected_edge_ids or set()
    diffusion_weight = 1.0 - rarity_weight - path_weight - impact_weight - behavior_weight
    edge_scores: dict[int, float] = {}
    edge_score_components: dict[int, dict[str, float]] = {}
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    edge_id_set = set(edge_by_id)
    if any(edge_id not in edge_id_set for edge_id in escape_eligible_edge_ids):
        raise ValueError("escape eligible edges must belong to the candidate graph")
    member_to_group: dict[int, tuple[int, ...]] = {}
    for members in (atomic_edge_groups or {}).values():
        present = tuple(edge_id for edge_id in members if edge_id in edge_by_id)
        for edge_id in present:
            member_to_group[edge_id] = present
    for edge_id in edge_by_id:
        member_to_group.setdefault(edge_id, (edge_id,))
    endpoint_diffusion_scores = {
        edge.edge_id: (
            diffusion.edge_scores.get(edge.edge_id, 0.0)
            if diffusion.edge_scores
            else max(
                diffusion.scores.get(edge.src, 0.0),
                diffusion.scores.get(edge.dst, 0.0),
            )
        )
        for edge in graph.edges
    }
    if edge_scores_override is not None:
        if set(edge_scores_override) != set(edge_by_id):
            raise ValueError("edge_scores_override must cover the candidate graph exactly")
        if any(
            not 0.0 <= float(score) <= 1.0
            for score in edge_scores_override.values()
        ):
            raise ValueError("edge_scores_override values must be in [0, 1]")
        edge_scores = edge_scores_override
        edge_score_components = edge_score_components_override or {}
    elif fusion_mode == "rdp_guard":
        fused = fuse_rarity_diffusion(
            edge_by_id,
            rarity=edge_rarity,
            diffusion=endpoint_diffusion_scores,
            rarity_weight=rarity_weight,
            path=path_importance,
            path_weight=path_weight,
            impact=impact_importance,
            impact_weight=impact_weight,
            behavior=behavior_importance,
            behavior_weight=behavior_weight,
        )
        edge_scores = fused.scores
        edge_score_components = fused.components
    else:
        max_diffusion = max(
            (diffusion.edge_scores or diffusion.scores).values(), default=0.0
        )
        for edge in graph.edges:
            endpoint_diffusion = endpoint_diffusion_scores[edge.edge_id]
            if max_diffusion > 0:
                endpoint_diffusion /= max_diffusion
            rarity = min(1.0, max(0.0, edge_rarity.get(edge.edge_id, 0.0)))
            path_score = min(
                1.0, max(0.0, path_importance.get(edge.edge_id, 0.0))
            )
            impact_score = min(
                1.0, max(0.0, impact_importance.get(edge.edge_id, 0.0))
            )
            behavior_score = min(
                1.0, max(0.0, behavior_importance.get(edge.edge_id, 0.0))
            )
            edge_score_components[edge.edge_id] = {
                "rarity": rarity,
                "diffusion": endpoint_diffusion,
                "path": path_score,
                "depimpact": impact_score,
                "behavior": behavior_score,
            }
            edge_scores[edge.edge_id] = (
                rarity_weight * rarity
                + diffusion_weight * endpoint_diffusion
                + path_weight * path_score
                + impact_weight * impact_score
                + behavior_weight * behavior_score
            )

    unique_groups = {members for members in member_to_group.values()}
    ranked_groups = sorted(
        unique_groups,
        key=lambda members: (
            # One merged dependency has one semantic benefit, while every raw
            # event still consumes storage. Rank by benefit per raw-event cost.
            -(max(edge_scores[edge_id] for edge_id in members) / len(members)),
            -max(edge_scores[edge_id] for edge_id in members),
            min(members),
        ),
    )
    # Floor is required for a true raw-edge ratio ceiling.  The minimum of one
    # only applies to non-empty toy graphs where any non-empty result must
    # necessarily exceed a sub-edge fractional request.
    budget_edges = max(1, math.floor(len(graph.edges) * keep_ratio))
    ratio_group_count = max(1, math.ceil(len(ranked_groups) * keep_ratio))
    keep_group_count = ratio_group_count
    if selection_mode == "adaptive" and len(ranked_groups) > 1:
        group_scores = [
            max(edge_scores[edge_id] for edge_id in members)
            for members in ranked_groups
        ]
        gaps = [
            group_scores[index] - group_scores[index + 1]
            for index in range(len(ranked_groups) - 1)
        ]
        largest_gap = max(gaps)
        if largest_gap > 1e-12:
            keep_group_count = max(ratio_group_count, gaps.index(largest_gap) + 1)
    def expand_groups(edge_ids: set[int]) -> set[int]:
        return {
            member
            for edge_id in edge_ids
            for member in member_to_group.get(edge_id, (edge_id,))
            if member in edge_by_id
        }

    selection_reasons: dict[int, set[str]] = {
        edge_id: set() for edge_id in edge_by_id
    }

    def mark(edge_ids: set[int], reason: str) -> None:
        for edge_id in edge_ids & edge_id_set:
            selection_reasons[edge_id].add(reason)

    def mark_atomic_expansion(original: set[int], expanded: set[int]) -> None:
        for edge_id in expanded - original:
            selection_reasons[edge_id].add("atomic_group_expansion")

    connectivity_paths = (
        _directed_connectivity_paths(
            graph, edge_scores, connectivity_target_edge_ids
        )
        if connectivity_target_edge_ids else {}
    )
    connectivity_targets_present = {
        edge_id for edge_id in (connectivity_target_edge_ids or set())
        if edge_id in edge_by_id
    }
    protected_present = set(protected_edge_ids) & edge_id_set
    protected_expanded = expand_groups(protected_present)
    mark(protected_expanded, "protected_alert")
    mark_atomic_expansion(protected_present, protected_expanded)
    (
        stage_backbone,
        stage_pairs,
        connected_stage_pairs,
        _candidate_stage_witnesses,
        candidate_disconnected_stage_pairs,
    ) = _ordered_path_cover_backbone(
        graph, edge_scores, ordered_path_cover
    )
    expanded_stage_backbone = expand_groups(stage_backbone)
    mark(expanded_stage_backbone, "causal_path_cover")
    # Preserve the established reason as an alias for downstream v2 readers.
    mark(expanded_stage_backbone, "ordered_stage_backbone")
    mark_atomic_expansion(stage_backbone, expanded_stage_backbone)
    expanded_connectivity_targets = expand_groups(connectivity_targets_present)
    mark(expanded_connectivity_targets, "connectivity_target")
    mark_atomic_expansion(connectivity_targets_present, expanded_connectivity_targets)
    mandatory_core = (
        protected_expanded
        | expanded_stage_backbone
        | expanded_connectivity_targets
    )
    if protect_seed_incident_edges:
        seed_incident = {
            edge.edge_id for edge in graph.edges
            if edge.src in seeds or edge.dst in seeds
        }
        expanded_seed_incident = expand_groups(seed_incident)
        mandatory_core.update(expanded_seed_incident)
        mark(expanded_seed_incident, "seed_incident")
        mark_atomic_expansion(seed_incident, expanded_seed_incident)
    mandatory_bridges = expand_groups({
        bridge
        for edge_id in mandatory_core
        for bridge in connectivity_paths.get(edge_id, ())
    })
    mark(mandatory_bridges, "connectivity_bridge")
    selected = mandatory_core | mandatory_bridges
    minimum_required_edges = len(selected)
    budget_feasible = minimum_required_edges <= budget_edges
    core_selected = set(mandatory_core)

    previous_present = (
        expand_groups(set(previous_kept_edge_ids or set()) & edge_id_set)
        if previous_kept_edge_ids is not None else set()
    )
    mandatory_delta = len(selected - previous_present)
    budget_contraction_edges = (
        max(0, len(previous_present) - budget_edges)
        if previous_kept_edge_ids is not None else 0
    )
    declared_allowed_removed_previous_edges = (
        min(
            len(previous_present),
            budget_contraction_edges
            + mandatory_delta
            + math.ceil(churn_slack_ratio * budget_edges),
        )
        if previous_kept_edge_ids is not None else 0
    )
    # Atomic groups can make the declared edge-level overlap unattainable even
    # when raw capacity exists. Compute the exact unavoidable packing gap for
    # disjoint prior groups (the normal DEPIMPACT representation) rather than
    # pre-granting a worst-case group-size allowance.
    atomicity_churn_slack_edges = 0
    planned_prior_groups: set[tuple[int, ...]] | None = None
    if previous_kept_edge_ids is not None and budget_feasible:
        current_previous_overlap = len(selected & previous_present)
        required_declared_overlap = max(
            0,
            len(previous_present) - declared_allowed_removed_previous_edges,
        )
        remaining_capacity = max(0, budget_edges - len(selected))
        prior_atomic_groups: list[tuple[int, ...]] = []
        atomic_model_supported = True
        for members in ranked_groups:
            member_ids = set(members)
            if member_ids <= selected:
                continue
            prior_delta = (member_ids - selected) & previous_present
            if not prior_delta:
                continue
            raw_cost = len(member_ids - selected)
            if raw_cost != len(prior_delta):
                atomic_model_supported = False
                break
            prior_atomic_groups.append(tuple(sorted(member_ids - selected)))
        if atomic_model_supported:
            required_additional_overlap = max(
                0, required_declared_overlap - current_previous_overlap
            )
            maximum_additional_overlap, planned_prior_groups = (
                _bounded_atomic_subset(
                    prior_atomic_groups,
                    capacity=remaining_capacity,
                    minimum_edges=required_additional_overlap,
                )
            )
            maximum_atomic_overlap = (
                current_previous_overlap + maximum_additional_overlap
            )
            atomicity_churn_slack_edges = max(
                0, required_declared_overlap - maximum_atomic_overlap
            )
    allowed_removed_previous_edges = min(
        len(previous_present),
        declared_allowed_removed_previous_edges + atomicity_churn_slack_edges,
    ) if previous_kept_edge_ids is not None else 0
    required_previous_edges = max(
        0, len(previous_present) - allowed_removed_previous_edges
    )

    def trial_group(
        current: set[int], members: tuple[int, ...]
    ) -> tuple[set[int], set[int], set[int]]:
        member_ids = set(members)
        new_core = expand_groups(member_ids) - current
        bridges: set[int] = set()
        if connectivity_target_edge_ids:
            bridges = expand_groups({
                bridge
                for edge_id in new_core
                for bridge in connectivity_paths.get(edge_id, ())
            }) - current - new_core
        return new_core | bridges, new_core, bridges

    # Establish the minimum previous-result overlap before considering new
    # utility. This turns otherwise arbitrary prefix replacement into a stated,
    # auditable edge-level churn constraint.
    selection_candidate_edges_examined = 0
    retained_previous_during_selection = len(selected & previous_present)
    if previous_kept_edge_ids is not None and budget_feasible:
        prior_groups = [
            members for members in ranked_groups
            if set(members) & previous_present
        ]
        for members in prior_groups:
            if retained_previous_during_selection >= required_previous_edges:
                break
            if (
                planned_prior_groups is not None
                and tuple(sorted(set(members) - selected))
                not in planned_prior_groups
            ):
                continue
            if set(members) <= selected:
                continue
            additions, new_core, bridges = trial_group(selected, members)
            selection_candidate_edges_examined += len(new_core)
            if len(selected) + len(additions) > budget_edges:
                continue
            newly_retained_previous = len(
                additions & previous_present
            )
            selected.update(additions)
            retained_previous_during_selection += newly_retained_previous
            core_selected.update(new_core)
            mark(new_core & previous_present, "prior_retention")
            mark(new_core, "positive_score_rank")
            if len(members) > 1:
                mark(new_core, "atomic_group_expansion")
            mark(bridges, "connectivity_bridge")

    eligible_escape_ids = {
        edge_id for edge_id in escape_eligible_edge_ids
        if float(escape_importance.get(edge_id, 0.0)) >= escape_threshold
    }
    escape_budget_edges = (
        max(1, math.floor(budget_edges * escape_quota_ratio))
        if eligible_escape_ids and escape_quota_ratio > 0.0 else 0
    )
    escape_selected: set[int] = set()
    ranked_escape_groups = sorted(
        {member_to_group[edge_id] for edge_id in eligible_escape_ids},
        key=lambda members: (
            -max(float(escape_importance.get(edge_id, 0.0)) for edge_id in members),
            min(members),
        ),
    )
    for members in ranked_escape_groups:
        if len(escape_selected) >= escape_budget_edges:
            break
        additions, new_core, bridges = trial_group(selected, members)
        eligible_new = new_core & eligible_escape_ids
        if not eligible_new or len(selected) + len(additions) > budget_edges:
            continue
        if len(escape_selected | eligible_new) > escape_budget_edges:
            continue
        selection_candidate_edges_examined += len(new_core)
        selected.update(additions)
        core_selected.update(new_core)
        escape_selected.update(eligible_new)
        mark(new_core, "rarity_escape_diversity")
        if len(members) > 1:
            mark(new_core, "atomic_group_expansion")
        mark(bridges, "connectivity_bridge")

    # Select score groups together with the causal bridges they require.  Both
    # atomic group members and bridge events consume the raw-event budget. Add
    # only each group's delta: rebuilding the complete selected set here makes
    # large alert windows quadratic in the requested number of retained edges.
    considered = 0
    for members in ranked_groups:
        member_ids = set(members)
        if member_ids <= selected:
            continue
        group_score = max(edge_scores[edge_id] for edge_id in members)
        if positive_score_only and group_score <= 0.0:
            break
        if selection_mode == "adaptive" and considered >= keep_group_count:
            break
        considered += 1
        additions, new_core, bridges = trial_group(selected, members)
        selection_candidate_edges_examined += len(new_core)
        if len(selected) + len(additions) <= budget_edges:
            core_selected.update(new_core)
            selected.update(additions)
            mark(new_core, "positive_score_rank")
            if len(members) > 1:
                mark(new_core, "atomic_group_expansion")
            mark(bridges, "connectivity_bridge")
        elif selection_mode == "rdp_guard":
            # An expensive merged group need not waste the remaining raw-event
            # budget: continue looking for lower-ranked groups that fit.
            continue
        else:
            # Prefix selection makes retention curves nested: increasing a
            # budget can only add groups, never replace an earlier solution
            # with a different lower-ranked combination.
            break
        if len(selected) >= budget_edges:
            break
    mark(selected & previous_present, "prior_retention")
    before_connectivity = set(core_selected)
    threshold = min((edge_scores[edge_id] for edge_id in core_selected), default=1.0)

    kept = [edge for edge in graph.edges if edge.edge_id in selected]
    kept_node_ids = {
        endpoint for edge in kept for endpoint in (edge.src, edge.dst)
    }
    kept_graph = Neighborhood(
        {uuid: graph.nodes[uuid] for uuid in kept_node_ids if uuid in graph.nodes},
        kept,
    )
    (
        _,
        _,
        retained_stage_pairs,
        stage_path_witnesses,
        _,
    ) = _ordered_path_cover_backbone(
        kept_graph, edge_scores, ordered_path_cover
    )
    requested_certificate_poi_ids = (
        set(certificate_poi_edge_ids or set())
        | set(declared_ordered_ids)
        | set(connectivity_target_edge_ids or set())
    )
    certificate_poi_ids = {
        edge_id
        for edge_id in requested_certificate_poi_ids
        if edge_id in edge_by_id
    }
    certificate_retained_poi_edges = len(certificate_poi_ids & selected)
    ordered_certificate_present = bool(ordered_path_cover)
    expected_poi_count = (
        int(certificate_expected_poi_count)
        if certificate_expected_poi_count is not None
        else len(requested_certificate_poi_ids)
    )
    all_pois_present_and_retained = (
        expected_poi_count > 0
        and len(certificate_poi_ids) == expected_poi_count
        and certificate_retained_poi_edges == expected_poi_count
    )
    if expected_poi_count == 1 and ordered_certificate_present:
        certificate_topology = "singleton"
    elif len(ordered_path_cover) == 1:
        certificate_topology = "chain"
    elif len(ordered_path_cover) > 1:
        certificate_topology = "forest"
    else:
        certificate_topology = "unordered"
    certificate_branch_count = len(ordered_path_cover)
    if not all_pois_present_and_retained:
        path_certificate_status = "missing_poi"
    elif not budget_feasible:
        path_certificate_status = "budget_infeasible"
    elif ordered_certificate_present and connected_stage_pairs < stage_pairs:
        path_certificate_status = "candidate_disconnected"
    elif ordered_certificate_present and stage_pairs > 0 and (
        retained_stage_pairs < stage_pairs
    ):
        path_certificate_status = "missing_poi"
    elif ordered_certificate_present and expected_poi_count == 1:
        path_certificate_status = "poi_only"
    elif ordered_certificate_present and certificate_topology == "forest":
        path_certificate_status = "valid_forest"
    elif ordered_certificate_present and stage_pairs > 0:
        path_certificate_status = "valid"
    elif expected_poi_count > 1:
        path_certificate_status = "unordered_multi_poi"
    else:
        path_certificate_status = "poi_only"
    path_certificate_valid = path_certificate_status in {
        "valid", "valid_forest", "poi_only"
    }
    causal_path_cover_certificate_valid = path_certificate_valid
    strict_multistage_certificate_valid = path_certificate_status == "valid"
    retained_previous_edges = len(selected & previous_present)
    removed_previous_edges = len(previous_present - selected)
    added_edges = len(selected - previous_present) if previous_kept_edge_ids is not None else 0
    union_size = len(selected | previous_present)
    prefix_jaccard = (
        len(selected & previous_present) / union_size
        if previous_kept_edge_ids is not None and union_size else
        1.0 if previous_kept_edge_ids is not None else None
    )
    churn_bound_satisfied = (
        removed_previous_edges <= allowed_removed_previous_edges
        if previous_kept_edge_ids is not None else True
    )
    zero_score_fill_stopped = bool(
        positive_score_only
        and len(selected) < budget_edges
        and any(
            edge_scores[edge_id] <= 0.0
            for edge_id in edge_id_set - selected
        )
    )
    total_score_mass = sum(max(0.0, score) for score in edge_scores.values())
    score_mass_retained = (
        sum(max(0.0, edge_scores.get(edge_id, 0.0)) for edge_id in selected)
        / total_score_mass
        if total_score_mass > 0.0 else 1.0
    )
    return PruningResult(
        kept_edges=kept,
        edge_scores=edge_scores,
        threshold=threshold,
        requested_keep_ratio=keep_ratio,
        actual_keep_ratio=len(kept) / len(graph.edges),
        selection_mode=selection_mode,
        edge_score_components=edge_score_components,
        connectivity_added_edges=(
            len(selected - before_connectivity)
            + len(expanded_stage_backbone - protected_expanded)
        ),
        budget_edges=budget_edges,
        budget_rounding_policy="floor_hard_cap_minimum_one",
        minimum_required_edges=minimum_required_edges,
        budget_feasible=budget_feasible,
        budget_overflow_edges=max(0, len(selected) - budget_edges),
        stage_pairs=stage_pairs,
        connected_stage_pairs=connected_stage_pairs,
        retained_stage_pairs=retained_stage_pairs,
        selection_candidate_edges_examined=selection_candidate_edges_examined,
        scoring_mode=fusion_mode,
        score_mass_retained=score_mass_retained,
        certificate_poi_edges=len(certificate_poi_ids),
        certificate_retained_poi_edges=certificate_retained_poi_edges,
        path_certificate_valid=path_certificate_valid,
        path_certificate_status=path_certificate_status,
        strict_multistage_certificate_valid=(
            strict_multistage_certificate_valid
        ),
        causal_path_cover_certificate_valid=(
            causal_path_cover_certificate_valid
        ),
        certificate_topology=certificate_topology,
        certificate_branch_count=certificate_branch_count,
        candidate_disconnected_stage_pairs=(
            candidate_disconnected_stage_pairs
        ),
        stage_path_witnesses=stage_path_witnesses,
        edge_selection_reasons={
            edge_id: tuple(sorted(reasons))
            for edge_id, reasons in selection_reasons.items()
            if edge_id in selected
        },
        previous_candidate_edges=len(previous_present),
        retained_previous_edges=retained_previous_edges,
        added_edges=added_edges,
        removed_previous_edges=removed_previous_edges,
        declared_allowed_removed_previous_edges=(
            declared_allowed_removed_previous_edges
        ),
        allowed_removed_previous_edges=allowed_removed_previous_edges,
        budget_contraction_edges=budget_contraction_edges,
        atomicity_churn_slack_edges=atomicity_churn_slack_edges,
        churn_bound_satisfied=churn_bound_satisfied,
        churn_constraint_status=(
            "not_applicable"
            if previous_kept_edge_ids is None else
            "satisfied" if churn_bound_satisfied else "infeasible"
        ),
        prefix_jaccard=prefix_jaccard,
        unused_budget_edges=max(0, budget_edges - len(selected)),
        zero_score_fill_stopped=zero_score_fill_stopped,
        escape_budget_edges=escape_budget_edges,
        escape_selected_edges=len(escape_selected),
    )


__all__ = ["PruningResult", "adaptive_prune"]
