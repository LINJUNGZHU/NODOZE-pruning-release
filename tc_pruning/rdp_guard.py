"""RDP-Guard: diffusion-gated rarity scoring and operating-point selection.

The module is deliberately independent from Ground Truth annotations.  Its
inputs are online graph signals (rarity, temporal diffusion and optional
structural features) plus pruning diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class RDPGuardScores:
    scores: dict[int, float]
    components: dict[int, dict[str, float]]


@dataclass(frozen=True, slots=True)
class PrefixAggregateScores:
    scores: dict[int, float]
    components: dict[int, dict[str, float]]
    provenance: dict[int, dict[str, object]]
    local_score_digests: dict[str, str]
    # Sparse positive edge scores for every immutable POI-local scorer.  A
    # missing edge is exactly zero.  Keeping this separately from winner
    # provenance makes the noisy-OR aggregate independently reproducible.
    local_score_contributions: dict[str, dict[int, float]]


class PrefixScoreAccumulator:
    """Memory-bounded noisy-OR accumulator for fixed-graph POI scores."""

    def __init__(
        self,
        *,
        context_digest: str | None = None,
        require_same_edge_ids: bool = True,
    ) -> None:
        self._scores: dict[int, float] = {}
        self._winner_scores: dict[int, float] = {}
        self._winner_pois: dict[int, str] = {}
        self._winner_components: dict[int, dict[str, float]] = {}
        self._support_counts: dict[int, int] = {}
        self._digests: dict[str, str] = {}
        self._local_score_contributions: dict[str, dict[int, float]] = {}
        self._edge_ids: set[int] | None = None
        self._context_digest = str(context_digest) if context_digest else None
        self._require_same_edge_ids = bool(require_same_edge_ids)
        self._auxiliary_node_scores: dict[str, dict[str, dict[str, float]]] = {}
        self._auxiliary_phase_seconds: dict[str, dict[str, float]] = {}

    def bind_context(self, context_digest: str) -> None:
        """Bind the accumulator to one immutable graph/scoring context."""
        value = str(context_digest)
        if not value:
            raise ValueError("prefix scoring context digest must not be empty")
        if self._context_digest is None:
            self._context_digest = value
        elif self._context_digest != value:
            raise ValueError("prefix score state context does not match this run")

    def add_auxiliary_node_scores(
        self,
        poi_event_id: str,
        method: str,
        scores: Mapping[str, float],
        phase_seconds: Mapping[str, float] | None = None,
    ) -> None:
        """Retain online-only node impacts used by Table 8 prefix evaluation."""
        per_method = self._auxiliary_node_scores.setdefault(str(method), {})
        poi = str(poi_event_id)
        if poi in per_method:
            raise ValueError(f"duplicate auxiliary POI score context: {poi}")
        per_method[poi] = {
            str(node): _bounded(value) for node, value in scores.items()
        }
        if phase_seconds is not None:
            totals = self._auxiliary_phase_seconds.setdefault(str(method), {})
            for phase, seconds in phase_seconds.items():
                totals[str(phase)] = totals.get(str(phase), 0.0) + float(seconds)

    def aggregate_auxiliary_node_scores(self) -> dict[str, dict[str, float]]:
        result: dict[str, dict[str, float]] = {}
        for method, per_poi in self._auxiliary_node_scores.items():
            complements: dict[str, float] = {}
            for scores in per_poi.values():
                for node, score in scores.items():
                    complements[node] = complements.get(node, 1.0) * (1.0 - score)
            result[method] = {
                node: 1.0 - complement
                for node, complement in complements.items()
            }
        return result

    @property
    def auxiliary_phase_seconds(self) -> dict[str, dict[str, float]]:
        return {
            method: dict(phases)
            for method, phases in self._auxiliary_phase_seconds.items()
        }

    @property
    def context_digest(self) -> str | None:
        return self._context_digest

    def add(self, poi_event_id: str, result: RDPGuardScores) -> None:
        edge_ids = set(result.scores)
        if self._edge_ids is None:
            self._edge_ids = set(edge_ids)
        elif self._require_same_edge_ids and edge_ids != self._edge_ids:
            raise ValueError("every POI-local score map must cover the same graph")
        else:
            self._edge_ids.update(edge_ids)
        poi = str(poi_event_id)
        if poi in self._digests:
            raise ValueError(f"duplicate POI score context: {poi}")
        self._digests[poi] = score_map_digest(result.scores)
        self._local_score_contributions[poi] = {}
        for edge_id in sorted(edge_ids):
            local = _bounded(result.scores[edge_id])
            previous = self._scores.get(edge_id, 0.0)
            self._scores[edge_id] = _bounded(
                previous + (1.0 - previous) * local
            )
            if local > 0.0:
                self._local_score_contributions[poi][edge_id] = local
                self._support_counts[edge_id] = (
                    self._support_counts.get(edge_id, 0) + 1
                )
            winner_score = self._winner_scores.get(edge_id, -1.0)
            winner_poi = self._winner_pois.get(edge_id, poi)
            if local > winner_score or (
                local == winner_score and poi < winner_poi
            ):
                self._winner_scores[edge_id] = local
                self._winner_pois[edge_id] = poi
                self._winner_components[edge_id] = dict(
                    result.components.get(edge_id, {})
                )

    @property
    def poi_event_ids(self) -> frozenset[str]:
        return frozenset(self._digests)

    @property
    def edge_ids(self) -> frozenset[int]:
        return frozenset(self._edge_ids or set())

    @property
    def local_score_digests(self) -> dict[str, str]:
        return dict(self._digests)

    def finalize(self) -> PrefixAggregateScores:
        components: dict[int, dict[str, float]] = {}
        provenance: dict[int, dict[str, object]] = {}
        for edge_id in sorted(self._scores):
            aggregate = self._scores[edge_id]
            winner_score = self._winner_scores[edge_id]
            components[edge_id] = {
                **self._winner_components[edge_id],
                "max_local_score": winner_score,
                "aggregate_noisy_or": aggregate,
                "poi_support_count": float(self._support_counts.get(edge_id, 0)),
            }
            provenance[edge_id] = {
                "aggregation": "noisy_or",
                "support_count": self._support_counts.get(edge_id, 0),
                "winner_poi_event_id": self._winner_pois[edge_id],
                "winner_local_score": winner_score,
            }
        return PrefixAggregateScores(
            scores=dict(self._scores),
            components=components,
            provenance=provenance,
            local_score_digests=dict(self._digests),
            local_score_contributions={
                poi: dict(contributions)
                for poi, contributions in self._local_score_contributions.items()
            },
        )


def _bounded(value: float) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError("score values must be finite")
    return min(1.0, max(0.0, numeric))


def _validate_weights(weights: Sequence[float]) -> None:
    if any(not 0.0 <= value <= 1.0 for value in weights):
        raise ValueError("scoring weights must be in [0, 1]")
    if sum(weights) > 1.0 + 1e-12:
        raise ValueError("scoring weights must sum to <= 1")


def fuse_rarity_diffusion(
    edge_ids: Iterable[int],
    *,
    rarity: Mapping[int, float],
    diffusion: Mapping[int, float],
    rarity_weight: float,
    path: Mapping[int, float] | None = None,
    path_weight: float = 0.0,
    impact: Mapping[int, float] | None = None,
    impact_weight: float = 0.0,
    behavior: Mapping[int, float] | None = None,
    behavior_weight: float = 0.0,
) -> RDPGuardScores:
    """Fuse online scores while requiring temporal-diffusion support.

    ``D * (w_d + w_r R + ...)`` is used instead of an independent additive
    rarity term.  Consequently, a disconnected edge with ``D == 0`` cannot be
    promoted solely because it is rare.
    """
    weights = (rarity_weight, path_weight, impact_weight, behavior_weight)
    _validate_weights(weights)
    diffusion_weight = 1.0 - sum(weights)
    ids = tuple(dict.fromkeys(int(edge_id) for edge_id in edge_ids))
    if not ids:
        return RDPGuardScores({}, {})

    path = path or {}
    impact = impact or {}
    behavior = behavior or {}
    max_diffusion = max(
        (max(0.0, float(diffusion.get(edge_id, 0.0))) for edge_id in ids),
        default=0.0,
    )
    raw_scores: dict[int, float] = {}
    components: dict[int, dict[str, float]] = {}
    for edge_id in ids:
        diffusion_score = (
            max(0.0, float(diffusion.get(edge_id, 0.0))) / max_diffusion
            if max_diffusion > 0.0 else 0.0
        )
        rarity_score = _bounded(rarity.get(edge_id, 0.0))
        path_score = _bounded(path.get(edge_id, 0.0))
        impact_score = _bounded(impact.get(edge_id, 0.0))
        behavior_score = _bounded(behavior.get(edge_id, 0.0))
        gated_rarity = diffusion_score * rarity_score
        gated_path = diffusion_score * path_score
        gated_impact = diffusion_score * impact_score
        gated_behavior = diffusion_score * behavior_score
        raw = (
            diffusion_weight * diffusion_score
            + rarity_weight * gated_rarity
            + path_weight * gated_path
            + impact_weight * gated_impact
            + behavior_weight * gated_behavior
        )
        raw_scores[edge_id] = raw
        components[edge_id] = {
            "rarity": rarity_score,
            "diffusion": diffusion_score,
            "path": path_score,
            "depimpact": impact_score,
            "behavior": behavior_score,
            "gated_rarity": gated_rarity,
            "gated_path": gated_path,
            "gated_depimpact": gated_impact,
            "gated_behavior": gated_behavior,
            "raw_rdp_guard": raw,
        }
    maximum = max(raw_scores.values(), default=0.0)
    scores = {
        edge_id: score / maximum if maximum > 0.0 else 0.0
        for edge_id, score in raw_scores.items()
    }
    return RDPGuardScores(scores, components)


def score_map_digest(scores: Mapping[int, float]) -> str:
    """Return a stable digest for an immutable POI-local score map."""
    payload = [
        [int(edge_id), float(scores[edge_id])]
        for edge_id in sorted(scores)
    ]
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def aggregate_poi_scores(
    local_scores: Sequence[tuple[str, RDPGuardScores]],
) -> PrefixAggregateScores:
    """Aggregate immutable POI-local scores with a monotone noisy-OR.

    Component values come from the local scorer that supplied the strongest
    score, with POI event ID as a deterministic tie break. The aggregate is an
    importance measure rather than a probability estimate.
    """
    accumulator = PrefixScoreAccumulator()
    for poi_event_id, result in local_scores:
        accumulator.add(poi_event_id, result)
    return accumulator.finalize()


def recommend_operating_point(
    rows: Iterable[Mapping[str, object]], *, score_mass_target: float = 0.95
) -> dict[str, object]:
    """Choose a compression point without consulting attack labels."""
    if not 0.0 < score_mass_target <= 1.0:
        raise ValueError("score_mass_target must be in (0, 1]")
    materialized = list(rows)
    online_inputs = [
        "requested_keep_ratio",
        "actual_keep_ratio",
        "score_mass_retained",
        "path_certificate_valid",
        "strict_multistage_certificate_valid",
        "causal_path_cover_certificate_valid",
        "budget_feasible",
        "churn_bound_satisfied",
    ]

    def certificate_eligible(row: Mapping[str, object]) -> bool:
        stage_pairs = int(row.get("stage_pairs") or 0)
        certificate_valid = (
            bool(row["causal_path_cover_certificate_valid"])
            if "causal_path_cover_certificate_valid" in row
            else (
                bool(row.get("strict_multistage_certificate_valid"))
                if stage_pairs > 0
                else bool(row.get("path_certificate_valid"))
            )
        )
        return (
            certificate_valid
            and bool(row.get("budget_feasible", True))
            and bool(row.get("churn_bound_satisfied", True))
        )

    valid = [
        row for row in materialized
        if certificate_eligible(row)
    ]
    meeting = [
        row for row in valid
        if float(row.get("score_mass_retained") or 0.0) >= score_mass_target
    ]
    if meeting:
        chosen = min(
            meeting,
            key=lambda row: (
                float(row.get("actual_keep_ratio") or 0.0),
                float(row.get("requested_keep_ratio") or 0.0),
            ),
        )
        reason = "minimum_ratio_meeting_certificate_and_score_mass"
    elif valid:
        chosen = max(
            valid,
            key=lambda row: (
                float(row.get("score_mass_retained") or 0.0),
                -float(row.get("actual_keep_ratio") or 0.0),
            ),
        )
        reason = "highest_score_mass_with_valid_certificate"
    else:
        return {
            "available": False,
            "score_mass_target": score_mass_target,
            "selection_reason": "no_budget_feasible_valid_certificate",
            "online_inputs": online_inputs,
        }
    return {
        "available": True,
        "requested_keep_ratio": float(chosen["requested_keep_ratio"]),
        "actual_keep_ratio": float(chosen["actual_keep_ratio"]),
        "score_mass_retained": float(chosen.get("score_mass_retained") or 0.0),
        "score_mass_target": score_mass_target,
        "path_certificate_valid": bool(chosen["path_certificate_valid"]),
        "selection_reason": reason,
        "online_inputs": online_inputs,
    }


__all__ = [
    "PrefixAggregateScores",
    "PrefixScoreAccumulator",
    "RDPGuardScores",
    "aggregate_poi_scores",
    "fuse_rarity_diffusion",
    "recommend_operating_point",
    "score_map_digest",
]
