"""Ground-truth-free rarity escape channel for diffusion-disconnected events.

PS-RDP's main score deliberately gates rarity by POI diffusion.  That protects
against isolated rare noise, but it can also hide a genuinely novel attack
branch that is causally disconnected from the current POI set.  REDQ assigns a
small, separately budgeted escape score to such events using only historical
frequency statistics available before the scenario cutoff.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping

from .models import Neighborhood
from .nodoze import NODOZEFrequencyModel


@dataclass(frozen=True, slots=True)
class RarityEscapeResult:
    scores: dict[int, float]
    evidence: dict[int, dict[str, float]]
    eligible_edge_ids: frozenset[int]
    threshold: float


def _bounded(value: float) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError("rarity escape inputs must be finite")
    return min(1.0, max(0.0, numeric))


def _positive_quantile(values: list[float], quantile: float) -> float:
    positive = sorted(value for value in values if value > 0.0)
    if not positive:
        return 0.0
    return positive[max(0, math.ceil(quantile * len(positive)) - 1)]


def compute_rarity_escape(
    graph: Neighborhood,
    *,
    rarity: Mapping[int, float],
    diffusion_support: Mapping[int, float],
    history: NODOZEFrequencyModel,
    absolute_threshold: float = 0.5,
    score_quantile: float = 0.995,
    maximum_diffusion: float = 0.05,
) -> RarityEscapeResult:
    """Compute REDQ escape scores from frozen historical statistics.

    ``X=(R*T*V)^(1/3)*sqrt(1-D)`` combines structural rarity ``R``,
    transition anomaly ``T``, destination active-day novelty ``V`` and the
    complement of POI diffusion support ``D``.  The absolute/quantile gate is
    evaluated only among low-diffusion edges and includes every cutoff tie.
    """
    if not 0.0 <= absolute_threshold <= 1.0:
        raise ValueError("escape absolute_threshold must be in [0, 1]")
    if not 0.0 < score_quantile <= 1.0:
        raise ValueError("escape score_quantile must be in (0, 1]")
    if not 0.0 <= maximum_diffusion <= 1.0:
        raise ValueError("escape maximum_diffusion must be in [0, 1]")

    scores: dict[int, float] = {}
    evidence: dict[int, dict[str, float]] = {}
    low_diffusion_scores: list[float] = []
    for edge in graph.edges:
        edge_rarity = _bounded(rarity.get(edge.edge_id, 0.0))
        diffusion = _bounded(diffusion_support.get(edge.edge_id, 0.0))
        transition_anomaly = _bounded(history.edge_anomaly(edge))
        destination = edge.dst_semantic or edge.dst
        active_days = max(0, int(history.incoming_active_days.get(destination, 0)))
        destination_novelty = _bounded(1.0 - active_days / history.total_days)
        diffusion_complement = math.sqrt(max(0.0, 1.0 - diffusion))
        product = edge_rarity * transition_anomaly * destination_novelty
        escape_score = math.pow(product, 1.0 / 3.0) * diffusion_complement
        escape_score = _bounded(escape_score)
        scores[edge.edge_id] = escape_score
        if diffusion <= maximum_diffusion:
            low_diffusion_scores.append(escape_score)
        evidence[edge.edge_id] = {
            "transition_anomaly": transition_anomaly,
            "destination_novelty": destination_novelty,
            "escape_diffusion_support": diffusion,
            "diffusion_complement": diffusion_complement,
            "escape_score": escape_score,
            "escape_eligible": 0.0,
        }
    quantile_cutoff = _positive_quantile(low_diffusion_scores, score_quantile)
    threshold = max(float(absolute_threshold), quantile_cutoff)
    eligible = frozenset(
        edge.edge_id
        for edge in graph.edges
        if diffusion_support.get(edge.edge_id, 0.0) <= maximum_diffusion
        and scores[edge.edge_id] > 0.0
        and scores[edge.edge_id] >= threshold
    )
    for edge_id in eligible:
        evidence[edge_id]["escape_eligible"] = 1.0
    return RarityEscapeResult(scores, evidence, eligible, threshold)


__all__ = ["RarityEscapeResult", "compute_rarity_escape"]
