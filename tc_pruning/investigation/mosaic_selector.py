from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
from typing import Mapping


@dataclass(frozen=True, slots=True)
class MosaicEvidenceUnit:
    unit_id: str
    raw_event_ids: tuple[str, ...]
    kairos_ids: frozenset[str]
    branch_ids: frozenset[str]
    anchor_ids: frozenset[str]
    demand_prizes: Mapping[str, float]
    relevance: float
    removal_risk: float
    mandatory_bridge: bool


@dataclass(frozen=True, slots=True)
class ObjectiveTargets:
    kairos: float
    branch: float
    anchor: float
    path_prize: float
    relevance: float


@dataclass(frozen=True, slots=True)
class ObjectiveVector:
    kairos: float
    branch: float
    anchor: float
    path_prize: float
    relevance: float
    minimum_ratio: float


@dataclass(frozen=True, slots=True)
class SelectionCheckpoint:
    selected_unit_ids: tuple[str, ...]
    selected_event_ids: tuple[str, ...]
    raw_event_count: int
    objective: ObjectiveVector


@dataclass(frozen=True, slots=True)
class QualitySizeFrontier:
    checkpoints: tuple[SelectionCheckpoint, ...]
    minimum_satisfying_event_ids: tuple[str, ...] | None
    active_units: int


class RobustMultiobjectiveSelector:
    @staticmethod
    def branch_gain(branches, coverage) -> float:
        return sum(
            (math.log1p(coverage.get(branch, 0) + 1) - math.log1p(coverage.get(branch, 0)))
            / math.log(2)
            for branch in branches
        )

    @staticmethod
    def objective(units: tuple[MosaicEvidenceUnit, ...], targets: ObjectiveTargets) -> ObjectiveVector:
        kairos = {item for unit in units for item in unit.kairos_ids}
        anchors = {item for unit in units for item in unit.anchor_ids}
        branches = Counter(item for unit in units for item in unit.branch_ids)
        prizes = {}
        for unit in units:
            for demand, prize in unit.demand_prizes.items():
                prizes[demand] = max(prizes.get(demand, 0.0), float(prize))
        values = (
            float(len(kairos)),
            sum(math.log1p(count) / math.log(2) for count in branches.values()),
            float(len(anchors)), sum(prizes.values()),
            sum(max(0.0, unit.relevance) for unit in units),
        )
        requested = (targets.kairos, targets.branch, targets.anchor, targets.path_prize, targets.relevance)
        ratios = [value / target if target > 0 else 1.0 for value, target in zip(values, requested)]
        return ObjectiveVector(*values, min(ratios))

    @staticmethod
    def representative_prefilter(units: tuple[MosaicEvidenceUnit, ...], top_k: int = 16):
        if top_k < 1:
            raise ValueError("top_k must be positive")
        lanes = {}
        for unit in units:
            labels = unit.branch_ids or unit.anchor_ids or frozenset({"unassigned"})
            for label in labels:
                lanes.setdefault(label, []).append(unit)
        keep = {unit.unit_id for unit in units if unit.mandatory_bridge}
        for lane in lanes.values():
            lane.sort(key=lambda unit: (-(unit.relevance + len(unit.kairos_ids) + sum(unit.demand_prizes.values())), unit.unit_id))
            keep.update(unit.unit_id for unit in lane[:top_k])
        return tuple(unit for unit in sorted(units, key=lambda item: item.unit_id) if unit.unit_id in keep)

    def select_trajectory(self, units, targets: ObjectiveTargets, *, top_k: int = 16) -> QualitySizeFrontier:
        active = self.representative_prefilter(tuple(units), top_k)
        selected = []
        remaining = list(active)
        checkpoints = []
        satisfying = None
        covered_kairos = set()
        covered_anchors = set()
        branch_coverage = Counter()
        demand_prizes = {}
        relevance = 0.0
        selected_events = set()
        target_values = (
            targets.kairos, targets.branch, targets.anchor,
            targets.path_prize, targets.relevance,
        )

        def state_objective():
            values = (
                float(len(covered_kairos)),
                sum(math.log1p(count) / math.log(2) for count in branch_coverage.values()),
                float(len(covered_anchors)), sum(demand_prizes.values()), relevance,
            )
            ratios = [value / target if target > 0 else 1.0 for value, target in zip(values, target_values)]
            return ObjectiveVector(*values, min(ratios))

        while remaining:
            candidates = []
            before = state_objective()
            before_values = (
                before.kairos, before.branch, before.anchor,
                before.path_prize, before.relevance,
            )
            for unit in remaining:
                gains = (
                    float(len(unit.kairos_ids - covered_kairos)),
                    self.branch_gain(unit.branch_ids, branch_coverage),
                    float(len(unit.anchor_ids - covered_anchors)),
                    sum(max(0.0, float(prize) - demand_prizes.get(demand, 0.0))
                        for demand, prize in unit.demand_prizes.items()),
                    max(0.0, unit.relevance),
                )
                after_values = tuple(value + gain for value, gain in zip(before_values, gains))
                ratios_after = [
                    value / target if target > 0 else 1.0
                    for value, target in zip(after_values, target_values)
                ]
                after_minimum = min(ratios_after)
                cost = len(set(unit.raw_event_ids) - selected_events) or 1
                newly_advanced = sum(
                    target > 0 and previous < target and current > previous
                    for target, previous, current in zip(target_values, before_values, after_values)
                )
                normalized_gain = sum(
                    (current - previous) / target
                    for target, previous, current in zip(target_values, before_values, after_values)
                    if target > 0
                )
                ratios = (
                    after_minimum,
                    newly_advanced,
                    normalized_gain / cost,
                )
                candidates.append((ratios, unit.unit_id, unit))
            _, _, chosen = max(candidates, key=lambda item: (item[0], tuple(-ord(c) for c in item[1])))
            selected.append(chosen)
            remaining.remove(chosen)
            covered_kairos.update(chosen.kairos_ids)
            covered_anchors.update(chosen.anchor_ids)
            branch_coverage.update(chosen.branch_ids)
            for demand, prize in chosen.demand_prizes.items():
                demand_prizes[demand] = max(demand_prizes.get(demand, 0.0), float(prize))
            relevance += max(0.0, chosen.relevance)
            selected_events.update(chosen.raw_event_ids)
            objective = state_objective()
            events = tuple(sorted(selected_events))
            checkpoint = SelectionCheckpoint(tuple(unit.unit_id for unit in selected), events, len(events), objective)
            checkpoints.append(checkpoint)
            if objective.minimum_ratio >= 1.0:
                satisfying = events
                break
        return QualitySizeFrontier(tuple(checkpoints), satisfying, len(active))


__all__ = [
    "MosaicEvidenceUnit", "ObjectiveTargets", "ObjectiveVector", "QualitySizeFrontier",
    "RobustMultiobjectiveSelector", "SelectionCheckpoint",
]
