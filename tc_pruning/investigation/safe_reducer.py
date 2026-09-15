from __future__ import annotations

from dataclasses import dataclass

from .mosaic_selector import MosaicEvidenceUnit, ObjectiveTargets, RobustMultiobjectiveSelector


@dataclass(frozen=True, slots=True)
class ReductionResult:
    selected_unit_ids: tuple[str, ...]
    selected_event_ids: tuple[str, ...]
    removed_unit_ids: tuple[str, ...]
    rejected_removals: tuple[str, ...]


class CertifiedProgressiveReducer:
    def reduce(self, units, targets: ObjectiveTargets, *, path_bundles=()) -> ReductionResult:
        selected = list(units)
        bundles_by_demand = {}
        for bundle in path_bundles:
            bundles_by_demand.setdefault(bundle.demand_id, []).append(
                frozenset(bundle.raw_event_ids)
            )
        initial_events = {
            event for item in selected for event in item.raw_event_ids
        }
        protected_demands = {
            demand: bundles for demand, bundles in bundles_by_demand.items()
            if any(bundle <= initial_events for bundle in bundles)
        }
        removed = []
        rejected = []
        for unit in sorted(selected, key=lambda item: (item.removal_risk, item.unit_id)):
            if unit.mandatory_bridge:
                rejected.append(unit.unit_id)
                continue
            trial = tuple(item for item in selected if item.unit_id != unit.unit_id)
            trial_events = {
                event for item in trial for event in item.raw_event_ids
            }
            witnesses_valid = all(
                any(bundle <= trial_events for bundle in bundles)
                for bundles in protected_demands.values()
            )
            if (
                witnesses_valid
                and RobustMultiobjectiveSelector.objective(trial, targets).minimum_ratio >= 1.0
            ):
                selected = list(trial)
                removed.append(unit.unit_id)
            else:
                rejected.append(unit.unit_id)
        events = tuple(sorted({event for unit in selected for event in unit.raw_event_ids}))
        return ReductionResult(tuple(sorted(unit.unit_id for unit in selected)), events,
                               tuple(removed), tuple(rejected))


__all__ = ["CertifiedProgressiveReducer", "ReductionResult"]
