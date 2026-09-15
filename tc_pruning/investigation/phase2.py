from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math
from typing import Iterable, Mapping

from .branch_fair_selector import BranchFairConfig, LazyGreedySelector
from .evidence_units import EvidenceUnit


@dataclass(frozen=True, slots=True)
class Phase2Config:
    algorithm_mode: str = "legacy"
    selector_mode: str = "legacy"
    budget_ratios: tuple[float, ...] = (0.05, 0.10, 0.20, 0.30)
    clean_view_enabled: bool = True
    reverse_reachability_enabled: bool = False
    reverse_samples: int = 128
    reverse_seed: int = 0
    forward_sphere_enabled: bool = False
    forward_min_marginal_gain: float = 0.01
    motif_enabled: bool = False
    preserver_enabled: bool = False
    branch_fair: BranchFairConfig = field(default_factory=BranchFairConfig)

    def __post_init__(self) -> None:
        if self.algorithm_mode not in {"legacy", "reverse_forward", "full_experimental"}:
            raise ValueError("unknown algorithm mode")
        if self.selector_mode not in {"legacy", "normalized", "branch_fair"}:
            raise ValueError("unknown selector mode")
        if not self.budget_ratios or any(not 0 < ratio <= 1 for ratio in self.budget_ratios):
            raise ValueError("budget ratios must be in (0, 1]")

    def absolute_budgets(self, baseline_candidate_count: int) -> dict[str, int]:
        if baseline_candidate_count <= 0:
            raise ValueError("baseline candidate count must be positive")
        return {
            f"{ratio:.2f}": max(1, math.floor(ratio * baseline_candidate_count))
            for ratio in self.budget_ratios
        }


@dataclass(frozen=True, slots=True)
class Phase2Selection:
    selected_event_ids: tuple[str, ...]
    selector_mode: str
    budget: int
    metrics: Mapping[str, object]


def select_residual(
    units: Iterable[EvidenceUnit],
    *,
    config: Phase2Config,
    budget: int,
    mandatory_event_ids: set[str],
    legacy_selected_event_ids: set[str],
) -> Phase2Selection:
    if config.selector_mode == "legacy":
        selected = tuple(sorted(legacy_selected_event_ids))
        if len(selected) > budget:
            raise ValueError("legacy selection exceeds absolute budget")
        return Phase2Selection(selected, "legacy", budget, {})
    result = LazyGreedySelector(config.branch_fair).select(
        units, mandatory_event_ids=mandatory_event_ids, budget=budget
    )
    return Phase2Selection(
        result.selected_event_ids,
        config.selector_mode,
        budget,
        {
            "branch_coverage": result.branch_coverage,
            "anchor_coverage": result.anchor_coverage,
            "motif_coverage": result.motif_coverage,
            "heap_pushes": result.heap_pushes,
            "heap_pops": result.heap_pops,
            "utility_recomputes": result.utility_recomputes,
            "candidate_units": result.candidate_units,
            "selected_units": result.selected_units,
        },
    )


def canonical_online_bytes(value: Mapping[str, object]) -> bytes:
    def inspect(item: object) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if "groundtruth" in str(key).lower() or "ground_truth" in str(key).lower():
                    raise ValueError("groundtruth field forbidden in online freeze")
                inspect(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                inspect(child)
    inspect(value)
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


__all__ = ["Phase2Config", "Phase2Selection", "canonical_online_bytes", "select_residual"]
