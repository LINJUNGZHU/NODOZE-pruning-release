from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import heapq
import math
import time
from typing import Iterable, Mapping

from .evidence_units import EvidenceUnit


@dataclass(frozen=True, slots=True)
class BranchFairConfig:
    lambda_relevance: float = 1.0
    lambda_branch: float = 1.0
    lambda_anchor: float = 1.0
    lambda_motif: float = 0.5
    lambda_verification: float = 1.0
    lambda_redundancy: float = 0.25

    def __post_init__(self) -> None:
        if any(
            value < 0
            for value in (
                self.lambda_relevance,
                self.lambda_branch,
                self.lambda_anchor,
                self.lambda_motif,
                self.lambda_verification,
                self.lambda_redundancy,
            )
        ):
            raise ValueError("selector lambdas must be non-negative")


@dataclass(frozen=True, slots=True)
class SelectionLedgerRow:
    unit_id: str
    unit_raw_event_cost: int
    marginal_relevance: float
    marginal_branch: float
    marginal_anchor: float
    marginal_motif: float
    marginal_verification: float
    redundancy_penalty: float
    marginal_total: float
    utility_per_cost: float
    selected: bool
    selection_round: int | None
    selection_reason: str


@dataclass(frozen=True, slots=True)
class BranchFairSelectionResult:
    selected_unit_ids: tuple[str, ...]
    selected_event_ids: tuple[str, ...]
    raw_event_cost: int
    budget: int
    branch_coverage: Mapping[str, int]
    anchor_coverage: Mapping[str, int]
    motif_coverage: Mapping[str, int]
    heap_pushes: int
    heap_pops: int
    utility_recomputes: int
    candidate_units: int
    selected_units: int
    ledger: tuple[SelectionLedgerRow, ...]
    selection_seconds: float = field(compare=False)


class LazyGreedySelector:
    def __init__(self, config: BranchFairConfig) -> None:
        self.config = config

    @staticmethod
    def _coverage_gain(labels: Iterable[str], coverage: Mapping[str, int]) -> float:
        return sum(
            math.log1p(coverage.get(label, 0) + 1)
            - math.log1p(coverage.get(label, 0))
            for label in labels
        )

    def marginal(
        self,
        unit: EvidenceUnit,
        branch_coverage: Mapping[str, int],
        covered_events: set[str],
        anchor_or_motif_coverage: set[str],
        *,
        anchor_coverage: Mapping[str, int] | None = None,
        motif_coverage: Mapping[str, int] | None = None,
    ) -> dict[str, float]:
        anchors = anchor_coverage or {
            value: 1 for value in anchor_or_motif_coverage
        }
        motifs = motif_coverage or {
            value: 1 for value in anchor_or_motif_coverage
        }
        overlap = len(set(unit.raw_event_ids) & covered_events)
        redundancy = overlap / max(1, unit.raw_event_cost)
        relevance = self.config.lambda_relevance * max(
            0.0, float(unit.normalized_relevance)
        )
        branch = self.config.lambda_branch * self._coverage_gain(
            unit.branch_ids, branch_coverage
        )
        anchor = self.config.lambda_anchor * self._coverage_gain(
            unit.anchor_ids, anchors
        )
        motif_labels = () if unit.motif_type is None else (unit.motif_type,)
        motif = self.config.lambda_motif * self._coverage_gain(
            motif_labels, motifs
        )
        verification = self.config.lambda_verification * max(
            0.0, float(unit.verification_score)
        )
        penalty = self.config.lambda_redundancy * redundancy
        return {
            "relevance": relevance,
            "branch": branch,
            "anchor": anchor,
            "motif": motif,
            "verification": verification,
            "redundancy": penalty,
            "total": relevance + branch + anchor + motif + verification - penalty,
        }

    def select(
        self,
        units: Iterable[EvidenceUnit],
        *,
        mandatory_event_ids: set[str],
        budget: int,
    ) -> BranchFairSelectionResult:
        started = time.perf_counter()
        if budget < 0:
            raise ValueError("budget must be non-negative")
        unit_list = tuple(sorted(units, key=lambda unit: unit.unit_id))
        covered = set(mandatory_event_ids)
        branches: Counter[str] = Counter()
        anchors: Counter[str] = Counter()
        motifs: Counter[str] = Counter()
        selected: list[EvidenceUnit] = []
        selected_round: dict[str, int] = {}
        heap: list[tuple[float, str, int]] = []
        versions = {unit.unit_id: 0 for unit in unit_list}
        unit_by_id = {unit.unit_id: unit for unit in unit_list}
        precovered_units: set[str] = set()
        pushes = pops = recomputes = 0

        def push(unit: EvidenceUnit, version: int) -> None:
            nonlocal pushes
            values = self.marginal(
                unit, branches, covered, set(),
                anchor_coverage=anchors, motif_coverage=motifs,
            )
            cost = len(set(unit.raw_event_ids) - covered)
            ratio = values["total"] / max(1, cost)
            heapq.heappush(heap, (-ratio, unit.unit_id, version))
            pushes += 1

        for unit in unit_list:
            if set(unit.raw_event_ids) <= covered:
                precovered_units.add(unit.unit_id)
                branches.update(unit.branch_ids)
                anchors.update(unit.anchor_ids)
                if unit.motif_type is not None:
                    motifs.update((unit.motif_type,))
                continue
            push(unit, 0)
        round_index = 0
        while heap:
            _, unit_id, version = heapq.heappop(heap)
            pops += 1
            if unit_id in selected_round:
                continue
            unit = unit_by_id[unit_id]
            if version != round_index:
                versions[unit_id] += 1
                push(unit, round_index)
                recomputes += 1
                continue
            new_events = set(unit.raw_event_ids) - covered
            if len(covered) + len(new_events) > budget:
                continue
            values = self.marginal(
                unit, branches, covered, set(),
                anchor_coverage=anchors, motif_coverage=motifs,
            )
            if values["total"] <= 0:
                break
            round_index += 1
            selected.append(unit)
            selected_round[unit_id] = round_index
            covered.update(new_events)
            branches.update(unit.branch_ids)
            anchors.update(unit.anchor_ids)
            if unit.motif_type is not None:
                motifs.update((unit.motif_type,))
            if len(covered) >= budget:
                break

        ledger = []
        # Final-state marginals are diagnostic for unselected units; selected rows retain
        # their selection round while remaining fully auditable.
        for unit in unit_list:
            values = self.marginal(
                unit, branches, covered, set(),
                anchor_coverage=anchors, motif_coverage=motifs,
            )
            new_cost = len(set(unit.raw_event_ids) - mandatory_event_ids)
            ledger.append(SelectionLedgerRow(
                unit.unit_id,
                unit.raw_event_cost,
                values["relevance"],
                values["branch"],
                values["anchor"],
                values["motif"],
                values["verification"],
                values["redundancy"],
                values["total"],
                values["total"] / max(1, new_cost),
                unit.unit_id in selected_round,
                selected_round.get(unit.unit_id),
                (
                    "branch_fair_lazy_greedy" if unit.unit_id in selected_round
                    else "mandatory_precovered" if unit.unit_id in precovered_units
                    else "not_selected"
                ),
            ))
        event_order = tuple(sorted(covered))
        return BranchFairSelectionResult(
            tuple(unit.unit_id for unit in selected), event_order, len(covered), budget,
            dict(sorted(branches.items())), dict(sorted(anchors.items())),
            dict(sorted(motifs.items())), pushes, pops, recomputes, len(unit_list),
            len(selected), tuple(ledger), time.perf_counter() - started,
        )


__all__ = [
    "BranchFairConfig", "BranchFairSelectionResult", "LazyGreedySelector",
    "SelectionLedgerRow",
]
