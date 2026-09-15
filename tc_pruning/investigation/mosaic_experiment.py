"""Deterministic online KAIROS-MOSAIC ablation assembly and selection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, replace
import hashlib
import json
import math
from typing import Iterable, Mapping

from ..detectors.kairos_adapter import KairosEvidence
from ..models import StoredEdge
from .edge_projection import EvaluationEdgeProjection, ProjectionMode
from .kairos_components import KairosAnchorComponentBuilder
from .mosaic_selector import (
    MosaicEvidenceUnit,
    ObjectiveTargets,
    RobustMultiobjectiveSelector,
)
from .safe_reducer import CertifiedProgressiveReducer


def _canonical_hash(payload: Mapping) -> str:
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


def _layer(
    event_ids: Iterable[str], edge_by_id: Mapping[str, StoredEdge],
    projector: EvaluationEdgeProjection,
) -> dict:
    ids = tuple(sorted(set(event_ids) & edge_by_id.keys()))
    projected = projector.project(edge_by_id[event] for event in ids)
    return {
        "event_ids": list(ids),
        "raw_event_count": len(ids),
        "projected_edge_count": len(projected),
    }


def _targets(units: tuple[MosaicEvidenceUnit, ...], fraction: float) -> ObjectiveTargets:
    empty = ObjectiveTargets(0, 0, 0, 0, 0)
    objective = RobustMultiobjectiveSelector.objective(units, empty)
    return ObjectiveTargets(*(
        value * fraction for value in (
            objective.kairos, objective.branch, objective.anchor,
            objective.path_prize, objective.relevance,
        )
    ))


def _units(
    event_ids: set[str], evidence: tuple[KairosEvidence, ...],
    edge_by_id: Mapping[str, StoredEdge], *, unit_size: int,
    corridor_ids: set[str], include_branch: bool = True,
    include_path: bool = True,
) -> tuple[MosaicEvidenceUnit, ...]:
    evidence_by_event: dict[str, list[KairosEvidence]] = defaultdict(list)
    for row in evidence:
        evidence_by_event[row.raw_event_id].append(row)
    components = KairosAnchorComponentBuilder().build(evidence)
    component_by_event = {
        event: component.component_id
        for component in components for event in component.event_ids
    }
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for event in sorted(event_ids & edge_by_id.keys()):
        edge = edge_by_id[event]
        grouped[(edge.relation.upper(), component_by_event.get(event, "context"))].append(event)
    result = []
    for (relation, component), events in sorted(grouped.items()):
        for offset in range(0, len(events), unit_size):
            chunk = tuple(events[offset: offset + unit_size])
            native = frozenset(
                row.native_id for event in chunk for row in evidence_by_event.get(event, ())
            )
            relevance = sum(
                max((row.loss_percentile for row in evidence_by_event.get(event, ())), default=0.05)
                for event in chunk
            ) / len(chunk)
            corridor = bool(set(chunk) & corridor_ids)
            unit_id = f"{relation}:{component}:{offset // unit_size:06d}"
            result.append(MosaicEvidenceUnit(
                unit_id,
                chunk,
                native,
                frozenset({relation}) if include_branch else frozenset(),
                frozenset({component}) if component != "context" else frozenset(),
                {"corridor": 1.0} if include_path and corridor else {},
                relevance,
                1.0 - relevance,
                corridor,
            ))
    return tuple(result)


def _selection(
    units: tuple[MosaicEvidenceUnit, ...], fraction: float, *, top_k: int,
) -> tuple[dict, tuple[MosaicEvidenceUnit, ...], ObjectiveTargets, tuple[dict, ...]]:
    active = RobustMultiobjectiveSelector.representative_prefilter(units, top_k)
    targets = _targets(active, fraction)
    frontier = RobustMultiobjectiveSelector().select_trajectory(units, targets, top_k=top_k)
    checkpoint = frontier.checkpoints[-1] if frontier.checkpoints else None
    selected_ids = set(checkpoint.selected_unit_ids) if checkpoint else set()
    selected_units = tuple(unit for unit in active if unit.unit_id in selected_ids)
    output = {
        "event_ids": list(checkpoint.selected_event_ids if checkpoint else ()),
        "raw_event_count": checkpoint.raw_event_count if checkpoint else 0,
        "objective": asdict(checkpoint.objective) if checkpoint else asdict(
            RobustMultiobjectiveSelector.objective((), targets)
        ),
        "targets": asdict(targets),
        "active_units": len(active),
        "target_satisfied": bool(checkpoint and checkpoint.objective.minimum_ratio >= 1.0),
    }
    checkpoints = tuple({
        "raw_event_count": row.raw_event_count,
        "minimum_ratio": row.objective.minimum_ratio,
        "event_ids": list(row.selected_event_ids),
    } for row in frontier.checkpoints)
    return output, selected_units, targets, checkpoints


def run_online_experiment(
    evidence: Iterable[KairosEvidence],
    edges: Iterable[StoredEdge],
    *,
    scenario: str,
    config: Mapping[str, object],
    layer_event_ids: Mapping[str, Iterable[str]] | None = None,
) -> dict:
    """Run frozen online ablations. No reference labels are accepted by design."""
    rows = tuple(sorted(evidence, key=lambda row: (row.timestamp_ns, row.native_id)))
    edge_rows = tuple(sorted(edges, key=lambda edge: (edge.timestamp_ns, edge.event_id)))
    edge_by_id = {edge.event_id: edge for edge in edge_rows}
    additions = {key: set(value) for key, value in (layer_event_ids or {}).items()}
    projection_window = int(config.get("projection_window_ns", 900_000_000_000))
    projector = EvaluationEdgeProjection(
        ProjectionMode.DEPIMPACT_COMPATIBLE, merge_window_ns=projection_window
    )
    loss = {row.raw_event_id for row in rows if row.anomalous_native}
    queue = {row.raw_event_id for row in rows if row.queue_ids}
    summary = {row.raw_event_id for row in rows if row.summary_membership}
    k_sets = {
        "K0": loss,
        "K1": queue,
        "K2": summary,
        "K3": loss | queue | summary,
    }
    k_sets["K4"] = k_sets["K3"] | additions.get("inverse", set())
    k_sets["K5"] = k_sets["K4"] | additions.get("target", set())
    k_sets["K6"] = k_sets["K5"] | additions.get("long_history", set())
    r_sets = {
        "R0": k_sets["K3"],
        "R1": k_sets["K3"] | additions.get("inverse", set()),
    }
    r_sets["R2"] = r_sets["R1"] | additions.get("target", set())
    r_sets["R3"] = r_sets["R2"] | additions.get("long_history", set())
    r_sets["R4"] = r_sets["R3"] | additions.get("corridor", set())
    fraction = float(config.get("selection_fraction", 0.8))
    unit_size = int(config.get("unit_size", 64))
    top_k = int(config.get("representative_top_k", 16))
    budget = max(1, math.ceil(len(r_sets["R4"]) * fraction)) if r_sets["R4"] else 0
    evidence_rank = defaultdict(float)
    for row in rows:
        evidence_rank[row.raw_event_id] = max(evidence_rank[row.raw_event_id], row.loss_percentile)
    legacy_ids = tuple(sorted(
        r_sets["R4"], key=lambda event: (-evidence_rank[event], event)
    )[:budget])
    s0 = _layer(legacy_ids, edge_by_id, projector)
    s0["selector"] = "legacy_relevance_prefix"

    by_relation: dict[str, list[str]] = defaultdict(list)
    for event in r_sets["R4"] & edge_by_id.keys():
        by_relation[edge_by_id[event].relation.upper()].append(event)
    for values in by_relation.values():
        values.sort(key=lambda event: (-evidence_rank[event], event))
    fair = []
    while len(fair) < budget and any(by_relation.values()):
        for relation in sorted(by_relation):
            if by_relation[relation] and len(fair) < budget:
                fair.append(by_relation[relation].pop(0))
    s1 = _layer(fair, edge_by_id, projector)
    s1["selector"] = "branch_round_robin"

    corridor_ids = additions.get("corridor", set())
    plain_units = _units(
        r_sets["R4"], rows, edge_by_id, unit_size=unit_size,
        corridor_ids=corridor_ids, include_branch=False, include_path=False,
    )
    branch_units = tuple(replace(unit, demand_prizes={}) for unit in _units(
        r_sets["R4"], rows, edge_by_id, unit_size=unit_size,
        corridor_ids=corridor_ids, include_branch=True, include_path=False,
    ))
    full_units = _units(
        r_sets["R4"], rows, edge_by_id, unit_size=unit_size,
        corridor_ids=corridor_ids, include_branch=True, include_path=True,
    )
    s2, _, _, _ = _selection(plain_units, fraction, top_k=top_k)
    s2["selector"] = "multiobjective_no_branch"
    s3, _, _, _ = _selection(branch_units, fraction, top_k=top_k)
    s3["selector"] = "multiobjective_branch_concave"
    s4, selected_units, targets, frontier = _selection(full_units, fraction, top_k=top_k)
    s4["selector"] = "multiobjective_branch_path_prize"
    reduced = CertifiedProgressiveReducer().reduce(selected_units, targets)
    s5 = _layer(reduced.selected_event_ids, edge_by_id, projector)
    s5.update({
        "selector": "certified_progressive_safe_deletion",
        "removed_unit_ids": list(reduced.removed_unit_ids),
        "rejected_removals": list(reduced.rejected_removals),
    })
    selection = {"S0": s0, "S1": s1, "S2": s2, "S3": s3, "S4": s4, "S5": s5}
    for value in selection.values():
        if "projected_edge_count" not in value:
            projected = _layer(value["event_ids"], edge_by_id, projector)
            value["projected_edge_count"] = projected["projected_edge_count"]
    payload = {
        "schema_version": "kairos-mosaic-online-v1",
        "dataset": "DARPA_TC_E3_CADETS",
        "scenario": str(scenario).zfill(2),
        "groundtruth_access": "NONE",
        "config": dict(sorted(config.items())),
        "mapped_native_events": len(rows),
        "available_raw_events": len(edge_by_id),
        "kairos_ablations": {key: _layer(value, edge_by_id, projector) for key, value in k_sets.items()},
        "retrieval_ablations": {key: _layer(value, edge_by_id, projector) for key, value in r_sets.items()},
        "selection_ablations": selection,
        "quality_size_frontier": list(frontier),
    }
    payload["content_sha256"] = _canonical_hash(payload)
    return payload


__all__ = ["run_online_experiment"]
