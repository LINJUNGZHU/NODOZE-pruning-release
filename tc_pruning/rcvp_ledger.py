"""Validation helpers for the optional RCVP evidence extension."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Mapping, Sequence

from .diffusion import _causal_endpoints
from .models import Neighborhood


EXTENSION_SCHEMA = "rcvp-edge-evidence-v1"
_UNIT_FIELDS = {
    "relation_transition_weight", "relation_backward_transition_weight",
    "temporal_weight", "backward_temporal_weight", "fanout_weight",
    "backward_fanout_weight", "poi_forward_score",
    "background_forward_score", "poi_backward_score",
    "background_backward_score", "root_forward_score",
    "roundtrip_verification_score", "forward_normalized",
    "backward_normalized", "root_forward_normalized", "diffusion_legacy",
    "diffusion_relation_aware", "diffusion_verified",
}
_REQUIRED_PROPAGATION = {
    "relation_family", "relation_transition_weight", "temporal_weight",
    "fanout_weight", "forward_normalized", "backward_normalized",
    "root_forward_normalized", "roundtrip_verification_score",
    "diffusion_legacy", "diffusion_relation_aware", "diffusion_verified",
}
_REQUIRED_PRUNING = {
    "group_id", "raw_cost", "removal_priority", "removal_attempted",
    "removal_allowed", "removal_round", "rejection_reason",
}


def _json_safe(value: object, label: str) -> object:
    try:
        encoded = json.dumps(value, allow_nan=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}: must be finite JSON data") from exc
    return json.loads(encoded)


def _roots(context: Mapping[str, object]) -> list[Mapping[str, object]]:
    values: list[object] = []
    if "roots" in context:
        roots = context["roots"]
        if not isinstance(roots, list):
            raise ValueError("rcvp_context.roots must be a list")
        values.extend(roots)
    runs = context.get("runs", {})
    if not isinstance(runs, Mapping):
        raise ValueError("rcvp_context.runs must be an object")
    for poi, run in runs.items():
        if not isinstance(poi, str) or not isinstance(run, Mapping):
            raise ValueError("rcvp_context.runs must contain POI objects")
        run_roots = run.get("roots", [])
        if not isinstance(run_roots, list):
            raise ValueError(f"rcvp_context.runs.{poi}.roots must be a list")
        values.extend(run_roots)
    if any(not isinstance(root, Mapping) for root in values):
        raise ValueError("RCVP roots must be objects")
    return list(values)  # type: ignore[arg-type]


def validate_root_witnesses(
    graph: Neighborhood, context: Mapping[str, object]
) -> None:
    by_event = {edge.event_id: edge for edge in graph.edges}
    if len(by_event) != len(graph.edges):
        raise ValueError("candidate graph event IDs must be unique for RCVP")
    top_poi_ids = set(context.get("poi_event_ids", [])) if isinstance(
        context.get("poi_event_ids", []), list
    ) else set()
    root_poi_membership: dict[int, set[str]] = {}
    top_roots = context.get("roots", [])
    if isinstance(top_roots, list):
        for root in top_roots:
            root_poi_membership[id(root)] = top_poi_ids
    runs = context.get("runs", {})
    if isinstance(runs, Mapping):
        for run in runs.values():
            if isinstance(run, Mapping) and isinstance(run.get("poi_event_ids"), list):
                run_pois = set(run["poi_event_ids"])
                run_roots = run.get("roots", [])
                if isinstance(run_roots, list):
                    for root in run_roots:
                        root_poi_membership[id(root)] = run_pois
    roots = _roots(context)
    for root in roots:
        witness = root.get("witness_event_ids", root.get("witness", []))
        if not isinstance(witness, list) or not witness or any(
            not isinstance(event_id, str) or event_id not in by_event
            for event_id in witness
        ):
            raise ValueError("root witness must contain non-empty candidate event_ids")
        if len(witness) != len(set(witness)):
            raise ValueError("root witness event_ids must be unique")
        if root.get("event_id") is not None and (
            not witness or witness[0] != root["event_id"]
        ):
            raise ValueError("root witness must start at its declared event_id")
        first = by_event[witness[0]]
        first_src, _ = _causal_endpoints(first)
        if root.get("node_uuid") != first_src:
            raise ValueError("root node_uuid must match witness causal source")
        if root.get("timestamp_ns") != first.timestamp_ns:
            raise ValueError("root timestamp must match first witness event")
        score = _number(root.get("score"), unit=True)
        seed_weight = _number(root.get("seed_weight"), unit=True)
        if score is None or score <= 0.0 or seed_weight is None or seed_weight <= 0.0:
            raise ValueError("root score and seed_weight must be finite in (0, 1]")
        poi_event_id = root.get("poi_event_id")
        allowed_pois = root_poi_membership.get(id(root), top_poi_ids)
        if (
            not isinstance(poi_event_id, str)
            or poi_event_id not in allowed_pois
        ):
            raise ValueError("root witness must name a declared POI event")
        poi_edge = by_event.get(poi_event_id)
        last_edge = by_event[witness[-1]]
        if witness[-1] != poi_event_id:
            _, last_target = _causal_endpoints(last_edge)
            poi_endpoints = set(_causal_endpoints(poi_edge))
            if (
                last_target not in poi_endpoints
                or last_edge.timestamp_ns >= poi_edge.timestamp_ns
            ):
                raise ValueError(
                    "root witness must reach its POI anchor before the POI"
                )
        for left_id, right_id in zip(witness, witness[1:]):
            left, right = by_event[left_id], by_event[right_id]
            _, left_dst = _causal_endpoints(left)
            right_src, _ = _causal_endpoints(right)
            if left_dst != right_src or left.timestamp_ns >= right.timestamp_ns:
                raise ValueError("root witness is not a continuous temporal path")
    config = context.get("config", {})
    if isinstance(config, Mapping) and "max_root_candidates" in config:
        maximum = config["max_root_candidates"]
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
            raise ValueError("max_root_candidates must be a positive integer")
        if len(roots) > maximum:
            raise ValueError("root count exceeds max_root_candidates")


def _implementation_hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    result = {}
    for name in (
        "causal.py", "depimpact.py", "diffusion.py", "evaluation.py",
        "pruning.py", "progressive_pruning.py", "rasp.py", "rcvp.py",
        "rcvp_adapter.py", "rcvp_config.py", "rcvp_ledger.py",
        "rdp_guard.py", "score_ledger.py",
    ):
        path = root / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result[f"tc_pruning/{name}"] = digest
    return result


def prepare_extension(
    *, graph: Neighborhood,
    decisions: Mapping[str, Mapping[int, Sequence[str]]],
    propagation_evidence: Mapping[int, Mapping[str, object]] | None,
    progressive_evidence: Mapping[
        str, Mapping[int, Mapping[str, object]]
    ] | None,
    rcvp_context: Mapping[str, object] | None,
) -> tuple[dict[str, object] | None, dict[int, dict[str, object]]]:
    if propagation_evidence is None and progressive_evidence is None:
        return None, {}
    edge_ids = {edge.edge_id for edge in graph.edges}
    if propagation_evidence is not None and set(propagation_evidence) != edge_ids:
        raise ValueError("propagation evidence must cover candidate edges exactly")
    if progressive_evidence is not None and set(progressive_evidence) != set(decisions):
        raise ValueError("progressive evidence budgets must match decisions exactly")
    for budget, values in (progressive_evidence or {}).items():
        if set(values) != edge_ids:
            raise ValueError(
                f"progressive evidence {budget} must cover candidate edges exactly"
            )
    context = _json_safe(dict(rcvp_context or {}), "rcvp_context")
    assert isinstance(context, dict)
    if propagation_evidence is not None:
        if "scope" in context and context.get("scope") not in {"winner_poi", "per_poi"}:
            raise ValueError("rcvp_context.scope must be winner_poi or per_poi")
        if "scope" not in context and not {
            "version", "operator", "config"
        } <= set(context):
            raise ValueError("joint RCVP context requires version, operator, and config")
        validate_root_witnesses(graph, context)
    rows = {}
    for edge_id in edge_ids:
        rows[edge_id] = {
            "schema_version": EXTENSION_SCHEMA,
            **({"propagation": _json_safe(
                dict(propagation_evidence[edge_id]),
                f"propagation evidence edge {edge_id}",
            )} if propagation_evidence is not None else {}),
            "pruning": {
                budget: _json_safe(dict(progressive_evidence[budget][edge_id]),
                                   f"progressive evidence {budget} edge {edge_id}")
                for budget in sorted(progressive_evidence or {})
            },
        }
    manifest = {
        "schema_version": EXTENSION_SCHEMA,
        "context": context,
        "implementation_sha256": _implementation_hashes(),
        "propagation_edge_count": len(edge_ids),
        "propagation_present": propagation_evidence is not None,
        "progressive_present": progressive_evidence is not None,
        "progressive_budget_keys": sorted(progressive_evidence or {}),
    }
    errors = validate_extension(graph, decisions, manifest, rows)
    if errors:
        raise ValueError(errors[0])
    return manifest, rows


def _number(value: object, *, unit: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or (unit and number > 1.0):
        return None
    return number


def validate_extension(
    graph: Neighborhood,
    decisions: Mapping[str, Mapping[int, Sequence[str]]],
    manifest: Mapping[str, object],
    rows: Mapping[int, Mapping[str, object]],
) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != EXTENSION_SCHEMA:
        return ["rcvp_extension: unsupported extension schema"]
    if manifest.get("implementation_sha256") != _implementation_hashes():
        errors.append("rcvp extension implementation SHA mismatch")
    edge_ids = {edge.edge_id for edge in graph.edges}
    if set(rows) != edge_ids:
        errors.append("rcvp extension row coverage mismatch")
    propagation_present = manifest.get("propagation_present") is True
    progressive_present = manifest.get("progressive_present") is True
    budgets = manifest.get("progressive_budget_keys")
    expected_budgets = sorted(decisions) if progressive_present else []
    if budgets != expected_budgets:
        errors.append("rcvp extension decision budget coverage mismatch")
    context = manifest.get("context")
    if not isinstance(context, Mapping):
        errors.append("rcvp extension context must be an object")
        context = {}
    elif propagation_present:
        try:
            validate_root_witnesses(graph, context)
        except ValueError as exc:
            errors.append(str(exc))
    event_by_edge = {edge.edge_id: edge.event_id for edge in graph.edges}
    declared_pois = set(context.get("poi_event_ids", [])) if isinstance(
        context.get("poi_event_ids", []), list
    ) else set()
    runs_value = context.get("runs", {})
    if isinstance(runs_value, Mapping):
        for run_value in runs_value.values():
            if isinstance(run_value, Mapping) and isinstance(
                run_value.get("poi_event_ids"), list
            ):
                declared_pois.update(run_value["poi_event_ids"])
    for edge_id, row in rows.items():
        label = f"rcvp edge {edge_id}"
        if row.get("schema_version") != EXTENSION_SCHEMA:
            errors.append(f"{label}: unsupported extension schema")
        propagation = row.get("propagation")
        if not propagation_present:
            if propagation is not None:
                errors.append(f"{label}: unexpected propagation evidence")
            propagation = None
        elif not isinstance(propagation, Mapping):
            errors.append(f"{label}: propagation must be an object")
            continue
        if propagation is None:
            missing: set[str] = set()
        else:
            missing = _REQUIRED_PROPAGATION - set(propagation)
        stated_poi = propagation.get("poi_event_id") if propagation else None
        stated_pois = propagation.get("poi_event_ids", []) if propagation else []
        if stated_poi is not None and (
            not isinstance(stated_poi, str) or stated_poi not in declared_pois
        ):
            errors.append(f"{label}: poi_event_id is not declared by its RCVP run")
        if stated_pois and (
            not isinstance(stated_pois, list)
            or any(not isinstance(value, str) for value in stated_pois)
            or not set(stated_pois) <= declared_pois
        ):
            errors.append(f"{label}: poi_event_ids are not declared by an RCVP run")
        config = context.get("config", {})
        if not isinstance(config, Mapping) and propagation is not None:
            config = {}
        if propagation is not None and not config:
            runs = context.get("runs", {})
            run = {}
            if isinstance(runs, Mapping):
                for candidate in runs.values():
                    candidate_pois = (
                        candidate.get("poi_event_ids", [])
                        if isinstance(candidate, Mapping) else []
                    )
                    if (
                        isinstance(candidate_pois, list)
                        and (
                            stated_poi in candidate_pois
                            or bool(stated_pois)
                            and set(stated_pois) <= set(candidate_pois)
                        )
                    ):
                        run = candidate
                        break
            config = run.get("config", {}) if isinstance(run, Mapping) else {}
        weights = config.get("channel_weights", {}) if isinstance(config, Mapping) else {}
        expected_weights = {
            name: weights.get(name)
            for name in ("backward", "forward", "verification")
        } if isinstance(weights, Mapping) else {}
        valid_weights = all(
            _number(value, unit=True) is not None
            for value in expected_weights.values()
        )
        if propagation is not None and not valid_weights:
            errors.append(f"{label}: missing finite channel_weights")
        if missing:
            errors.append(f"{label}: missing propagation fields {sorted(missing)}")
        if propagation is not None and (not isinstance(propagation.get("relation_family"), str) or not propagation.get("relation_family")):
            errors.append(f"{label}: relation_family must be a non-empty string")
        for field in _UNIT_FIELDS & set(propagation or {}):
            if _number(propagation[field], unit=True) is None:
                errors.append(f"{label}: {field} must be finite [0, 1]")
        for field in ("forward_lift", "backward_lift"):
            if propagation is not None and field in propagation and _number(propagation[field]) is None:
                errors.append(f"{label}: {field} must be finite non-negative")
        if propagation is not None and valid_weights and not missing:
            backward = float(propagation["backward_normalized"])
            forward = float(propagation["forward_normalized"])
            verification = float(propagation["roundtrip_verification_score"])
            relation_expected = 1 - (1 - float(expected_weights["backward"]) * backward) * (1 - float(expected_weights["forward"]) * forward)
            verified_expected = relation_expected + (1 - relation_expected) * float(expected_weights["verification"]) * verification
            is_poi = (
                propagation.get("poi_event_id") == event_by_edge.get(edge_id)
                or event_by_edge.get(edge_id) in set(stated_pois)
                or "scope" not in context
                and event_by_edge.get(edge_id) in declared_pois
            )
            actual_relation = propagation.get("diffusion_relation_aware")
            actual_verified = propagation.get("diffusion_verified")
            if is_poi:
                if actual_relation != 1 and actual_relation != 1.0:
                    errors.append(f"{label}: POI diffusion_relation_aware must equal 1")
            elif (
                _number(actual_relation, unit=True) is None
                or not math.isclose(float(actual_relation), relation_expected, abs_tol=1e-12)
            ):
                errors.append(f"{label}: diffusion_relation_aware noisy-OR mismatch")
            if is_poi:
                if actual_verified != 1 and actual_verified != 1.0:
                    errors.append(f"{label}: POI diffusion_verified must equal 1")
            elif _number(actual_verified, unit=True) is None or not math.isclose(float(actual_verified), verified_expected, abs_tol=1e-12):
                errors.append(f"{label}: diffusion_verified noisy-OR mismatch")
        pruning = row.get("pruning")
        expected_pruning = set(decisions) if progressive_present else set()
        if not isinstance(pruning, Mapping) or set(pruning) != expected_pruning:
            errors.append(f"{label}: pruning budget coverage mismatch")
            continue
        for budget, audit in pruning.items():
            if not isinstance(audit, Mapping) or not _REQUIRED_PRUNING <= set(audit):
                errors.append(f"{label} budget {budget}: malformed pruning audit")
                continue
            kept = edge_id in decisions[budget]
            attempted, allowed = audit.get("removal_attempted"), audit.get("removal_allowed")
            round_value = audit.get("removal_round")
            if not isinstance(attempted, bool) or not isinstance(allowed, bool):
                errors.append(f"{label} budget {budget}: attempted/allowed must be boolean")
            if kept and allowed:
                errors.append(f"{label} budget {budget}: kept edge cannot have allowed removal")
            if allowed and attempted and (
                isinstance(round_value, bool) or not isinstance(round_value, int) or round_value < 1
            ):
                errors.append(f"{label} budget {budget}: allowed removal requires positive round")
            if not kept and not allowed and audit.get("rejection_reason") != "ineligible":
                errors.append(f"{label} budget {budget}: removed edge lacks allowed decision")
            priority = audit.get("removal_priority")
            if (
                isinstance(priority, bool)
                or not isinstance(priority, (int, float))
                or not math.isfinite(float(priority))
            ):
                errors.append(f"{label} budget {budget}: invalid removal_priority")
            raw_cost = audit.get("raw_cost")
            if isinstance(raw_cost, bool) or not isinstance(raw_cost, int) or raw_cost < 1:
                errors.append(f"{label} budget {budget}: invalid raw_cost")
    return errors


__all__ = ["EXTENSION_SCHEMA", "prepare_extension", "validate_extension"]
