"""Offline, source-validated chain retention and mutually exclusive loss funnels.

This module accepts frozen event identities, never a scorer or selection callback.
A reference's review declaration is supplied by the independent annotation source;
structural validity alone cannot upgrade derived or synthetic paths to attack truth.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any


def _identifier(value: Any) -> str:
    result = str(value).strip().upper()
    if value is None or not result:
        raise ValueError("event and node identities must be nonempty")
    return result


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def _stage_sets(stages: Mapping[str, Iterable[str]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    previous: set[str] | None = None
    for name, values in stages.items():
        if not isinstance(name, str) or not name.strip() or name in {"surviving", "invalid_reference"}:
            raise ValueError("stage names must be nonempty and cannot use reserved loss labels")
        if isinstance(values, (str, bytes)):
            raise ValueError("stage events must be an iterable of event identities")
        current = {_identifier(value) for value in values}
        if previous is not None and not current <= previous:
            raise ValueError(f"stages must be nested: {name!r} introduces events absent from the previous stage")
        result[name] = current
        previous = current
    return result


def evaluate_event_funnel(
    reference_ids: Iterable[str], stages: Mapping[str, Iterable[str]],
) -> dict[str, Any]:
    """Account for each reference event's first loss in caller-supplied stage order."""
    references = {_identifier(value) for value in reference_ids}
    stage_sets = _stage_sets(stages)
    previous = references
    stage_results: dict[str, Any] = {}
    first_loss = {name: 0 for name in stage_sets}
    for name, ids in stage_sets.items():
        present = references & ids
        lost = previous - present
        stage_results[name] = {
            "retained_event_count": len(present),
            "total_retention": _ratio(len(present), len(references)),
            "conditional_retention": _ratio(len(present), len(previous)),
            "missing_ids": sorted(references - ids),
            "lost_ids": sorted(lost),
        }
        first_loss[name] = len(lost)
        previous = present
    first_loss["surviving"] = len(previous)
    return {"reference_event_count": len(references), "stage_order": list(stage_sets),
            "stages": stage_results, "first_loss_counts": first_loss}


def _nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value) and any(_nonempty(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return bool(value) and any(_nonempty(item) for item in value)
    return False


def _admission(chain: Mapping[str, Any]) -> str:
    provenance = chain.get("provenance") or {}
    if not isinstance(provenance, Mapping):
        raise ValueError("chain provenance must be a mapping")
    kind = provenance.get("kind")
    if kind in {"derived_reference", "synthetic"}:
        return str(kind)
    reviewer = chain.get("reviewed_by", provenance.get("reviewed_by"))
    scope = chain.get("scope", provenance.get("scope"))
    if (kind == "independent_review" and chain.get("scope_complete") is True
            and _nonempty(reviewer) and _nonempty(scope)):
        return "independent_complete"
    return "unreviewed_reference"


def _event_sequence(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        raise ValueError("reference event sequences must be ordered lists or tuples")
    return [_identifier(value) for value in values]


def _causal_endpoints(row: Mapping[str, Any]) -> tuple[str, str]:
    src, dst = _identifier(row["src"]), _identifier(row["dst"])
    if str(row["relation"]).upper() == "EVENT_EXECUTE":
        return dst, src
    return src, dst


def _timestamp(row: Mapping[str, Any]) -> int:
    value = row["timestamp_ns"]
    result = int(value)
    if isinstance(value, bool) or (not isinstance(value, str) and value != result):
        raise ValueError("timestamp_ns must be an exact integer")
    return result


def _validate_witnesses(
    paths: list[tuple[str, list[str]]], required: set[str],
    by_event: Mapping[str, Mapping[str, Any]],
) -> tuple[str, list[str], list[dict[str, Any]]]:
    missing = sorted(required - by_event.keys())
    breakpoints: list[dict[str, Any]] = [
        {"reason": "missing_source_event", "event_id": event, "stage": "source"}
        for event in missing
    ]
    malformed: set[str] = set()
    for event in sorted(required & by_event.keys()):
        try:
            _causal_endpoints(by_event[event])
            _timestamp(by_event[event])
        except (KeyError, TypeError, ValueError, OverflowError):
            malformed.add(event)
            breakpoints.append({"reason": "malformed_source_event", "event_id": event, "stage": "source"})
    if not paths:
        breakpoints.append({"reason": "no_reference_path", "stage": "source"})
    for name, path in paths:
        if not path:
            breakpoints.append({"reason": "empty_reference_path", "path": name, "stage": "source"})
        for index, (left_id, right_id) in enumerate(zip(path, path[1:])):
            if left_id not in by_event or right_id not in by_event or {left_id, right_id} & malformed:
                continue
            left, right = by_event[left_id], by_event[right_id]
            context = {"path": name, "position": index + 1, "left_event_id": left_id,
                       "right_event_id": right_id, "stage": "source"}
            left_time, right_time = _timestamp(left), _timestamp(right)
            if left_time >= right_time:
                reason = "simultaneous_timestamp" if left_time == right_time else "reversed_timestamp"
                breakpoints.append({**context, "reason": reason})
            if _causal_endpoints(left)[1] != _causal_endpoints(right)[0]:
                breakpoints.append({**context, "reason": "disconnected_direction"})
    status = "unverifiable" if missing else "invalid" if breakpoints else "valid"
    return status, missing, breakpoints


def evaluate_chains(
    chains: Iterable[Mapping[str, Any]],
    source_rows: Iterable[Mapping[str, Any]],
    stages: Mapping[str, Iterable[str]],
) -> dict[str, Any]:
    """Validate all branches against source events, then count exact retention.

    ``event_ids`` and every ``branches`` sequence are independent mandatory
    directed witnesses with strictly increasing timestamps. Their union plus
    ``required_event_ids`` is indivisible for retention. ``source_rows`` must
    come from the pre-pruning graph, not the candidate-only or retained graph.
    Stage event sets must be nested, and must contain only source event IDs.

    Complete-attack denominators include every independently reviewed, declared
    complete reference, including ones missing from the source. Invalid or
    unverifiable source witnesses never enter the numerator. Separate counts
    expose these limitations instead of silently shrinking the denominator.
    """
    stage_sets = _stage_sets(stages)
    by_event: dict[str, Mapping[str, Any]] = {}
    for row in source_rows:
        event = _identifier(row["event_id"])
        if event in by_event:
            raise ValueError(f"duplicate source event identity: {event}")
        by_event[event] = row
    for name, ids in stage_sets.items():
        if ids - by_event.keys():
            raise ValueError(f"stage {name!r} contains event identities missing from source_rows")
    seen_chain_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    all_reference_ids: set[str] = set()
    loss_counts = {name: 0 for name in stage_sets}
    loss_counts.update({"invalid_reference": 0, "surviving": 0})
    for chain in chains:
        chain_id = str(chain.get("id", "")).strip()
        if not chain_id:
            raise ValueError("chain id must be nonempty")
        if chain_id in seen_chain_ids:
            raise ValueError(f"duplicate chain identity: {chain_id}")
        seen_chain_ids.add(chain_id)
        paths: list[tuple[str, list[str]]] = []
        if "event_ids" in chain:
            paths.append(("event_ids", _event_sequence(chain["event_ids"])))
        branches = chain.get("branches", [])
        if not isinstance(branches, (list, tuple)):
            raise ValueError("branches must be an ordered list of event sequences")
        paths.extend((f"branches[{index}]", _event_sequence(path)) for index, path in enumerate(branches))
        required = {event for _, path in paths for event in path}
        required.update(_event_sequence(chain.get("required_event_ids", [])))
        all_reference_ids.update(required)
        admission = _admission(chain)
        status, missing_source, breakpoints = _validate_witnesses(paths, required, by_event)
        chain_stages: dict[str, Any] = {}
        first_loss: str | None = None
        if status == "invalid":
            first_loss = "invalid_reference"
        elif status == "unverifiable":
            first_loss = "source" if "source" not in stage_sets else next(iter(stage_sets))
            loss_counts.setdefault(first_loss, 0)
        for name, ids in stage_sets.items():
            missing = sorted(required - ids)
            complete = status == "valid" and not missing
            stage_breakpoints = [{"reason": "missing_event", "event_id": event, "stage": name} for event in missing]
            chain_stages[name] = {"complete": complete, "missing_ids": missing, "breakpoints": stage_breakpoints}
            if first_loss is None and not complete:
                first_loss = name
        loss_counts[first_loss or "surviving"] += 1
        records.append({
            "id": chain_id, "provenance": deepcopy(dict(chain.get("provenance") or {})),
            "scope_complete": chain.get("scope_complete") is True,
            "admission_status": admission,
            "source_validation": {"status": status, "valid": status == "valid"},
            "event_ids": next((path for name, path in paths if name == "event_ids"), []),
            "branches": [path for name, path in paths if name.startswith("branches[")],
            "required_event_ids": sorted(required), "missing_source_ids": missing_source,
            "first_loss_stage": first_loss, "stages": chain_stages, "breakpoints": breakpoints,
        })
    classes = {kind: [record for record in records if record["admission_status"] == kind]
               for kind in ("independent_complete", "derived_reference", "synthetic", "unreviewed_reference")}
    denominators = {kind: len(items) for kind, items in classes.items()}
    previous_complete = denominators["independent_complete"]
    stage_results = {}
    for name in stage_sets:
        counts = {kind: sum(record["stages"][name]["complete"] for record in items)
                  for kind, items in classes.items()}
        complete_count = counts["independent_complete"]
        all_count = sum(counts.values())
        stage_results[name] = {
            "complete_chain_count": complete_count,
            "complete_chain_retention": _ratio(complete_count, denominators["independent_complete"]),
            "conditional_complete_chain_retention": _ratio(complete_count, previous_complete),
            "derived_chain_count": counts["derived_reference"],
            "derived_chain_retention": _ratio(counts["derived_reference"], denominators["derived_reference"]),
            "synthetic_chain_count": counts["synthetic"],
            "synthetic_chain_retention": _ratio(counts["synthetic"], denominators["synthetic"]),
            "reference_chain_count": all_count,
            "reference_chain_retention": _ratio(all_count, len(records)),
        }
        previous_complete = complete_count
    return {
        "schema_version": "chain-evaluation-v1", "evaluation_only": True,
        "ground_truth_used_for_selection": False, "stage_order": list(stage_sets),
        "reference_chain_count": len(records),
        "admitted_complete_chain_count": denominators["independent_complete"],
        "valid_complete_chain_count": sum(item["source_validation"]["valid"] for item in classes["independent_complete"]),
        "derived_reference_chain_count": denominators["derived_reference"],
        "synthetic_chain_count": denominators["synthetic"],
        "unreviewed_reference_chain_count": denominators["unreviewed_reference"],
        "unverifiable_chain_count": sum(item["source_validation"]["status"] == "unverifiable" for item in records),
        "invalid_chain_count": sum(item["source_validation"]["status"] == "invalid" for item in records),
        "stages": stage_results, "first_loss_counts": loss_counts,
        "event_funnel": evaluate_event_funnel(all_reference_ids, stage_sets), "chains": records,
    }


__all__ = ["evaluate_chains", "evaluate_event_funnel"]
