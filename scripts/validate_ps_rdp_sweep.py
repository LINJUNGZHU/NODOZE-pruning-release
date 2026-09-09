#!/usr/bin/env python3
"""Fail-closed, source-database-independent validation of a PS-RDP prefix sweep."""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import sys
from dataclasses import fields
from pathlib import Path
from statistics import fmean
from typing import Any, Iterator, Mapping, NoReturn, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tc_pruning.cdm import event_investigation_anchor  # noqa: E402
from tc_pruning.models import StoredEdge  # noqa: E402
from tc_pruning.score_ledger import SCHEMA_VERSION, verify_score_ledger  # noqa: E402


SWEEP_SCHEMA_VERSION = "cadets-e3-poi-prefix-sweep-v3"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EDGE_FIELDS = tuple(field.name for field in fields(StoredEdge))


class ValidationFailure(RuntimeError):
    """A validation invariant was not satisfied."""


def _fail(message: str) -> NoReturn:
    raise ValidationFailure(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label}: expected an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label}: expected a list")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label}: expected an integer >= {minimum}")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label}: expected a finite number")
    result = float(value)
    if not math.isfinite(result):
        _fail(f"{label}: expected a finite number")
    return result


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label}: expected a non-empty string")
    return value


def _sha256(value: object, label: str) -> str:
    digest = _string(value, label)
    if _HEX_SHA256.fullmatch(digest) is None:
        _fail(f"{label}: expected a lowercase SHA-256 digest")
    return digest


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        _fail(f"{label}: missing file {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label}: invalid JSON ({exc})")
    return _object(value, label)


def _reported_path(
    run_dir: Path,
    value: object,
    label: str,
    *,
    directory: bool = False,
) -> Path:
    raw = _string(value, label)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = run_dir / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _fail(f"{label}: path cannot be resolved ({exc})")
    try:
        resolved.relative_to(run_dir)
    except ValueError:
        _fail(f"{label}: path escapes run_dir: {resolved}")
    expected_kind = resolved.is_dir() if directory else resolved.is_file()
    kind = "directory" if directory else "file"
    _require(expected_kind, f"{label}: expected a {kind}: {resolved}")
    return resolved


def _same_number(left: object, right: object, label: str) -> None:
    actual = _number(left, f"{label} (left)")
    expected = _number(right, f"{label} (right)")
    _require(abs(actual - expected) <= 1e-15, f"{label}: {actual} != {expected}")


def _same_recomputed_value(actual: object, expected: object, label: str) -> None:
    """Compare one reported value with an independently recomputed value."""
    if expected is None:
        _require(actual is None, f"{label}: expected null, got {actual!r}")
    elif type(expected) is bool:
        _require(type(actual) is bool and actual is expected, f"{label}: {actual!r} != {expected!r}")
    elif type(expected) is int:
        _require(type(actual) is int and actual == expected, f"{label}: {actual!r} != {expected!r}")
    elif type(expected) is float:
        _same_number(actual, expected, label)
    else:
        _require(
            type(actual) is type(expected) and actual == expected,
            f"{label}: {actual!r} != {expected!r}",
        )


def _same_recomputed_fields(
    reported: Mapping[str, object],
    recomputed: Mapping[str, object],
    names: Sequence[str],
    label: str,
) -> None:
    for name in names:
        _require(name in reported, f"{label}.{name}: missing reported value")
        _require(name in recomputed, f"{label}.{name}: missing recomputed value")
        _same_recomputed_value(
            reported[name], recomputed[name], f"{label}.{name}"
        )


def _same_fields(
    row: Mapping[str, object],
    result: Mapping[str, object],
    names: Sequence[str],
    label: str,
) -> None:
    for name in names:
        _require(name in row, f"{label}.{name}: missing from summary row")
        _require(name in result, f"{label}.{name}: missing from result")
        _require(
            type(row[name]) is type(result[name]) and row[name] == result[name],
            f"{label}.{name}: summary/result mismatch "
            f"({row[name]!r} != {result[name]!r})",
        )


def _iter_gzip_jsonl(path: Path, label: str) -> Iterator[dict[str, Any]]:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    _fail(f"{label} line {line_number}: invalid JSON ({exc})")
                yield _object(value, f"{label} line {line_number}")
    except (OSError, UnicodeError) as exc:
        _fail(f"{label}: unreadable gzip JSONL ({exc})")


def _stored_edges(ledger_dir: Path) -> dict[int, StoredEdge]:
    records = _iter_gzip_jsonl(
        ledger_dir / "candidate-graph.jsonl.gz", "candidate graph"
    )
    result: dict[int, StoredEdge] = {}
    event_ids: set[str] = set()
    for record in records:
        if record.get("record_type") != "edge":
            continue
        edge_values = {name: record.get(name) for name in _EDGE_FIELDS}
        try:
            edge = StoredEdge(**edge_values)
        except TypeError as exc:
            _fail(f"candidate graph edge has invalid StoredEdge fields ({exc})")
        _require(
            isinstance(edge.edge_id, int) and not isinstance(edge.edge_id, bool),
            "candidate graph edge_id must be an integer",
        )
        _require(isinstance(edge.event_id, str) and edge.event_id, "candidate graph event_id must be a string")
        _require(edge.edge_id not in result, f"candidate graph duplicate edge_id {edge.edge_id}")
        _require(edge.event_id not in event_ids, f"candidate graph duplicate event_id {edge.event_id!r}")
        result[edge.edge_id] = edge
        event_ids.add(edge.event_id)
    return result


def _score_state(
    ledger_dir: Path, budget_key: str
) -> tuple[dict[int, float], set[int], dict[int, set[str]]]:
    rows = _iter_gzip_jsonl(ledger_dir / "edge-scores.jsonl.gz", "score ledger")
    scores: dict[int, float] = {}
    kept: set[int] = set()
    reasons: dict[int, set[str]] = {}
    for row in rows:
        edge_id = _integer(row.get("edge_id"), "score ledger edge_id")
        _require(edge_id not in scores, f"score ledger duplicate edge_id {edge_id}")
        score = _number(row.get("score"), f"score ledger edge {edge_id} score")
        _require(0.0 <= score <= 1.0, f"score ledger edge {edge_id}: score outside [0, 1]")
        scores[edge_id] = score
        decisions = _list(row.get("decisions"), f"score ledger edge {edge_id} decisions")
        matches = [
            _object(decision, f"score ledger edge {edge_id} decision")
            for decision in decisions
            if isinstance(decision, dict) and decision.get("budget_key") == budget_key
        ]
        _require(
            len(matches) == 1,
            f"score ledger edge {edge_id}: expected exactly one decision for budget {budget_key}",
        )
        decision = matches[0]
        _require(
            isinstance(decision.get("kept"), bool),
            f"score ledger edge {edge_id}: decision kept flag must be boolean",
        )
        reason_values = _list(
            decision.get("reasons"), f"score ledger edge {edge_id} decision reasons"
        )
        _require(
            all(isinstance(reason, str) and reason.strip() for reason in reason_values),
            f"score ledger edge {edge_id}: reasons must be non-empty strings",
        )
        if decision["kept"]:
            _require(reason_values, f"score ledger edge {edge_id}: kept without a reason")
            kept.add(edge_id)
            reasons[edge_id] = set(reason_values)
        else:
            _require(not reason_values, f"score ledger edge {edge_id}: unkept edge has reasons")
    return scores, kept, reasons


def _causal_endpoints(edge: StoredEdge) -> tuple[str, str]:
    if edge.relation.upper() == "EVENT_EXECUTE":
        return edge.dst, edge.src
    return edge.src, edge.dst


def _validate_witness(
    witness: object,
    expected_pair: tuple[int, int],
    edges: Mapping[int, StoredEdge],
    kept: set[int],
    reasons: Mapping[int, set[str]],
    label: str,
) -> None:
    values = _list(witness, label)
    _require(len(values) == 3, f"{label}: expected [start_id, target_id, bridge_ids]")
    start_id = _integer(values[0], f"{label}.start_id")
    target_id = _integer(values[1], f"{label}.target_id")
    bridge_ids = [
        _integer(value, f"{label}.bridge_ids") for value in _list(values[2], f"{label}.bridge_ids")
    ]
    _require((start_id, target_id) == expected_pair, f"{label}: witness pair is not the consecutive POI pair")
    chain_ids = [start_id, *bridge_ids, target_id]
    _require(len(chain_ids) == len(set(chain_ids)), f"{label}: witness repeats an edge")
    unknown = sorted(set(chain_ids) - set(edges))
    _require(not unknown, f"{label}: witness contains unknown edges {unknown[:5]}")
    missing_kept = sorted(set(chain_ids) - kept)
    _require(not missing_kept, f"{label}: witness contains unkept edges {missing_kept[:5]}")
    missing_reason = [
        edge_id
        for edge_id in chain_ids
        if "causal_path_cover" not in reasons.get(edge_id, set())
    ]
    _require(
        not missing_reason,
        f"{label}: witness edges lack causal_path_cover reason {missing_reason[:5]}",
    )

    chain = [edges[edge_id] for edge_id in chain_ids]
    keys = [(edge.timestamp_ns, edge.edge_id) for edge in chain]
    _require(keys == sorted(keys) and len(keys) == len(set(keys)), f"{label}: witness is not strictly time ordered")

    start = chain[0]
    target = chain[-1]
    _, start_target = _causal_endpoints(start)
    target_source, _ = _causal_endpoints(target)
    states = {start_target, event_investigation_anchor(start)}
    for bridge in chain[1:-1]:
        source, destination = _causal_endpoints(bridge)
        _require(source in states, f"{label}: witness has a causal discontinuity at edge {bridge.edge_id}")
        states = {destination}
    target_states = {target_source, event_investigation_anchor(target)}
    _require(bool(states & target_states), f"{label}: witness does not causally reach its target")


def _strict_path_exists(
    edges: Mapping[int, StoredEdge],
    start_id: int,
    target_id: int,
    *,
    allowed_edge_ids: set[int] | None = None,
    ordered_edges: Sequence[StoredEdge] | None = None,
) -> bool:
    """Independently recompute strict temporal reachability for one POI pair."""
    start = edges[start_id]
    target = edges[target_id]
    start_key = (start.timestamp_ns, start.edge_id)
    target_key = (target.timestamp_ns, target.edge_id)
    if target_key <= start_key:
        return False
    _, start_target = _causal_endpoints(start)
    target_source, _ = _causal_endpoints(target)
    reachable = {start_target, event_investigation_anchor(start)}
    targets = {target_source, event_investigation_anchor(target)}
    if reachable & targets:
        return True
    timeline = ordered_edges or sorted(
        edges.values(), key=lambda item: (item.timestamp_ns, item.edge_id)
    )
    for edge in timeline:
        key = (edge.timestamp_ns, edge.edge_id)
        if key <= start_key:
            continue
        if key >= target_key:
            break
        if allowed_edge_ids is not None and edge.edge_id not in allowed_edge_ids:
            continue
        source, destination = _causal_endpoints(edge)
        if source in reachable:
            reachable.add(destination)
    return bool(reachable & targets)


def _online_sequences(
    document: Mapping[str, object], selected: list[str], label: str
) -> list[list[str]]:
    for name in ("seed_uuids", "attack_event_ids", "attack_node_uuids", "attack_paths"):
        values = _list(document.get(name), f"{label}.{name}")
        _require(not values, f"{label}.{name}: online pruning input must be empty")
    seed_ids = _list(document.get("seed_event_ids"), f"{label}.seed_event_ids")
    _require(
        all(isinstance(value, str) and value for value in seed_ids),
        f"{label}.seed_event_ids: expected non-empty strings",
    )
    _require(
        len(seed_ids) == len(set(seed_ids)) and set(seed_ids) == set(selected),
        f"{label}.seed_event_ids: does not exactly match selected POIs",
    )
    groups = _list(document.get("seed_event_groups"), f"{label}.seed_event_groups")
    _require(groups, f"{label}.seed_event_groups: must not be empty")
    sequences: list[list[str]] = []
    flattened: list[str] = []
    for index, raw_group in enumerate(groups):
        group = _object(raw_group, f"{label}.seed_event_groups[{index}]")
        values = _list(
            group.get("seed_event_ids"),
            f"{label}.seed_event_groups[{index}].seed_event_ids",
        )
        _require(
            values and all(isinstance(value, str) and value for value in values),
            f"{label}.seed_event_groups[{index}]: requires POI event IDs",
        )
        _require(
            len(values) == len(set(values)),
            f"{label}.seed_event_groups[{index}]: duplicate POI",
        )
        sequences.append(list(values))
        flattened.extend(values)
    _require(
        len(flattened) == len(set(flattened)),
        f"{label}.seed_event_groups: a POI occurs in multiple certificate paths",
    )
    _require(
        set(flattened) == set(selected),
        f"{label}.seed_event_groups: path cover does not exactly match selected POIs",
    )
    metadata = _object(document.get("metadata"), f"{label}.metadata")
    _require(
        metadata.get("certificate_topology_policy") == "causal_path_cover",
        f"{label}: certificate topology policy must be causal_path_cover",
    )
    return sequences


_PATH_METRIC_FIELDS = (
    "reference_paths",
    "retained_reference_paths",
    "complete_path_retention",
    "selected_terminal_paths",
    "retained_selected_terminal_paths",
    "selected_terminal_path_retention",
    "unselected_terminal_paths",
    "retained_unselected_terminal_paths",
    "unselected_terminal_path_retention",
)

_DAY_REFERENCE_FIELDS = (
    "minimum_sufficient_poi_count",
    "earliest_legal_poi_count_at_max_path_retention",
    "minimum_legal_poi_count_for_full_path_retention",
    "minimum_observed_poi_count_for_full_path_retention",
    "maximum_retained_paths",
    "maximum_observed_retained_paths",
    "total_reference_paths",
    "maximum_complete_path_retention",
    "fully_restored",
)

_CROSS_DAY_REFERENCE_FIELDS = (
    "minimum_total_pois",
    "mean_minimum_poi_fraction",
    "macro_maximum_complete_path_retention",
    "macro_unselected_path_retention_at_minimum",
    "unselected_path_macro_contributing_days",
)


def _load_fixed_reference(
    path: Path, label: str
) -> tuple[set[str], list[tuple[str, ...]]]:
    """Load and structurally validate the offline reference artifact."""
    document = _read_json(path, label)
    raw_events = _list(document.get("attack_event_ids"), f"{label}.attack_event_ids")
    _require(raw_events, f"{label}.attack_event_ids: must not be empty")
    _require(
        all(isinstance(value, str) and value for value in raw_events),
        f"{label}.attack_event_ids: expected non-empty strings",
    )
    _require(
        len(raw_events) == len(set(raw_events)),
        f"{label}.attack_event_ids: duplicate event IDs",
    )
    attack_events = set(raw_events)

    raw_paths = _list(document.get("attack_paths"), f"{label}.attack_paths")
    _require(raw_paths, f"{label}.attack_paths: must not be empty")
    paths: list[tuple[str, ...]] = []
    for index, raw_path in enumerate(raw_paths):
        values = _list(raw_path, f"{label}.attack_paths[{index}]")
        _require(
            values and all(isinstance(value, str) and value for value in values),
            f"{label}.attack_paths[{index}]: expected non-empty event IDs",
        )
        _require(
            len(values) == len(set(values)),
            f"{label}.attack_paths[{index}]: duplicate event ID",
        )
        unknown = [value for value in values if value not in attack_events]
        _require(
            not unknown,
            f"{label}.attack_paths[{index}]: events absent from attack_event_ids "
            f"{unknown[:5]}",
        )
        paths.append(tuple(values))
    _require(
        len(paths) == len(set(paths)),
        f"{label}.attack_paths: duplicate paths",
    )
    return attack_events, paths


def _recompute_path_metrics(
    reference_paths: Sequence[Sequence[str]],
    kept_event_ids: set[str],
    selected_poi_event_ids: set[str],
) -> dict[str, int | float | None]:
    """Recompute path retention without calling the sweep producer."""
    retained = [
        path for path in reference_paths if all(value in kept_event_ids for value in path)
    ]
    selected = [
        path for path in reference_paths if path[-1] in selected_poi_event_ids
    ]
    unselected = [
        path for path in reference_paths if path[-1] not in selected_poi_event_ids
    ]
    retained_selected = [
        path for path in selected if all(value in kept_event_ids for value in path)
    ]
    retained_unselected = [
        path for path in unselected if all(value in kept_event_ids for value in path)
    ]

    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "reference_paths": len(reference_paths),
        "retained_reference_paths": len(retained),
        "complete_path_retention": ratio(len(retained), len(reference_paths)),
        "selected_terminal_paths": len(selected),
        "retained_selected_terminal_paths": len(retained_selected),
        "selected_terminal_path_retention": ratio(
            len(retained_selected), len(selected)
        ),
        "unselected_terminal_paths": len(unselected),
        "retained_unselected_terminal_paths": len(retained_unselected),
        "unselected_terminal_path_retention": ratio(
            len(retained_unselected), len(unselected)
        ),
    }


def _recompute_day_reference_summary(
    rows: Sequence[Mapping[str, object]], total_paths: int
) -> dict[str, int | float | bool | None]:
    """Independently reproduce the documented offline prefix selection rule."""
    maximum_observed = max(
        (int(row["retained_reference_paths"]) for row in rows), default=0
    )
    legal = [
        row
        for row in rows
        if row["causal_path_cover_certificate_valid"] is True
        and row["budget_feasible"] is True
        and row["churn_bound_satisfied"] is True
    ]
    maximum = max(
        (int(row["retained_reference_paths"]) for row in legal), default=0
    )
    maximum_rows = [
        row for row in legal if int(row["retained_reference_paths"]) == maximum
    ]
    legal_full = [
        row for row in legal if int(row["retained_reference_paths"]) == total_paths
    ]
    observed_full = [
        row for row in rows if int(row["retained_reference_paths"]) == total_paths
    ]
    earliest_legal_maximum = min(
        (int(row["poi_count"]) for row in maximum_rows), default=None
    )
    minimum_legal_full = min(
        (int(row["poi_count"]) for row in legal_full), default=None
    )
    minimum_observed_full = min(
        (int(row["poi_count"]) for row in observed_full), default=None
    )
    return {
        "minimum_sufficient_poi_count": minimum_legal_full,
        "earliest_legal_poi_count_at_max_path_retention": earliest_legal_maximum,
        "minimum_legal_poi_count_for_full_path_retention": minimum_legal_full,
        "minimum_observed_poi_count_for_full_path_retention": minimum_observed_full,
        "maximum_retained_paths": maximum,
        "maximum_observed_retained_paths": maximum_observed,
        "total_reference_paths": total_paths,
        "maximum_complete_path_retention": (
            maximum / total_paths if total_paths else None
        ),
        "fully_restored": maximum == total_paths,
    }


def _validate_summary(run_dir: Path) -> tuple[dict[str, Any], list[tuple[str, int, dict[str, Any]]]]:
    status = _read_json(run_dir / "process-status.json", "process status")
    _require(status.get("status") == "complete", "process status: status must be 'complete'")
    _require(status.get("exit_code") == 0 and type(status.get("exit_code")) is int, "process status: exit_code must be integer zero")

    progress = _read_json(run_dir / "progress.json", "progress")
    _require(progress.get("stage") == "complete", "progress: stage must be 'complete'")
    _require(progress.get("incomplete") is False, "progress: incomplete must be false")

    incomplete_files = sorted(run_dir.rglob("*.incomplete.json"))
    _require(not incomplete_files, f"run contains incomplete prefix artifacts: {incomplete_files[:5]}")

    summary = _read_json(run_dir / "summary.json", "summary")
    _require(summary.get("schema_version") == SWEEP_SCHEMA_VERSION, f"summary: expected schema {SWEEP_SCHEMA_VERSION!r}")
    _require(summary.get("online_uses_groundtruth") is False, "summary: online_uses_groundtruth must be false")
    rows = [_object(value, f"summary.rows[{index}]") for index, value in enumerate(_list(summary.get("rows"), "summary.rows"))]
    days = [_object(value, f"summary.days[{index}]") for index, value in enumerate(_list(summary.get("days"), "summary.days"))]
    _require(days, "summary.days: must not be empty")

    scenario_order: list[str] = []
    full_counts: dict[str, int] = {}
    for day_index, day in enumerate(days):
        scenario = _string(day.get("scenario"), f"summary.days[{day_index}].scenario")
        full_count = _integer(day.get("full_poi_count"), f"summary.days[{day_index}].full_poi_count", minimum=1)
        _require(scenario not in full_counts, f"summary.days: duplicate scenario {scenario!r}")
        scenario_order.append(scenario)
        full_counts[scenario] = full_count

    row_map: dict[tuple[str, int], dict[str, Any]] = {}
    for row_index, row in enumerate(rows):
        scenario = _string(row.get("scenario"), f"summary.rows[{row_index}].scenario")
        poi_count = _integer(row.get("poi_count"), f"summary.rows[{row_index}].poi_count", minimum=1)
        key = (scenario, poi_count)
        _require(key not in row_map, f"summary.rows: duplicate prefix {key}")
        _require(scenario in full_counts, f"summary.rows: unknown scenario {scenario!r}")
        _require(row.get("full_poi_count") == full_counts[scenario], f"summary row {key}: full_poi_count mismatch")
        row_map[key] = row

    expected = {
        (scenario, poi_count)
        for scenario, full_count in full_counts.items()
        for poi_count in range(1, full_count + 1)
    }
    missing = sorted(expected - set(row_map))
    extra = sorted(set(row_map) - expected)
    _require(not missing and not extra, f"summary prefix matrix mismatch; missing={missing[:5]}, extra={extra[:5]}")

    cross = _object(summary.get("cross_day"), "summary.cross_day")
    for name in ("completed_prefix_runs", "expected_prefix_runs"):
        _require(_integer(cross.get(name), f"summary.cross_day.{name}") == len(expected), f"summary.cross_day.{name}: expected {len(expected)}")
    _require(cross.get("score_monotonicity_violations") == 0, "summary.cross_day: score monotonicity violations are nonzero")
    _require(cross.get("local_score_digest_violations") == 0, "summary.cross_day: local score digest violations are nonzero")
    _require(cross.get("all_churn_bounds_satisfied") is True, "summary.cross_day: churn bounds are not all satisfied")
    _require(cross.get("complete_score_ledgers") == len(expected), f"summary.cross_day.complete_score_ledgers: expected {len(expected)}")
    if "completed_prefix_runs" in progress:
        _require(progress.get("completed_prefix_runs") == len(expected), f"progress.completed_prefix_runs: expected {len(expected)}")

    ordered = [
        (scenario, poi_count, row_map[(scenario, poi_count)])
        for scenario in scenario_order
        for poi_count in range(1, full_counts[scenario] + 1)
    ]
    return summary, ordered


def validate(run_dir_value: str | Path) -> dict[str, object]:
    """Validate a completed run and return a compact success document."""
    try:
        run_dir = Path(run_dir_value).resolve(strict=True)
    except OSError as exc:
        _fail(f"run_dir: cannot be resolved ({exc})")
    _require(run_dir.is_dir(), f"run_dir: expected a directory: {run_dir}")
    summary, ordered_rows = _validate_summary(run_dir)

    prior_kept: dict[str, set[int]] = {}
    prior_scores: dict[str, dict[int, float]] = {}
    prior_digests: dict[str, dict[str, str]] = {}
    prior_selected: dict[str, list[str]] = {}
    prior_sequences: dict[str, list[list[str]]] = {}
    scenario_graph_digest: dict[str, str] = {}
    scenario_context_digest: dict[str, str] = {}
    reference_paths_by_scenario: dict[str, list[tuple[str, ...]]] = {}
    reference_events_by_scenario: dict[str, set[str]] = {}
    reference_files_by_scenario: dict[str, Path] = {}
    recomputed_rows_by_scenario: dict[str, list[dict[str, object]]] = {}
    previous_retained_paths = 0
    atomic_relaxations = 0

    for scenario, poi_count, row in ordered_rows:
        label = f"scenario {scenario} prefix {poi_count}"
        if poi_count == 1:
            # Rows are scenario-major. Drop the preceding scenario's large score
            # maps before materializing this scenario's first ledger.
            prior_kept.clear()
            prior_scores.clear()
            prior_digests.clear()
            prior_selected.clear()
            prior_sequences.clear()
            scenario_graph_digest.clear()
            scenario_context_digest.clear()
            previous_retained_paths = 0
        result_path = _reported_path(run_dir, row.get("result_file"), f"{label}.result_file")
        input_path = _reported_path(
            run_dir, row.get("input_file"), f"{label}.input_file"
        )
        online_input = _read_json(input_path, f"{label} online input")
        report = _read_json(result_path, f"{label} report")
        _require(report.get("incomplete") is False, f"{label}: report is incomplete")
        results = _list(report.get("results"), f"{label}.results")
        _require(len(results) == 1, f"{label}: expected exactly one pruning result")
        result = _object(results[0], f"{label}.results[0]")

        selected = _list(row.get("selected_poi_event_ids"), f"{label}.selected_poi_event_ids")
        _require(len(selected) == poi_count, f"{label}: selected POI count mismatch")
        _require(len(selected) == len(set(selected)), f"{label}: selected POIs are not unique")
        _require(all(isinstance(value, str) and value for value in selected), f"{label}: selected POI IDs must be strings")
        if poi_count > 1:
            _require(
                selected[:-1] == prior_selected[scenario],
                f"{label}: selected POIs are not an append-only prefix",
            )
        event_sequences = _online_sequences(
            online_input, selected, f"{label} online input"
        )
        if poi_count > 1:
            previous_event_ids = set(prior_selected[scenario])
            restricted = [
                [event_id for event_id in sequence if event_id in previous_event_ids]
                for sequence in event_sequences
            ]
            restricted = [sequence for sequence in restricted if sequence]
            _require(
                restricted == prior_sequences[scenario],
                f"{label}: certificate path membership changed across prefixes",
            )

        experiment = _object(report.get("poi_prefix_experiment"), f"{label}.poi_prefix_experiment")
        for name, expected in (
            ("scenario", scenario),
            ("poi_count", poi_count),
            ("full_poi_count", row.get("full_poi_count")),
            ("selected_poi_event_ids", selected),
            ("online_uses_groundtruth", False),
        ):
            _require(type(experiment.get(name)) is type(expected) and experiment.get(name) == expected, f"{label}.poi_prefix_experiment.{name}: mismatch")
        _require(
            experiment.get("selected_poi_event_sequences") == event_sequences,
            f"{label}: prefix experiment path cover differs from online input",
        )
        _require(
            experiment.get("certificate_topology_policy") == "causal_path_cover",
            f"{label}: prefix experiment topology policy mismatch",
        )
        _require(
            report.get("ordered_poi_event_sequences") == event_sequences,
            f"{label}: report path cover differs from online input",
        )
        reference_path = _reported_path(
            run_dir,
            experiment.get("fixed_reference_file"),
            f"{label}.poi_prefix_experiment.fixed_reference_file",
        )
        if poi_count == 1:
            attack_events, reference_paths = _load_fixed_reference(
                reference_path, f"{label} fixed reference"
            )
            reference_files_by_scenario[scenario] = reference_path
            reference_events_by_scenario[scenario] = attack_events
            reference_paths_by_scenario[scenario] = reference_paths
            recomputed_rows_by_scenario[scenario] = []
        else:
            _require(
                reference_path == reference_files_by_scenario[scenario],
                f"{label}: fixed reference file changed across prefixes",
            )

        ledger = _object(report.get("score_ledger"), f"{label}.score_ledger")
        ledger_dir = _reported_path(run_dir, ledger.get("directory"), f"{label}.score_ledger.directory", directory=True)
        manifest_path = _reported_path(run_dir, ledger.get("manifest"), f"{label}.score_ledger.manifest")
        row_manifest = _reported_path(run_dir, row.get("score_ledger_manifest"), f"{label}.score_ledger_manifest")
        _require(manifest_path == ledger_dir / "manifest.json" and row_manifest == manifest_path, f"{label}: ledger manifest paths disagree")
        verification = verify_score_ledger(ledger_dir)
        _require(bool(verification.get("valid")), f"{label}: invalid v2 score ledger: {verification.get('validation_errors')}")
        reported_verification = _object(
            ledger.get("verification"), f"{label}.score_ledger.verification"
        )
        _require(
            reported_verification.get("valid") is True
            and not reported_verification.get("validation_errors")
            and not reported_verification.get("hash_mismatches"),
            f"{label}: report embeds a failed ledger verification",
        )
        _require(row.get("score_ledger_valid") is True, f"{label}: summary does not mark score ledger valid")
        manifest = _read_json(manifest_path, f"{label} manifest")
        for name, value in manifest.items():
            _require(
                ledger.get(name) == value,
                f"{label}: report's embedded manifest field {name!r} disagrees "
                "with manifest.json",
            )
        _require(manifest.get("schema_version") == SCHEMA_VERSION, f"{label}: score ledger is not schema v2")
        _require(manifest.get("complete") is True, f"{label}: score ledger manifest is incomplete")
        _require(manifest.get("online_uses_groundtruth") is False, f"{label}: ledger uses ground truth online")

        candidate_count = _integer(manifest.get("candidate_edge_count"), f"{label}.candidate_edge_count")
        candidate_nodes = _integer(manifest.get("candidate_node_count"), f"{label}.candidate_node_count")
        _require(candidate_count > 0, f"{label}: candidate graph must not be empty")
        _require(row.get("candidate_events") == candidate_count, f"{label}: candidate event count mismatch")
        _require(row.get("candidate_nodes") == candidate_nodes, f"{label}: candidate node count mismatch")
        _require(report.get("original_edges") == candidate_count, f"{label}: report original edge count mismatch")
        _require(report.get("original_nodes") == candidate_nodes, f"{label}: report original node count mismatch")

        requested_ratio = _number(row.get("requested_keep_ratio"), f"{label}.requested_keep_ratio")
        _require(0.0 < requested_ratio <= 1.0, f"{label}: requested keep ratio outside (0, 1]")
        _same_number(result.get("requested_keep_ratio"), requested_ratio, f"{label}.requested_keep_ratio")
        if "keep_ratio" in summary:
            _same_number(summary.get("keep_ratio"), requested_ratio, f"{label}.summary_keep_ratio")
        budget_key = format(requested_ratio, ".12g")
        _require(manifest.get("decision_budget_keys") == [budget_key], f"{label}: ledger decision budget keys mismatch")

        edges = _stored_edges(ledger_dir)
        scores, kept, reasons = _score_state(ledger_dir, budget_key)
        _require(len(edges) == candidate_count and set(edges) == set(scores), f"{label}: candidate/score edge coverage mismatch")
        event_to_edge = {edge.event_id: edge_id for edge_id, edge in edges.items()}
        unknown_pois = [event_id for event_id in selected if event_id not in event_to_edge]
        _require(not unknown_pois, f"{label}: selected POIs absent from candidate graph {unknown_pois}")
        poi_edge_ids = [event_to_edge[event_id] for event_id in selected]
        _require(set(poi_edge_ids) <= kept, f"{label}: not all selected POIs were retained")

        kept_event_ids = _list(result.get("kept_event_ids"), f"{label}.kept_event_ids")
        _require(all(isinstance(value, str) for value in kept_event_ids), f"{label}: kept_event_ids must be strings")
        _require(len(kept_event_ids) == len(set(kept_event_ids)), f"{label}: duplicate kept_event_ids")
        ledger_kept_events = {edges[edge_id].event_id for edge_id in kept}
        _require(set(kept_event_ids) == ledger_kept_events, f"{label}: result kept_event_ids differ from ledger decisions")
        _require(row.get("kept_events") == len(kept), f"{label}: summary kept event count mismatch")

        recomputed_path_metrics = _recompute_path_metrics(
            reference_paths_by_scenario[scenario],
            ledger_kept_events,
            set(selected),
        )
        reported_path_metrics = _object(
            experiment.get("path_metrics"),
            f"{label}.poi_prefix_experiment.path_metrics",
        )
        _same_recomputed_fields(
            reported_path_metrics,
            recomputed_path_metrics,
            _PATH_METRIC_FIELDS,
            f"{label}.poi_prefix_experiment.path_metrics",
        )
        _same_recomputed_fields(
            row,
            recomputed_path_metrics,
            _PATH_METRIC_FIELDS,
            f"{label}.summary",
        )
        attack_events = reference_events_by_scenario[scenario]
        recomputed_attack_recall = (
            len(ledger_kept_events & attack_events) / len(attack_events)
            if attack_events
            else None
        )
        _same_recomputed_value(
            row.get("attack_event_recall"),
            recomputed_attack_recall,
            f"{label}.summary.attack_event_recall",
        )
        paper_results = _object(
            report.get("paper_main_results"), f"{label}.paper_main_results"
        )
        _require(
            paper_results.get("available") is True,
            f"{label}.paper_main_results.available: expected true",
        )
        paper_rows = _list(
            paper_results.get("rows"), f"{label}.paper_main_results.rows"
        )
        _require(
            len(paper_rows) == 1,
            f"{label}.paper_main_results.rows: expected exactly one row",
        )
        paper_row = _object(
            paper_rows[0], f"{label}.paper_main_results.rows[0]"
        )
        _same_recomputed_value(
            paper_row.get("attack_event_recall"),
            recomputed_attack_recall,
            f"{label}.paper_main_results.rows[0].attack_event_recall",
        )
        _same_recomputed_value(
            paper_row.get("complete_path_retention"),
            recomputed_path_metrics["complete_path_retention"],
            f"{label}.paper_main_results.rows[0].complete_path_retention",
        )
        marginal_restored = (
            int(recomputed_path_metrics["retained_reference_paths"])
            - previous_retained_paths
        )
        _same_recomputed_value(
            row.get("marginal_restored_paths"),
            marginal_restored,
            f"{label}.summary.marginal_restored_paths",
        )
        previous_retained_paths = int(
            recomputed_path_metrics["retained_reference_paths"]
        )
        recomputed_rows_by_scenario[scenario].append(
            {
                "poi_count": poi_count,
                **recomputed_path_metrics,
                "causal_path_cover_certificate_valid": result.get(
                    "causal_path_cover_certificate_valid"
                ),
                "budget_feasible": result.get("budget_feasible"),
                "churn_bound_satisfied": result.get("churn_bound_satisfied"),
            }
        )

        expected_budget = max(1, math.floor(candidate_count * requested_ratio))
        budget_edges = _integer(result.get("budget_edges"), f"{label}.budget_edges")
        minimum_required = _integer(result.get("minimum_required_edges"), f"{label}.minimum_required_edges")
        _require(budget_edges == expected_budget, f"{label}: budget mismatch; expected {expected_budget}, got {budget_edges}")
        _require(
            result.get("budget_rounding_policy")
            == "floor_hard_cap_minimum_one",
            f"{label}: budget rounding policy mismatch",
        )
        _require(result.get("budget_feasible") is True, f"{label}: budget is infeasible")
        _require(row.get("budget_feasible") is True, f"{label}: summary budget is infeasible")
        _require(minimum_required <= budget_edges, f"{label}: minimum required edges exceed budget")
        _require(len(kept) <= budget_edges, f"{label}: kept edges exceed budget")
        _require(result.get("budget_overflow_edges") == 0, f"{label}: budget overflow is nonzero")
        _require(row.get("budget_overflow_edges") == 0, f"{label}: summary budget overflow is nonzero")
        _require(result.get("unused_budget_edges") == budget_edges - len(kept), f"{label}: unused budget count mismatch")
        actual_ratio = len(kept) / candidate_count
        _same_number(result.get("actual_keep_ratio"), actual_ratio, f"{label}.actual_keep_ratio")
        _same_number(row.get("actual_keep_ratio"), actual_ratio, f"{label}.summary_actual_keep_ratio")

        context = _object(manifest.get("context"), f"{label}.manifest.context")
        _require(
            context.get("online_uses_groundtruth") is False,
            f"{label}: ledger context does not attest online GT isolation",
        )
        context_pois = _list(
            context.get("poi_event_ids"), f"{label}.manifest.context.poi_event_ids"
        )
        _require(
            len(context_pois) == len(set(context_pois))
            and set(context_pois) == set(selected),
            f"{label}: ledger context POIs differ from online input",
        )
        pruning_parameters = _object(
            context.get("pruning_parameters"),
            f"{label}.manifest.context.pruning_parameters",
        )
        _require(
            pruning_parameters.get("certificate_topology_policy")
            == "causal_path_cover",
            f"{label}: ledger topology policy mismatch",
        )
        _require(
            pruning_parameters.get("budget_rounding_policy")
            == "floor_hard_cap_minimum_one",
            f"{label}: ledger budget rounding policy mismatch",
        )
        _require(
            pruning_parameters.get("ordered_poi_event_sequences")
            == event_sequences,
            f"{label}: ledger path cover differs from online input",
        )
        candidate_digest = _sha256(manifest.get("candidate_identity_sha256"), f"{label}.candidate_identity_sha256")
        _require(_sha256(context.get("candidate_graph_sha256"), f"{label}.candidate_graph_sha256") == candidate_digest, f"{label}: candidate graph digest disagrees with ledger identity digest")
        local = _object(report.get("poi_local_scoring"), f"{label}.poi_local_scoring")
        _require(local.get("policy") == "immutable_per_poi_scores_aggregated_by_noisy_or", f"{label}: local scoring policy is not immutable noisy-or")
        _require(local.get("prefix_monotonicity_guarantee") is True, f"{label}: monotonicity guarantee is not enabled")
        local_digests = _object(local.get("local_score_digests"), f"{label}.local_score_digests")
        _require(set(local_digests) == set(selected), f"{label}: local digest keys do not exactly match selected POIs")
        normalized_digests = {
            key: _sha256(value, f"{label}.local_score_digests[{key!r}]")
            for key, value in local_digests.items()
        }
        _require(context.get("local_score_digests") == normalized_digests, f"{label}: manifest/report local score digests disagree")
        context_digest = _sha256(local.get("context_digest"), f"{label}.context_digest")
        _require(_sha256(context.get("prefix_score_context_sha256"), f"{label}.prefix_score_context_sha256") == context_digest, f"{label}: prefix scoring context digests disagree")

        if poi_count == 1:
            scenario_graph_digest[scenario] = candidate_digest
            scenario_context_digest[scenario] = context_digest
        else:
            _require(candidate_digest == scenario_graph_digest[scenario], f"{label}: candidate graph digest changed across prefixes")
            _require(context_digest == scenario_context_digest[scenario], f"{label}: scoring context digest changed across prefixes")
            old_digests = prior_digests[scenario]
            rewritten = [key for key, value in old_digests.items() if normalized_digests.get(key) != value]
            _require(not rewritten, f"{label}: prior local score digests changed {rewritten}")
            _require(set(scores) == set(prior_scores[scenario]), f"{label}: score edge set changed across prefixes")
            regressions = [
                edge_id
                for edge_id, old_score in prior_scores[scenario].items()
                if scores[edge_id] + 1e-15 < old_score
            ]
            _require(not regressions, f"{label}: score monotonicity regression on edges {regressions[:5]}")
        _require(row.get("score_monotonicity_violations") == 0, f"{label}: summary records score monotonicity violations")
        _require(row.get("local_score_digest_violations") == 0, f"{label}: summary records local digest violations")

        ordered_edge_sequences = [
            [event_to_edge[event_id] for event_id in sequence]
            for sequence in event_sequences
        ]
        for sequence_index, sequence in enumerate(ordered_edge_sequences):
            keys = [
                (edges[edge_id].timestamp_ns, edges[edge_id].edge_id)
                for edge_id in sequence
            ]
            _require(
                keys == sorted(keys) and len(keys) == len(set(keys)),
                f"{label}: certificate path {sequence_index} is not strictly chronological",
            )
        expected_pairs = [
            (start_id, target_id)
            for sequence in ordered_edge_sequences
            for start_id, target_id in zip(sequence, sequence[1:])
        ]
        expected_stage_pairs = len(expected_pairs)
        candidate_timeline = sorted(
            edges.values(), key=lambda item: (item.timestamp_ns, item.edge_id)
        )
        candidate_connected_pairs = [
            pair for pair in expected_pairs
            if _strict_path_exists(
                edges, pair[0], pair[1], ordered_edges=candidate_timeline
            )
        ]
        retained_connected_pairs = [
            pair for pair in expected_pairs
            if _strict_path_exists(
                edges, pair[0], pair[1], allowed_edge_ids=kept,
                ordered_edges=candidate_timeline,
            )
        ]
        candidate_disconnected_pairs = [
            list(pair) for pair in expected_pairs
            if pair not in candidate_connected_pairs
        ]
        branch_count = len(event_sequences)
        topology = (
            "singleton" if poi_count == 1 else
            "chain" if branch_count == 1 else
            "forest"
        )
        _require(result.get("stage_pairs") == expected_stage_pairs, f"{label}: stage pair count mismatch")
        _require(row.get("stage_pairs") == expected_stage_pairs, f"{label}: summary stage pair count mismatch")
        _require(result.get("certificate_poi_edges") == poi_count, f"{label}: certificate POI count mismatch")
        _require(result.get("certificate_retained_poi_edges") == poi_count, f"{label}: certificate did not retain every POI")
        _require(
            result.get("certificate_topology") == topology,
            f"{label}: certificate topology mismatch",
        )
        _require(
            result.get("certificate_branch_count") == branch_count
            and type(result.get("certificate_branch_count")) is int,
            f"{label}: certificate branch count mismatch",
        )
        _require(
            result.get("candidate_disconnected_stage_pairs")
            == candidate_disconnected_pairs,
            f"{label}: candidate disconnected pair list mismatch",
        )
        _require(
            result.get("connected_stage_pairs") == len(candidate_connected_pairs),
            f"{label}: independently recomputed candidate connectivity mismatch",
        )
        _require(
            result.get("retained_stage_pairs") == len(retained_connected_pairs),
            f"{label}: independently recomputed retained connectivity mismatch",
        )
        for edge_id in poi_edge_ids:
            _require(
                "causal_path_cover" in reasons.get(edge_id, set()),
                f"{label}: POI edge {edge_id} lacks causal_path_cover reason",
            )
        witnesses = _list(result.get("stage_path_witnesses"), f"{label}.stage_path_witnesses")
        _require(
            not candidate_disconnected_pairs,
            f"{label}: a declared certificate path is disconnected in the candidate graph",
        )
        _require(
            len(retained_connected_pairs) == expected_stage_pairs,
            f"{label}: a declared certificate path is disconnected after pruning",
        )
        expected_status = (
            "poi_only" if topology == "singleton" else
            "valid" if topology == "chain" else
            "valid_forest"
        )
        _require(
            result.get("path_certificate_status") == expected_status,
            f"{label}: certificate status mismatch",
        )
        _require(result.get("path_certificate_valid") is True, f"{label}: path certificate is invalid")
        _require(
            result.get("causal_path_cover_certificate_valid") is True,
            f"{label}: causal path-cover certificate is invalid",
        )
        expected_strict = topology == "chain" and expected_stage_pairs > 0
        _require(
            result.get("strict_multistage_certificate_valid") is expected_strict,
            f"{label}: strict multistage certificate flag mismatch",
        )
        _require(
            len(witnesses) == len(candidate_connected_pairs),
            f"{label}: witness count mismatch",
        )
        for witness_index, (witness, pair) in enumerate(
            zip(witnesses, candidate_connected_pairs)
        ):
            _validate_witness(
                witness, pair, edges, kept, reasons,
                f"{label}.witness[{witness_index}]",
            )

        _same_fields(
            row,
            result,
            (
                "path_certificate_valid",
                "budget_rounding_policy",
                "path_certificate_status",
                "strict_multistage_certificate_valid",
                "causal_path_cover_certificate_valid",
                "certificate_topology",
                "certificate_branch_count",
                "candidate_disconnected_stage_pairs",
                "connected_stage_pairs",
                "retained_stage_pairs",
                "added_edges",
                "removed_previous_edges",
                "declared_allowed_removed_previous_edges",
                "allowed_removed_previous_edges",
                "budget_contraction_edges",
                "atomicity_churn_slack_edges",
                "churn_bound_satisfied",
                "churn_constraint_status",
                "prefix_jaccard",
                "unused_budget_edges",
                "zero_score_fill_stopped",
            ),
            label,
        )

        if poi_count == 1:
            _require(result.get("previous_candidate_edges") == 0, f"{label}: first prefix previous count must be zero")
            _require(result.get("retained_previous_edges") == 0, f"{label}: first prefix retained previous count must be zero")
            _require(result.get("added_edges") == 0 and result.get("removed_previous_edges") == 0, f"{label}: first prefix churn deltas must be zero")
            _require(result.get("prefix_jaccard") is None, f"{label}: first prefix Jaccard must be null")
            _require(result.get("churn_constraint_status") == "not_applicable", f"{label}: first prefix churn status must be not_applicable")
        else:
            previous = prior_kept[scenario]
            retained = len(previous & kept)
            removed = len(previous - kept)
            added = len(kept - previous)
            union = len(previous | kept)
            jaccard = retained / union if union else 1.0
            _require(result.get("previous_candidate_edges") == len(previous), f"{label}: previous candidate edge count mismatch")
            _require(result.get("retained_previous_edges") == retained, f"{label}: retained previous edge count mismatch")
            _require(result.get("removed_previous_edges") == removed, f"{label}: removed previous edge count mismatch")
            _require(result.get("added_edges") == added, f"{label}: added edge count mismatch")
            _same_number(result.get("prefix_jaccard"), jaccard, f"{label}.prefix_jaccard")
            declared = _integer(result.get("declared_allowed_removed_previous_edges"), f"{label}.declared_churn_allowance")
            atomic = _integer(result.get("atomicity_churn_slack_edges"), f"{label}.atomicity_churn_slack")
            _require(declared <= len(previous), f"{label}: declared churn allowance exceeds the previous prefix")
            effective = min(len(previous), declared + atomic)
            _require(result.get("allowed_removed_previous_edges") == effective, f"{label}: effective churn allowance mismatch")
            _require(removed <= effective, f"{label}: effective churn bound exceeded")
            _require(removed <= declared, f"{label}: conservative declared churn bound exceeded")
            _require(result.get("churn_bound_satisfied") is True, f"{label}: churn bound is not satisfied")
            _require(result.get("churn_constraint_status") == "satisfied", f"{label}: churn constraint status must be satisfied")
            _require(_integer(result.get("budget_contraction_edges"), f"{label}.budget_contraction_edges") == max(0, len(previous) - budget_edges), f"{label}: budget contraction count mismatch")
            if atomic > 0:
                atomic_relaxations += 1

        prior_kept[scenario] = set(kept)
        prior_scores[scenario] = dict(scores)
        prior_digests[scenario] = normalized_digests
        prior_selected[scenario] = list(selected)
        prior_sequences[scenario] = [list(sequence) for sequence in event_sequences]
        del edges, scores, kept, reasons, event_to_edge

    reported_days = [
        _object(value, f"summary.days[{index}]")
        for index, value in enumerate(_list(summary.get("days"), "summary.days"))
    ]
    recomputed_days: list[dict[str, object]] = []
    for day_index, day in enumerate(reported_days):
        scenario = _string(day.get("scenario"), f"summary.days[{day_index}].scenario")
        rows = recomputed_rows_by_scenario[scenario]
        full_poi_count = _integer(
            day.get("full_poi_count"),
            f"summary.days[{day_index}].full_poi_count",
            minimum=1,
        )
        _require(
            len(rows) == full_poi_count,
            f"summary.days[{day_index}]: recomputed prefix count mismatch",
        )
        recomputed = {
            "scenario": scenario,
            "full_poi_count": full_poi_count,
            **_recompute_day_reference_summary(
                rows, len(reference_paths_by_scenario[scenario])
            ),
        }
        _same_recomputed_fields(
            day,
            recomputed,
            _DAY_REFERENCE_FIELDS,
            f"summary.days[{day_index}]",
        )
        recomputed_days.append(recomputed)

    minimum_counts = [
        int(day["minimum_sufficient_poi_count"])
        for day in recomputed_days
        if day["minimum_sufficient_poi_count"] is not None
    ]
    minimum_fractions = [
        int(day["minimum_sufficient_poi_count"]) / int(day["full_poi_count"])
        for day in recomputed_days
        if day["minimum_sufficient_poi_count"] is not None
    ]
    maximum_retention_values = [
        float(day["maximum_complete_path_retention"])
        for day in recomputed_days
        if day["maximum_complete_path_retention"] is not None
    ]
    unselected_at_minimum: list[float] = []
    for day in recomputed_days:
        minimum = day["minimum_sufficient_poi_count"]
        if minimum is None:
            continue
        scenario = str(day["scenario"])
        selected_rows = [
            row
            for row in recomputed_rows_by_scenario[scenario]
            if row["poi_count"] == minimum
        ]
        _require(
            len(selected_rows) == 1,
            f"summary.days scenario {scenario}: minimum prefix row is missing",
        )
        value = selected_rows[0]["unselected_terminal_path_retention"]
        if value is not None:
            unselected_at_minimum.append(float(value))

    recomputed_cross_day: dict[str, int | float | None] = {
        "minimum_total_pois": (
            sum(minimum_counts)
            if len(minimum_counts) == len(recomputed_days)
            else None
        ),
        "mean_minimum_poi_fraction": (
            fmean(minimum_fractions)
            if len(minimum_fractions) == len(recomputed_days)
            else None
        ),
        "macro_maximum_complete_path_retention": (
            fmean(maximum_retention_values) if maximum_retention_values else None
        ),
        "macro_unselected_path_retention_at_minimum": (
            fmean(unselected_at_minimum) if unselected_at_minimum else None
        ),
        "unselected_path_macro_contributing_days": len(unselected_at_minimum),
    }
    cross = _object(summary.get("cross_day"), "summary.cross_day")
    _same_recomputed_fields(
        cross,
        recomputed_cross_day,
        _CROSS_DAY_REFERENCE_FIELDS,
        "summary.cross_day",
    )

    consecutive_jaccards = [
        _number(row["prefix_jaccard"], "summary row prefix_jaccard")
        for _, poi_count, row in ordered_rows
        if poi_count > 1
    ]
    expected_minimum_jaccard = min(consecutive_jaccards, default=None)
    if expected_minimum_jaccard is None:
        _require(
            cross.get("minimum_consecutive_prefix_jaccard") is None,
            "summary.cross_day.minimum_consecutive_prefix_jaccard must be null",
        )
    else:
        _same_number(
            cross.get("minimum_consecutive_prefix_jaccard"),
            expected_minimum_jaccard,
            "summary.cross_day.minimum_consecutive_prefix_jaccard",
        )

    return {
        "atomic_relaxations": atomic_relaxations,
        "prefixes": len(ordered_rows),
        "scenarios": len({scenario for scenario, _, _ in ordered_rows}),
        "v2_ledgers": len(ordered_rows),
        "valid": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Deeply validate a completed PS-RDP POI-prefix sweep, including v2 "
            "score ledgers, budgets, churn, monotonicity, digests, and witnesses."
        )
    )
    parser.add_argument("run_dir", help="completed sweep output directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = validate(args.run_dir)
    except Exception as exc:
        print(json.dumps({"error": str(exc), "valid": False}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
