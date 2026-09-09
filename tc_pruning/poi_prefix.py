from __future__ import annotations

import csv
import gc
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Callable, Iterable, Sequence

from .config import load_experiment_config
from .evaluation import AttackAnnotations
from .evaluation import run_experiment
from .frequency_snapshot import default_snapshot_path
from .models import StoredEdge
from .rdp_guard import PrefixScoreAccumulator
from .store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class POIPrefixScenario:
    code: str
    poi_file: Path
    base_groundtruth_file: Path
    window_start_ns: int
    window_end_ns: int
    window_extension_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("scenario code must not be empty")
        if self.window_end_ns < self.window_start_ns:
            raise ValueError("window_end_ns must be greater than or equal to window_start_ns")


@dataclass(frozen=True, slots=True)
class POIPrefixSweepSpec:
    keep_ratio: float
    scenarios: tuple[POIPrefixScenario, ...]
    use_frequency_cache: bool = True
    use_frequency_snapshot: bool = True

    def __post_init__(self) -> None:
        if not 0.0 < self.keep_ratio <= 1.0:
            raise ValueError("keep_ratio must be in (0, 1]")
        if not self.scenarios:
            raise ValueError("sweep specification requires at least one scenario")
        codes = [scenario.code for scenario in self.scenarios]
        if len(set(codes)) != len(codes):
            raise ValueError("scenario codes must be unique")


def load_poi_prefix_spec(path: str | Path) -> POIPrefixSweepSpec:
    source = Path(path).resolve()
    raw = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError("POI prefix specification must be a JSON object")
    allowed = {
        "keep_ratio", "scenarios", "use_frequency_cache",
        "use_frequency_snapshot",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"unknown sweep fields: {', '.join(unknown)}")
    raw_scenarios = raw.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise ValueError("scenarios must be a list")
    scenarios = []
    scenario_allowed = {
        "code", "poi_file", "base_groundtruth_file", "window_start_ns",
        "window_end_ns", "window_extension_reason",
    }
    for index, item in enumerate(raw_scenarios):
        if not isinstance(item, dict):
            raise ValueError(f"scenarios[{index}] must be an object")
        item_unknown = sorted(set(item) - scenario_allowed)
        if item_unknown:
            raise ValueError(
                f"unknown scenarios[{index}] fields: {', '.join(item_unknown)}"
            )
        missing = sorted(
            {
                "code", "poi_file", "base_groundtruth_file",
                "window_start_ns", "window_end_ns",
            } - set(item)
        )
        if missing:
            raise ValueError(
                f"missing scenarios[{index}] fields: {', '.join(missing)}"
            )

        def relative_path(value: object) -> Path:
            candidate = Path(str(value))
            if not candidate.is_absolute():
                candidate = source.parent / candidate
            return candidate.resolve()

        scenarios.append(
            POIPrefixScenario(
                code=str(item["code"]),
                poi_file=relative_path(item["poi_file"]),
                base_groundtruth_file=relative_path(item["base_groundtruth_file"]),
                window_start_ns=int(item["window_start_ns"]),
                window_end_ns=int(item["window_end_ns"]),
                window_extension_reason=(
                    str(item["window_extension_reason"])
                    if item.get("window_extension_reason") else None
                ),
            )
        )

    def boolean_field(name: str, default: bool) -> bool:
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean")
        return value

    return POIPrefixSweepSpec(
        keep_ratio=float(raw.get("keep_ratio", 0.2)),
        scenarios=tuple(scenarios),
        use_frequency_cache=boolean_field("use_frequency_cache", True),
        use_frequency_snapshot=boolean_field("use_frequency_snapshot", True),
    )


def _load_poi_declaration(
    path: Path,
) -> tuple[list[str], list[tuple[str, tuple[str, ...]]], bool]:
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError(f"POI manifest must be a JSON object: {path}")
    event_ids = [str(item) for item in raw.get("event_ids", []) if str(item)]
    if not event_ids:
        raise ValueError(f"POI file contains no event_ids: {path}")
    if len(set(event_ids)) != len(event_ids):
        raise ValueError(f"POI file contains duplicate event IDs: {path}")
    raw_paths = raw.get("certificate_paths")
    if raw_paths is None:
        return event_ids, [("timeline", tuple(event_ids))], False
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ValueError("certificate_paths must be a non-empty list")
    paths: list[tuple[str, tuple[str, ...]]] = []
    path_ids: set[str] = set()
    covered: list[str] = []
    global_position = {event_id: index for index, event_id in enumerate(event_ids)}
    for index, item in enumerate(raw_paths):
        if not isinstance(item, dict):
            raise ValueError(f"certificate_paths[{index}] must be an object")
        unknown = sorted(set(item) - {"path_id", "event_ids"})
        if unknown:
            raise ValueError(
                f"unknown certificate_paths[{index}] fields: {', '.join(unknown)}"
            )
        path_id = str(item.get("path_id") or "").strip()
        if not path_id or re.fullmatch(r"[A-Za-z0-9._-]+", path_id) is None:
            raise ValueError(
                f"certificate_paths[{index}].path_id must use letters, digits, ._-"
            )
        if path_id in path_ids:
            raise ValueError(f"duplicate certificate path_id: {path_id}")
        values = item.get("event_ids")
        if not isinstance(values, list) or not values:
            raise ValueError(
                f"certificate_paths[{index}].event_ids must be a non-empty list"
            )
        sequence = tuple(str(value) for value in values if str(value))
        if len(sequence) != len(values):
            raise ValueError(
                f"certificate_paths[{index}].event_ids contains an empty ID"
            )
        if len(sequence) != len(set(sequence)):
            raise ValueError(
                "each POI event must occur exactly once in certificate_paths"
            )
        unknown_events = sorted(set(sequence) - set(event_ids))
        if unknown_events:
            raise ValueError(
                "certificate_paths must partition event_ids; unknown events: "
                f"{unknown_events}"
            )
        positions = [global_position[event_id] for event_id in sequence]
        if positions != sorted(positions):
            raise ValueError(
                f"certificate path {path_id!r} must follow the declared POI timeline"
            )
        path_ids.add(path_id)
        covered.extend(sequence)
        paths.append((path_id, sequence))
    if len(covered) != len(set(covered)):
        raise ValueError(
            "each POI event must occur exactly once in certificate_paths"
        )
    if set(covered) != set(event_ids):
        missing = sorted(set(event_ids) - set(covered))
        raise ValueError(
            "certificate_paths must partition event_ids; missing events: "
            f"{missing}"
        )
    return event_ids, paths, True


def _load_declared_event_ids(path: Path) -> list[str]:
    return _load_poi_declaration(path)[0]


def resolve_poi_timeline(
    store: ProvenanceStore, scenario: POIPrefixScenario
) -> list[StoredEdge]:
    """Resolve and strictly validate one report-declared POI timeline."""
    event_ids = _load_declared_event_ids(scenario.poi_file)
    resolved: list[StoredEdge] = []
    missing: list[str] = []
    outside: list[str] = []
    for event_id in event_ids:
        edge = store.get_edge_by_event_id(event_id)
        if edge is None:
            missing.append(event_id)
        elif not scenario.window_start_ns <= edge.timestamp_ns <= scenario.window_end_ns:
            outside.append(event_id)
        else:
            resolved.append(edge)
    if missing:
        raise ValueError(f"POI events missing from database: {missing}")
    if outside:
        raise ValueError(f"POI events outside fixed investigation window: {outside}")
    chronology = [(edge.timestamp_ns, edge.event_id) for edge in resolved]
    if chronology != sorted(chronology):
        raise ValueError("POI events must be declared in chronological order")
    return resolved


def build_prefix_annotations(
    scenario: POIPrefixScenario,
    timeline: Sequence[StoredEdge],
    poi_count: int,
) -> AttackAnnotations:
    if not 1 <= poi_count <= len(timeline):
        raise ValueError("poi_count must select a non-empty prefix of the timeline")
    declared_ids, declared_paths, explicit_path_cover = _load_poi_declaration(
        scenario.poi_file
    )
    timeline_ids = [edge.event_id for edge in timeline]
    if declared_ids != timeline_ids:
        raise ValueError("resolved POI timeline does not match its manifest")
    event_ids = tuple(timeline_ids[:poi_count])
    selected = set(event_ids)
    prefix_paths = [
        (path_id, tuple(event_id for event_id in sequence if event_id in selected))
        for path_id, sequence in declared_paths
    ]
    prefix_paths = [item for item in prefix_paths if item[1]]
    if not prefix_paths:
        raise RuntimeError("POI prefix produced an empty certificate path cover")
    if explicit_path_cover:
        group_ids = [
            f"ubc-{scenario.code}-prefix-{poi_count}-{path_id}"
            for path_id, _ in prefix_paths
        ]
    else:
        group_ids = [f"ubc-{scenario.code}-prefix-{poi_count}"]
    return AttackAnnotations(
        name=f"CADETS E3 UBC-{scenario.code} report POI prefix {poi_count}",
        seed_uuids=set(),
        seed_event_ids=set(event_ids),
        seed_event_groups=[set(sequence) for _, sequence in prefix_paths],
        seed_event_group_ids=group_ids,
        seed_event_sequences=[sequence for _, sequence in prefix_paths],
        investigation_windows={
            group_id: (scenario.window_start_ns, scenario.window_end_ns)
            for group_id in group_ids
        },
        attack_event_ids=set(),
        attack_node_uuids=set(),
        metadata={
            "scenario": scenario.code,
            "poi_count": poi_count,
            "full_poi_count": len(timeline),
            "poi_order_rule": "DARPA_report_timeline_then_database_timestamp_validation",
            "certificate_topology_policy": "causal_path_cover",
            "certificate_topology_source": (
                "report_declared"
                if explicit_path_cover else "implicit_strict_timeline_chain"
            ),
            "certificate_path_ids": [path_id for path_id, _ in prefix_paths],
            "window_extension_reason": scenario.window_extension_reason,
        },
    )


def _causal_endpoints(edge: StoredEdge) -> tuple[str, str]:
    if edge.relation.upper() == "EVENT_EXECUTE":
        return edge.dst, edge.src
    return edge.src, edge.dst


def build_report_reference(
    store: ProvenanceStore,
    scenario: POIPrefixScenario,
    base: AttackAnnotations,
    timeline: Sequence[StoredEdge],
) -> AttackAnnotations:
    """Build a fixed, report-POI-anchored reference for every prefix run."""
    core_edges = [
        edge
        for event_id in base.attack_event_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    core_edges.sort(key=lambda edge: (edge.timestamp_ns, edge.edge_id))
    incoming: dict[str, list[StoredEdge]] = {}
    for edge in core_edges:
        _, target = _causal_endpoints(edge)
        incoming.setdefault(target, []).append(edge)
    for edges in incoming.values():
        edges.sort(key=lambda edge: (edge.timestamp_ns, edge.edge_id), reverse=True)

    paths: list[tuple[str, ...]] = []
    path_boundaries: list[dict[str, object]] = []
    for poi in timeline:
        terminal_source, _ = _causal_endpoints(poi)
        terminal_order = (poi.timestamp_ns, poi.edge_id)
        queue = deque([(terminal_source, terminal_order, tuple())])
        visited = {(terminal_source, terminal_order)}
        resolved_path: tuple[str, ...] | None = None
        boundary_node: str | None = None
        while queue:
            node, upper_order, reverse_event_ids = queue.popleft()
            choices = [
                edge
                for edge in incoming.get(node, [])
                if edge.event_id != poi.event_id
                and (edge.timestamp_ns, edge.edge_id) < upper_order
            ]
            if not choices:
                resolved_path = (*reversed(reverse_event_ids), poi.event_id)
                boundary_node = node
                break
            for predecessor in choices:
                predecessor_source, _ = _causal_endpoints(predecessor)
                predecessor_order = (
                    predecessor.timestamp_ns, predecessor.edge_id
                )
                state = (predecessor_source, predecessor_order)
                if state in visited:
                    continue
                visited.add(state)
                queue.append(
                    (
                        predecessor_source,
                        predecessor_order,
                        (*reverse_event_ids, predecessor.event_id),
                    )
                )
        if resolved_path is None or boundary_node is None:
            raise RuntimeError(
                f"could not resolve temporal core entry for POI {poi.event_id}"
            )
        resolved_edges = [
            poi if event_id == poi.event_id
            else store.get_edge_by_event_id(event_id)
            for event_id in resolved_path
        ]
        if any(edge is None for edge in resolved_edges):
            raise RuntimeError(f"reference path for {poi.event_id} has a missing event")
        for previous, following in zip(resolved_edges, resolved_edges[1:]):
            assert previous is not None and following is not None
            _, previous_target = _causal_endpoints(previous)
            following_source, _ = _causal_endpoints(following)
            if (
                previous_target != following_source
                or (previous.timestamp_ns, previous.edge_id)
                >= (following.timestamp_ns, following.edge_id)
            ):
                raise RuntimeError(
                    f"reference path for {poi.event_id} is not time-respecting causal"
                )
        paths.append(resolved_path)
        path_boundaries.append(
            {
                "terminal_poi_event_id": poi.event_id,
                "boundary_kind": "temporal_core_entry",
                "entry_node_uuid": boundary_node,
                "core_event_count": len(resolved_path) - 1,
            }
        )

    terminal_ids = [edge.event_id for edge in timeline]
    attack_events = set(base.attack_event_ids) | set(terminal_ids)
    attack_nodes = set(base.attack_node_uuids)
    for edge in timeline:
        attack_nodes.update((edge.src, edge.dst))
    base_metadata_keys = {
        "groundtruth_source",
        "groundtruth_source_sha256",
        "groundtruth_family",
        "groundtruth_source_semantics",
        "label_scope",
        "timezone",
        "attack_window_start",
        "attack_window_end",
        "attack_window_start_ns",
        "attack_window_end_ns",
        "groundtruth_uuid_count",
        "matched_attack_node_count",
        "derived_attack_event_count",
        "attack_event_rule",
    }
    poi_document = json.loads(
        scenario.poi_file.read_text(encoding="utf-8-sig")
    )
    poi_metadata = poi_document.get("metadata") or {}
    return AttackAnnotations(
        name=f"CADETS E3 UBC-{scenario.code} fixed report-POI reference",
        seed_uuids=set(),
        seed_event_ids=set(),
        attack_event_ids=attack_events,
        attack_node_uuids=attack_nodes,
        attack_paths=paths,
        metadata={
            **{
                key: value
                for key, value in base.metadata.items()
                if key in base_metadata_keys
            },
            "scenario": scenario.code,
            "reference_policy": "fixed_full_report_poi_pool_for_all_prefixes",
            "path_quality": (
                "report_poi_anchored_paths_derived_within_manually_reviewed_ubc_core"
            ),
            "terminal_poi_event_ids": terminal_ids,
            "path_boundaries": path_boundaries,
            "path_entry_rule": (
                "breadth_first_shortest causal predecessor chain to a node with "
                "no earlier UBC-core incoming event"
            ),
            "path_validation_rule": (
                "adjacent causal endpoints match and event order strictly increases"
            ),
            "poi_manifest_file": str(scenario.poi_file.resolve()),
            "poi_manifest_sha256": hashlib.sha256(
                scenario.poi_file.read_bytes()
            ).hexdigest(),
            "poi_source": poi_metadata.get("source"),
            "poi_policy": poi_metadata.get("policy"),
            "poi_selection_rule": poi_metadata.get("selection_rule"),
            "poi_semantics": poi_metadata.get("poi_semantics"),
            "window_start_ns": scenario.window_start_ns,
            "window_end_ns": scenario.window_end_ns,
            "window_extension_reason": scenario.window_extension_reason,
            "online_uses_groundtruth": False,
        },
    )


def compute_prefix_path_metrics(
    reference_paths: Iterable[Sequence[str]],
    kept_event_ids: set[str],
    selected_poi_event_ids: set[str],
) -> dict[str, int | float | None]:
    paths = [tuple(path) for path in reference_paths]
    retained = [path for path in paths if set(path) <= kept_event_ids]
    selected = [path for path in paths if path[-1] in selected_poi_event_ids]
    unselected = [path for path in paths if path[-1] not in selected_poi_event_ids]
    retained_selected = [path for path in selected if set(path) <= kept_event_ids]
    retained_unselected = [path for path in unselected if set(path) <= kept_event_ids]

    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "reference_paths": len(paths),
        "retained_reference_paths": len(retained),
        "complete_path_retention": ratio(len(retained), len(paths)),
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


def select_minimum_sufficient(
    rows: Sequence[dict], *, total_paths: int
) -> dict[str, int | float | bool | None]:
    maximum_observed = max(
        (int(row["retained_reference_paths"]) for row in rows), default=0
    )
    def legal_operating_point(row: dict) -> bool:
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
            and bool(row.get("budget_feasible"))
            and bool(row.get("churn_bound_satisfied", True))
        )

    legal = [row for row in rows if legal_operating_point(row)]
    maximum = max(
        (int(row["retained_reference_paths"]) for row in legal), default=0
    )
    eligible = [
        row
        for row in legal
        if int(row["retained_reference_paths"]) == maximum
    ]
    earliest_legal_maximum = min(
        (int(row["poi_count"]) for row in eligible), default=None
    )
    legal_full = [
        row for row in legal
        if int(row["retained_reference_paths"]) == total_paths
    ]
    observed_full = [
        row for row in rows
        if int(row["retained_reference_paths"]) == total_paths
    ]
    minimum_legal_full = min(
        (int(row["poi_count"]) for row in legal_full), default=None
    )
    minimum_observed_full = min(
        (int(row["poi_count"]) for row in observed_full), default=None
    )
    return {
        # In schema v3, "sufficient" means sufficient for full restoration.
        "minimum_sufficient_poi_count": minimum_legal_full,
        "earliest_legal_poi_count_at_max_path_retention": (
            earliest_legal_maximum
        ),
        "minimum_legal_poi_count_for_full_path_retention": minimum_legal_full,
        "minimum_observed_poi_count_for_full_path_retention": (
            minimum_observed_full
        ),
        "maximum_retained_paths": maximum,
        "maximum_observed_retained_paths": maximum_observed,
        "total_reference_paths": total_paths,
        "maximum_complete_path_retention": (
            maximum / total_paths if total_paths else None
        ),
        "fully_restored": maximum == total_paths,
    }


def _annotations_document(annotations: AttackAnnotations) -> dict:
    groups = []
    for index, sequence in enumerate(annotations.seed_event_sequences):
        group_id = (
            annotations.seed_event_group_ids[index]
            if index < len(annotations.seed_event_group_ids)
            else f"group-{index + 1}"
        )
        group: dict[str, object] = {
            "group_id": group_id,
            "seed_event_ids": list(sequence),
        }
        if group_id in annotations.investigation_windows:
            start, end = annotations.investigation_windows[group_id]
            group["window_start_ns"] = start
            group["window_end_ns"] = end
        groups.append(group)
    return {
        "name": annotations.name,
        "seed_uuids": sorted(annotations.seed_uuids),
        "seed_event_ids": sorted(annotations.seed_event_ids),
        "seed_event_groups": groups,
        "attack_event_ids": sorted(annotations.attack_event_ids),
        "attack_node_uuids": sorted(annotations.attack_node_uuids),
        "attack_paths": [list(path) for path in annotations.attack_paths],
        "metadata": annotations.metadata,
    }


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary.replace(path)


def _report_for_json(report: dict) -> dict:
    """Return a shallow persistence copy without private live runtime state."""
    return {key: value for key, value in report.items() if not key.startswith("_")}


def require_complete_prefix_report(
    report: dict, *, scenario: str, poi_count: int
) -> None:
    if not report.get("incomplete") and report.get("results"):
        churn_failures = [
            result
            for result in report["results"]
            if result.get("churn_constraint_status") == "infeasible"
            or result.get("churn_bound_satisfied") is False
        ]
        if churn_failures:
            raise RuntimeError(
                f"UBC-{scenario} prefix {poi_count} experiment is incomplete: "
                "prefix churn constraint is infeasible"
            )
        certificate_failures = [
            result
            for result in report["results"]
            if "causal_path_cover_certificate_valid" in result
            and result["causal_path_cover_certificate_valid"] is not True
        ]
        if certificate_failures:
            statuses = sorted({
                str(result.get("path_certificate_status"))
                for result in certificate_failures
            })
            raise RuntimeError(
                f"UBC-{scenario} prefix {poi_count} experiment is incomplete: "
                "causal path-cover certificate is invalid "
                f"({', '.join(statuses)})"
            )
        return
    reason = report.get("incomplete_reason")
    candidate = report.get("candidate_construction")
    if not reason and isinstance(candidate, dict):
        reason = (
            candidate.get("incomplete_reason")
            or candidate.get("termination_reason")
            or candidate.get("truncation_reason")
        )
    raise RuntimeError(
        f"UBC-{scenario} prefix {poi_count} experiment is incomplete: "
        f"{reason or 'no primary pruning result was produced'}"
    )


def _run_one_prefix(
    store: ProvenanceStore,
    annotations: AttackAnnotations,
    reference: AttackAnnotations | Callable[[], AttackAnnotations],
    *,
    keep_ratio: float,
    experiment_config,
    use_frequency_cache: bool,
    use_frequency_snapshot: bool,
    progress_callback: Callable[[dict], None] | None,
    score_ledger_dir: Path | None = None,
    previous_kept_event_ids: set[str] | None = None,
    prefix_score_accumulator: PrefixScoreAccumulator | None = None,
) -> dict:
    return run_experiment(
        store,
        annotations,
        keep_ratios=(keep_ratio,),
        rarity_weight=experiment_config.rarity_weight,
        damping=experiment_config.damping,
        diffusion_mode=experiment_config.diffusion_mode,
        path_weight=experiment_config.path_weight,
        impact_weight=experiment_config.impact_weight,
        behavior_weight=experiment_config.behavior_weight,
        path_decay=experiment_config.path_decay,
        pruning_mode=experiment_config.pruning_mode,
        fusion_mode=experiment_config.fusion_mode,
        score_mass_target=experiment_config.score_mass_target,
        protect_alert_edges=experiment_config.protect_alert_edges,
        groundtruth_annotations=reference,
        pruning_scope=experiment_config.pruning_scope,
        causal_search_config=experiment_config.causal_search,
        merge_threshold_seconds=experiment_config.merge_threshold_seconds,
        data_flow_alpha=experiment_config.data_flow_alpha,
        kmeans_restarts=experiment_config.kmeans_restarts,
        depimpact_random_seed=experiment_config.depimpact_random_seed,
        behavior_min_cluster_size=experiment_config.behavior_min_cluster_size,
        behavior_fallback_gap_seconds=(
            experiment_config.behavior_fallback_gap_seconds
        ),
        embedding_dimensions=experiment_config.embedding_dimensions,
        minimum_token_frequency=experiment_config.minimum_token_frequency,
        connectivity_protection=True,
        use_frequency_cache=use_frequency_cache,
        use_frequency_snapshot=use_frequency_snapshot,
        progress_callback=progress_callback,
        include_method_comparison=False,
        poi_aggregation=experiment_config.poi_aggregation,
        previous_kept_event_ids=previous_kept_event_ids,
        churn_slack_ratio=experiment_config.churn_slack_ratio,
        positive_score_only=experiment_config.positive_score_only,
        certificate_topology_policy=(
            experiment_config.certificate_topology_policy
        ),
        score_ledger_dir=(
            score_ledger_dir if experiment_config.score_ledger_enabled else None
        ),
        high_score_threshold=experiment_config.high_score_threshold,
        high_score_quantile=experiment_config.high_score_quantile,
        prefix_score_accumulator=prefix_score_accumulator,
        include_internal_state=True,
    )


def _summary_markdown(summary: dict) -> str:
    lines = [
        "# CADETS E3 POI prefix sweep",
        "",
        (
            f"Fixed raw-event keep ratio: "
            f"{float(summary['keep_ratio']):.1%}."
        ),
        "",
        "| Day | k | Paths | Unseeded paths | Actual keep | Certificate | Jaccard |",
        "|---|---:|---:|---:|---:|:---:|---:|",
    ]
    for row in summary["rows"]:
        unseeded = row["unselected_terminal_path_retention"]
        lines.append(
            "| UBC-{scenario} | {poi_count} | {retained_reference_paths}/"
            "{reference_paths} | {unseeded} | {actual:.2%} | {certificate} | "
            "{jaccard} |".format(
                **row,
                unseeded=("—" if unseeded is None else f"{unseeded:.2%}"),
                actual=float(row["actual_keep_ratio"]),
                certificate=row["path_certificate_status"],
                jaccard=(
                    "—" if row["prefix_jaccard"] is None
                    else f"{float(row['prefix_jaccard']):.3f}"
                ),
            )
        )
    lines.extend(["", "## Minimum sufficient POIs", ""])
    for day in summary["days"]:
        lines.append(
            f"- UBC-{day['scenario']}: k*="
            f"{day['minimum_sufficient_poi_count']}; restored "
            f"{day['maximum_retained_paths']}/{day['total_reference_paths']} paths."
        )
    return "\n".join(lines) + "\n"


def _write_summary_csv(path: Path, rows: Sequence[dict]) -> None:
    columns = [
        "scenario", "poi_count", "full_poi_count", "candidate_events",
        "candidate_nodes", "kept_events", "requested_keep_ratio",
        "actual_keep_ratio", "event_compression_ratio", "attack_event_recall",
        "reference_paths", "retained_reference_paths",
        "complete_path_retention", "selected_terminal_paths",
        "retained_selected_terminal_paths", "selected_terminal_path_retention",
        "unselected_terminal_paths", "retained_unselected_terminal_paths",
        "unselected_terminal_path_retention", "marginal_restored_paths",
        "path_certificate_valid", "budget_feasible", "score_mass_retained",
        "budget_rounding_policy",
        "path_certificate_status", "strict_multistage_certificate_valid",
        "causal_path_cover_certificate_valid", "certificate_topology",
        "certificate_branch_count", "candidate_disconnected_stage_pairs",
        "stage_pairs", "connected_stage_pairs", "retained_stage_pairs",
        "prefix_jaccard", "added_edges", "removed_previous_edges",
        "declared_allowed_removed_previous_edges",
        "allowed_removed_previous_edges", "churn_bound_satisfied",
        "budget_contraction_edges", "atomicity_churn_slack_edges",
        "churn_constraint_status",
        "score_monotonicity_violations", "local_score_digest_violations",
        "unused_budget_edges", "zero_score_fill_stopped",
        "score_ledger_valid",
        "elapsed_seconds", "result_file",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


TABLE8_METHODS = (
    "temporal_only", "temporal_data", "fixed_projection",
    "uniform_random", "depimpact",
)


def _write_dict_rows(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(rows[0]) if rows else []
    temporary = path.parent / f".{path.name}.tmp"
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        if columns:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    temporary.replace(path)


def _write_depimpact_paper_tables(destination: Path, rows: Sequence[dict]) -> None:
    runtime_rows = [
        {
            "scenario": row["scenario"],
            "poi_count": row["poi_count"],
            "attack_causality_analysis_s": row["table7_attack_causality_s"],
            "edge_merge_s": row["table7_edge_merge_s"],
            "depimpact_weight_s": row["table7_depimpact_weight_s"],
            "fixed_projection_weight_s": row["table7_fixed_projection_weight_s"],
            "depimpact_propagation_s": row["table7_depimpact_propagation_s"],
            "fixed_projection_propagation_s": row["table7_fixed_projection_propagation_s"],
            "nodoze_s": row["table7_nodoze_s"],
        }
        for row in rows
    ]
    rank_rows = [
        {
            "scenario": row["scenario"],
            "poi_count": row["poi_count"],
            "candidate_entries": row["table8_candidate_entries"],
            "attack_entries": row["table8_attack_entries"],
            "covered_attack_entries": row["table8_covered_attack_entries"],
            "attack_entry_coverage": row["table8_attack_entry_coverage"],
            **{
                f"{method}_average_rank": row[f"table8_{method}_average_rank"]
                for method in TABLE8_METHODS
            },
        }
        for row in rows
    ]
    _write_dict_rows(destination / "table7-runtime.csv", runtime_rows)
    _write_dict_rows(destination / "table8-entry-ranks.csv", rank_rows)
    runtime_lines = [
        "# DEPIMPACT-style Table 7: runtime (seconds)", "",
        "| Day | k | Causality | Merge | DEP weight | Fixed weight | DEP propagation | Fixed propagation | NoDoze |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in runtime_rows:
        runtime_lines.append(
            "| UBC-{scenario} | {poi_count} | {attack_causality_analysis_s:.6f} | "
            "{edge_merge_s:.6f} | {depimpact_weight_s:.6f} | "
            "{fixed_projection_weight_s:.6f} | {depimpact_propagation_s:.6f} | "
            "{fixed_projection_propagation_s:.6f} | {nodoze_s:.6f} |".format(**row)
        )
    rank_lines = [
        "# DEPIMPACT-style Table 8: average attack-entry rank", "",
        "| Day | k | Entry coverage | Temp | Temp+Data | Fixed | Random | DEPIMPACT |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rank_rows:
        coverage = row["attack_entry_coverage"]
        values = {
            method: ("—" if row[f"{method}_average_rank"] is None else f"{row[f'{method}_average_rank']:.3f}")
            for method in TABLE8_METHODS
        }
        rank_lines.append(
            f"| UBC-{row['scenario']} | {row['poi_count']} | "
            f"{row['covered_attack_entries']}/{row['attack_entries']} "
            f"({'—' if coverage is None else f'{coverage:.2%}'}) | "
            f"{values['temporal_only']} | {values['temporal_data']} | "
            f"{values['fixed_projection']} | {values['uniform_random']} | "
            f"{values['depimpact']} |"
        )
    (destination / "table7-runtime.md").write_text(
        "\n".join(runtime_lines) + "\n", encoding="utf-8"
    )
    (destination / "table8-entry-ranks.md").write_text(
        "\n".join(rank_lines) + "\n", encoding="utf-8"
    )


def run_poi_prefix_sweep(
    database_path: str | Path,
    spec_path: str | Path,
    config_path: str | Path,
    output_dir: str | Path,
    *,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    """Run all report-ordered POI prefixes and persist auditable summaries."""
    spec = load_poi_prefix_spec(spec_path)
    experiment_config = load_experiment_config(config_path)
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    progress_path = destination / "progress.json"

    def progress(event: dict) -> None:
        _write_json(progress_path, {"incomplete": True, **event})
        if progress_callback is not None:
            progress_callback(event)

    rows: list[dict] = []
    day_summaries: list[dict] = []
    with ProvenanceStore(database_path) as store:
        progress({"stage": "preflight_started", "scenario_count": len(spec.scenarios)})
        prepared_scenarios = []
        for scenario in spec.scenarios:
            timeline = resolve_poi_timeline(store, scenario)
            base = AttackAnnotations.load(
                scenario.base_groundtruth_file, require_seeds=False
            )
            if spec.use_frequency_snapshot:
                first_day = (
                    min(edge.timestamp_ns for edge in timeline)
                    // 86_400_000_000_000
                )
                snapshot_path = default_snapshot_path(store.path, first_day)
                if not snapshot_path.is_file():
                    raise RuntimeError(
                        f"missing precomputed frequency snapshot: {snapshot_path}"
                    )
            prepared_scenarios.append((scenario, timeline, base))
        progress({
            "stage": "preflight_complete",
            "scenario_count": len(prepared_scenarios),
            "expected_prefix_runs": sum(
                len(timeline) for _, timeline, _ in prepared_scenarios
            ),
        })
        for scenario, timeline, base in prepared_scenarios:
            scenario_dir = destination / f"scenario-{scenario.code}"
            fixed_reference_path = scenario_dir / "fixed-reference.json"
            reference_cache: list[AttackAnnotations] = []

            def reference_provider(
                scenario_value=scenario,
                timeline_value=timeline,
                base_value=base,
            ) -> AttackAnnotations:
                if not reference_cache:
                    reference_cache.append(
                        build_report_reference(
                            store,
                            scenario_value,
                            base_value,
                            timeline_value,
                        )
                    )
                return reference_cache[0]

            prior_restored = 0
            prior_kept_event_ids: set[str] | None = None
            prior_edge_scores: dict[int, float] | None = None
            prior_local_score_digests: dict[str, str] = {}
            prefix_score_accumulator: PrefixScoreAccumulator | None = None
            scenario_rows: list[dict] = []
            for poi_count in range(1, len(timeline) + 1):
                prefix = build_prefix_annotations(scenario, timeline, poi_count)
                prefix_path = scenario_dir / f"poi-prefix-{poi_count}-input.json"
                result_path = scenario_dir / f"poi-prefix-{poi_count}.json"
                _write_json(prefix_path, _annotations_document(prefix))
                progress(
                    {
                        "stage": "prefix_started",
                        "scenario": scenario.code,
                        "poi_count": poi_count,
                        "full_poi_count": len(timeline),
                    }
                )

                def nested_progress(event: dict) -> None:
                    progress(
                        {
                            **event,
                            "scenario": scenario.code,
                            "poi_count": poi_count,
                            "full_poi_count": len(timeline),
                        }
                    )

                report = _run_one_prefix(
                    store,
                    prefix,
                    reference_provider,
                    keep_ratio=spec.keep_ratio,
                    experiment_config=experiment_config,
                    use_frequency_cache=spec.use_frequency_cache,
                    use_frequency_snapshot=spec.use_frequency_snapshot,
                    progress_callback=nested_progress,
                    score_ledger_dir=(
                        scenario_dir / f"poi-prefix-{poi_count}-ledger"
                    ),
                    previous_kept_event_ids=prior_kept_event_ids,
                    prefix_score_accumulator=prefix_score_accumulator,
                )
                try:
                    require_complete_prefix_report(
                        report, scenario=scenario.code, poi_count=poi_count
                    )
                except RuntimeError as exc:
                    _write_json(
                        scenario_dir / f"poi-prefix-{poi_count}.incomplete.json",
                        _report_for_json(report),
                    )
                    progress(
                        {
                            "stage": "prefix_failed",
                            "scenario": scenario.code,
                            "poi_count": poi_count,
                            "full_poi_count": len(timeline),
                            "reason": str(exc),
                        }
                    )
                    raise
                online_state = report.pop("_online_state")
                reference = reference_provider()
                if poi_count == 1:
                    _write_json(
                        fixed_reference_path,
                        _annotations_document(reference),
                    )
                current_edge_scores = online_state["edge_scores"]
                current_local_digests = report["poi_local_scoring"][
                    "local_score_digests"
                ]
                score_monotonicity_violations = (
                    sum(
                        current_edge_scores.get(edge_id, 0.0) + 1e-15 < score
                        for edge_id, score in prior_edge_scores.items()
                    )
                    if (
                        experiment_config.poi_aggregation == "noisy_or"
                        and prior_edge_scores is not None
                    ) else 0
                )
                local_score_digest_violations = (
                    sum(
                        current_local_digests.get(poi_event_id) != digest
                        for poi_event_id, digest in prior_local_score_digests.items()
                    )
                    if experiment_config.poi_aggregation == "noisy_or" else 0
                )
                if score_monotonicity_violations:
                    raise RuntimeError(
                        f"UBC-{scenario.code} prefix {poi_count} violated "
                        f"score monotonicity on {score_monotonicity_violations} edges"
                    )
                if local_score_digest_violations:
                    raise RuntimeError(
                        f"UBC-{scenario.code} prefix {poi_count} rewrote "
                        f"{local_score_digest_violations} prior POI score maps"
                    )
                result = report["results"][0]
                path_metrics = compute_prefix_path_metrics(
                    reference.attack_paths,
                    set(result["kept_event_ids"]),
                    set(prefix.seed_event_ids),
                )
                report["poi_prefix_experiment"] = {
                    "scenario": scenario.code,
                    "poi_count": poi_count,
                    "full_poi_count": len(timeline),
                    "selected_poi_event_ids": [
                        edge.event_id for edge in timeline[:poi_count]
                    ],
                    "selected_poi_event_sequences": [
                        list(sequence) for sequence in prefix.seed_event_sequences
                    ],
                    "certificate_topology_policy": (
                        prefix.metadata["certificate_topology_policy"]
                    ),
                    "fixed_reference_file": str(
                        fixed_reference_path.resolve()
                    ),
                    "online_uses_groundtruth": False,
                    "path_metrics": path_metrics,
                }
                report["incomplete"] = False
                _write_json(result_path, report)
                paper = report["paper_main_results"]["rows"][0]
                table7 = report["depimpact_table7_runtime"]
                table8 = report["depimpact_table8_entry_ranks"]
                row = {
                    "scenario": scenario.code,
                    "poi_count": poi_count,
                    "full_poi_count": len(timeline),
                    "selected_poi_event_ids": [
                        edge.event_id for edge in timeline[:poi_count]
                    ],
                    "candidate_events": report["original_edges"],
                    "candidate_nodes": report["original_nodes"],
                    "kept_events": paper["events_after"],
                    "requested_keep_ratio": spec.keep_ratio,
                    "actual_keep_ratio": result["actual_keep_ratio"],
                    "event_compression_ratio": paper["event_compression_ratio"],
                    "attack_event_recall": paper["attack_event_recall"],
                    **path_metrics,
                    "marginal_restored_paths": (
                        path_metrics["retained_reference_paths"] - prior_restored
                    ),
                    "path_certificate_valid": result["path_certificate_valid"],
                    "path_certificate_status": result["path_certificate_status"],
                    "strict_multistage_certificate_valid": result[
                        "strict_multistage_certificate_valid"
                    ],
                    "causal_path_cover_certificate_valid": result[
                        "causal_path_cover_certificate_valid"
                    ],
                    "certificate_topology": result["certificate_topology"],
                    "certificate_branch_count": result[
                        "certificate_branch_count"
                    ],
                    "candidate_disconnected_stage_pairs": result[
                        "candidate_disconnected_stage_pairs"
                    ],
                    "budget_feasible": result["budget_feasible"],
                    "budget_rounding_policy": result[
                        "budget_rounding_policy"
                    ],
                    "budget_overflow_edges": result["budget_overflow_edges"],
                    "score_mass_retained": result["score_mass_retained"],
                    "stage_pairs": result["stage_pairs"],
                    "connected_stage_pairs": result["connected_stage_pairs"],
                    "retained_stage_pairs": result["retained_stage_pairs"],
                    "prefix_jaccard": result["prefix_jaccard"],
                    "added_edges": result["added_edges"],
                    "removed_previous_edges": result[
                        "removed_previous_edges"
                    ],
                    "declared_allowed_removed_previous_edges": result[
                        "declared_allowed_removed_previous_edges"
                    ],
                    "allowed_removed_previous_edges": result[
                        "allowed_removed_previous_edges"
                    ],
                    "budget_contraction_edges": result[
                        "budget_contraction_edges"
                    ],
                    "atomicity_churn_slack_edges": result[
                        "atomicity_churn_slack_edges"
                    ],
                    "churn_bound_satisfied": result["churn_bound_satisfied"],
                    "churn_constraint_status": result[
                        "churn_constraint_status"
                    ],
                    "score_monotonicity_violations": (
                        score_monotonicity_violations
                    ),
                    "local_score_digest_violations": (
                        local_score_digest_violations
                    ),
                    "unused_budget_edges": result["unused_budget_edges"],
                    "zero_score_fill_stopped": result[
                        "zero_score_fill_stopped"
                    ],
                    "score_ledger_manifest": report["score_ledger"].get(
                        "manifest"
                    ),
                    "score_ledger_valid": bool(
                        report["score_ledger"].get("verification", {}).get(
                            "valid"
                        )
                    ),
                    "elapsed_seconds": report["elapsed_seconds"],
                    "result_file": str(result_path.resolve()),
                    "input_file": str(prefix_path.resolve()),
                    "table7_attack_causality_s": table7[
                        "attack_causality_analysis_seconds"
                    ],
                    "table7_edge_merge_s": table7["edge_merge_seconds"],
                    "table7_depimpact_weight_s": table7[
                        "dependency_weight_computation_seconds"
                    ]["depimpact"],
                    "table7_fixed_projection_weight_s": table7[
                        "dependency_weight_computation_seconds"
                    ]["fixed_projection"],
                    "table7_depimpact_propagation_s": table7[
                        "dependency_impact_propagation_seconds"
                    ]["depimpact"],
                    "table7_fixed_projection_propagation_s": table7[
                        "dependency_impact_propagation_seconds"
                    ]["fixed_projection"],
                    "table7_nodoze_s": table7["nodoze_seconds"],
                    "table8_candidate_entries": table8[
                        "candidate_entry_count"
                    ],
                    "table8_attack_entries": table8["attack_entry_count"],
                    "table8_covered_attack_entries": table8[
                        "covered_attack_entry_count"
                    ],
                    "table8_attack_entry_coverage": table8[
                        "attack_entry_coverage"
                    ],
                    **{
                        f"table8_{method}_average_rank": table8["methods"][
                            method
                        ]["average_rank"]
                        for method in TABLE8_METHODS
                    },
                }
                prior_restored = int(path_metrics["retained_reference_paths"])
                prior_kept_event_ids = set(online_state["kept_event_ids"])
                prior_edge_scores = current_edge_scores
                prior_local_score_digests = dict(current_local_digests)
                prefix_score_accumulator = online_state[
                    "prefix_score_accumulator"
                ]
                rows.append(row)
                scenario_rows.append(row)
                _write_json(
                    destination / "partial-summary.json",
                    {
                        "incomplete": True,
                        "keep_ratio": spec.keep_ratio,
                        "completed_prefix_runs": len(rows),
                        "rows": rows,
                    },
                )
                _write_summary_csv(
                    destination / "partial-summary.csv", rows
                )
                progress(
                    {
                        "stage": "prefix_complete",
                        "scenario": scenario.code,
                        "poi_count": poi_count,
                        "full_poi_count": len(timeline),
                        "retained_reference_paths": path_metrics[
                            "retained_reference_paths"
                        ],
                    }
                )
                del report
                gc.collect()
            day_summaries.append(
                {
                    "scenario": scenario.code,
                    "full_poi_count": len(timeline),
                    **select_minimum_sufficient(
                        scenario_rows, total_paths=len(reference.attack_paths)
                    ),
                }
            )

    selected_rows = []
    for day in day_summaries:
        wanted = day["minimum_sufficient_poi_count"]
        selected_rows.extend(
            row
            for row in rows
            if row["scenario"] == day["scenario"] and row["poi_count"] == wanted
        )
    unseeded_values = [
        float(row["unselected_terminal_path_retention"])
        for row in selected_rows
        if row["unselected_terminal_path_retention"] is not None
    ]
    minimum_counts = [
        int(day["minimum_sufficient_poi_count"])
        for day in day_summaries
        if day["minimum_sufficient_poi_count"] is not None
    ]
    minimum_fractions = [
        int(day["minimum_sufficient_poi_count"]) / int(day["full_poi_count"])
        for day in day_summaries
        if day["minimum_sufficient_poi_count"] is not None
    ]
    summary = {
        "schema_version": "cadets-e3-poi-prefix-sweep-v3",
        "database": str(Path(database_path).resolve()),
        "spec_file": str(Path(spec_path).resolve()),
        "config_file": str(Path(config_path).resolve()),
        "keep_ratio": spec.keep_ratio,
        "online_uses_groundtruth": False,
        "online_method": (
            "PS-RDP_prefix_stable_noisy_or_bounded_churn_"
            "causal_path_cover"
        ),
        "score_semantics": "heuristic_importance_not_probability",
        "deployment_stopping_rule_available": False,
        "minimum_sufficient_rule": (
            "offline_hindsight_only: earliest valid causal-path-cover, budget-"
            "feasible, churn-valid prefix attaining the day's maximum retained "
            "derived-reference paths"
        ),
        "table8_method_average_ranks": {
            method: (
                fmean(values) if (values := [
                    float(row[f"table8_{method}_average_rank"])
                    for row in rows
                    if row[f"table8_{method}_average_rank"] is not None
                ]) else None
            )
            for method in TABLE8_METHODS
        },
        "rows": rows,
        "days": day_summaries,
        "cross_day": {
            "completed_prefix_runs": len(rows),
            "expected_prefix_runs": sum(
                day["full_poi_count"] for day in day_summaries
            ),
            "minimum_total_pois": (
                sum(minimum_counts)
                if len(minimum_counts) == len(day_summaries) else None
            ),
            "mean_minimum_poi_fraction": (
                fmean(minimum_fractions)
                if len(minimum_fractions) == len(day_summaries) else None
            ),
            "macro_maximum_complete_path_retention": fmean(
                float(day["maximum_complete_path_retention"])
                for day in day_summaries
                if day["maximum_complete_path_retention"] is not None
            ),
            "macro_unselected_path_retention_at_minimum": (
                fmean(unseeded_values) if unseeded_values else None
            ),
            "unselected_path_macro_contributing_days": len(unseeded_values),
            "score_monotonicity_violations": sum(
                int(row["score_monotonicity_violations"]) for row in rows
            ),
            "local_score_digest_violations": sum(
                int(row["local_score_digest_violations"]) for row in rows
            ),
            "minimum_consecutive_prefix_jaccard": min(
                (
                    float(row["prefix_jaccard"])
                    for row in rows if row["prefix_jaccard"] is not None
                ),
                default=None,
            ),
            "all_churn_bounds_satisfied": all(
                bool(row["churn_bound_satisfied"]) for row in rows
            ),
            "complete_score_ledgers": sum(
                bool(row.get("score_ledger_valid")) for row in rows
            ),
        },
    }
    _write_json(destination / "summary.json", summary)
    _write_summary_csv(destination / "summary.csv", rows)
    _write_depimpact_paper_tables(destination, rows)
    (destination / "summary.md").write_text(
        _summary_markdown(summary), encoding="utf-8"
    )
    _write_json(
        progress_path,
        {
            "incomplete": False,
            "stage": "complete",
            "completed_prefix_runs": len(rows),
        },
    )
    if progress_callback is not None:
        progress_callback(
            {"stage": "complete", "completed_prefix_runs": len(rows)}
        )
    return summary


__all__ = [
    "POIPrefixScenario",
    "POIPrefixSweepSpec",
    "build_prefix_annotations",
    "build_report_reference",
    "compute_prefix_path_metrics",
    "load_poi_prefix_spec",
    "require_complete_prefix_report",
    "resolve_poi_timeline",
    "run_poi_prefix_sweep",
    "select_minimum_sufficient",
]
