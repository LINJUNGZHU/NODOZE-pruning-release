"""Deterministic, complete evidence ledger for edge-level pruning scores."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
from collections import Counter
from dataclasses import asdict, fields
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from .models import Neighborhood, NodeRecord, StoredEdge
from .rdp_guard import score_map_digest


SCHEMA_VERSION = "rdp-edge-score-ledger-v3"
_CANDIDATE_ARTIFACT = "candidate-graph.jsonl.gz"
_SCORE_ARTIFACT = "edge-scores.jsonl.gz"
_HIGH_SCORE_ARTIFACT = "high-anomaly-edges.json"
_LOCAL_CONTRIBUTION_ARTIFACT = "poi-local-contributions.jsonl.gz"
_SCORE_SEMANTICS = "heuristic_importance_not_probability"
_LOCAL_CONTRIBUTION_ENCODING = (
    "sparse_positive_rows_missing_pairs_are_exact_zero"
)
_NODE_FIELDS = tuple(field.name for field in fields(NodeRecord))
_EDGE_FIELDS = tuple(field.name for field in fields(StoredEdge))
_EVIDENCE_FIELDS = ("components", "provenance", "rarity_evidence")
_NOISY_OR_PROVENANCE_FIELDS = {
    "aggregation",
    "support_count",
    "winner_local_score",
    "winner_poi_event_id",
}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_jsonl_gzip(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with io.TextIOWrapper(
                    compressed, encoding="utf-8", newline="\n"
                ) as text:
                    for row in rows:
                        text.write(_canonical_json(row) + "\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _formatted_keep_ratio_keys(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label}: expected a list")
    formatted: list[str] = []
    for ratio in value:
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
            raise ValueError(f"{label}: values must be finite numbers")
        numeric = float(ratio)
        if not math.isfinite(numeric):
            raise ValueError(f"{label}: values must be finite numbers")
        formatted.append(format(numeric, ".12g"))
    return sorted(formatted)


def _scoring_contract(
    context: Mapping[str, object] | None,
) -> tuple[bool, bool]:
    if not context or "scoring_parameters" not in context:
        return False, False
    scoring = context["scoring_parameters"]
    if not isinstance(scoring, Mapping):
        raise ValueError("context.scoring_parameters: expected an object")
    actual_aggregation = scoring.get("edge_score_aggregation")
    if actual_aggregation is not None:
        if actual_aggregation not in {"joint", "noisy_or"}:
            raise ValueError(
                "context.scoring_parameters.edge_score_aggregation: "
                "expected 'joint' or 'noisy_or'"
            )
        return True, actual_aggregation == "noisy_or"
    # Backward compatibility for ledgers written before the actual aggregation
    # field was introduced. New experiment reports always provide it.
    return True, scoring.get("poi_aggregation") == "noisy_or"


def _validate_keep_ratio_contract(
    context: Mapping[str, object] | None,
    budget_keys: Sequence[str],
) -> None:
    if not context or "pruning_parameters" not in context:
        return
    pruning = context["pruning_parameters"]
    if not isinstance(pruning, Mapping):
        raise ValueError("context.pruning_parameters: expected an object")
    if "keep_ratios" not in pruning:
        return
    ratio_keys = _formatted_keep_ratio_keys(
        pruning["keep_ratios"],
        label="context.pruning_parameters.keep_ratios",
    )
    if ratio_keys != list(budget_keys):
        raise ValueError(
            "context.pruning_parameters.keep_ratios formatted with '.12g' "
            "must equal decision budget keys (manifest.decision_budget_keys); "
            f"ratios={ratio_keys}, "
            f"decisions={list(budget_keys)}"
        )


def _mapping_with_string_keys(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: expected an object")
    result = dict(value)
    if any(not isinstance(key, str) for key in result):
        raise ValueError(f"{label}: keys must be strings")
    _validate_evidence_value(result, label=label)
    return result


def _validate_evidence_value(value: object, *, label: str) -> None:
    """Require portable JSON evidence and reject NaN/Inf at every depth."""
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{label}: numeric evidence must be finite")
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{label}: nested keys must be strings")
            _validate_evidence_value(nested, label=f"{label}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_evidence_value(nested, label=f"{label}[{index}]")
        return
    raise ValueError(
        f"{label}: evidence values must be JSON scalars, arrays, or objects"
    )


def _validate_noisy_or_provenance(
    value: Mapping[str, object], *, label: str
) -> None:
    missing = sorted(_NOISY_OR_PROVENANCE_FIELDS - set(value))
    if missing:
        raise ValueError(f"{label}: missing required fields {missing}")
    if value.get("aggregation") != "noisy_or":
        raise ValueError(f"{label}.aggregation: expected 'noisy_or'")
    support_count = value.get("support_count")
    if (
        isinstance(support_count, bool)
        or not isinstance(support_count, int)
        or support_count < 0
    ):
        raise ValueError(f"{label}.support_count: expected a non-negative integer")
    winner = value.get("winner_poi_event_id")
    if not isinstance(winner, str) or not winner:
        raise ValueError(f"{label}.winner_poi_event_id: expected a non-empty string")
    winner_score = value.get("winner_local_score")
    if (
        isinstance(winner_score, bool)
        or not isinstance(winner_score, (int, float))
        or not math.isfinite(float(winner_score))
        or not 0.0 <= float(winner_score) <= 1.0
    ):
        raise ValueError(f"{label}.winner_local_score: expected finite [0, 1]")


def _validate_noisy_or_evidence_consistency(
    *,
    score: object,
    components: Mapping[str, object],
    provenance: Mapping[str, object],
    rarity_evidence: Mapping[str, object],
    label: str,
) -> None:
    """Cross-check duplicated noisy-OR evidence instead of only its shape."""

    def number(mapping: Mapping[str, object], key: str) -> float | None:
        value = mapping.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            return None
        return float(value)

    score_value = (
        float(score)
        if not isinstance(score, bool)
        and isinstance(score, (int, float))
        and math.isfinite(float(score))
        else None
    )
    aggregate = number(components, "aggregate_noisy_or")
    maximum = number(components, "max_local_score")
    component_support = number(components, "poi_support_count")
    winner = number(provenance, "winner_local_score")
    provenance_support = provenance.get("support_count")
    rarity_score = number(rarity_evidence, "score")
    mismatches: list[str] = []
    required_numbers = {
        "score": score_value,
        "aggregate_noisy_or": aggregate,
        "max_local_score": maximum,
        "poi_support_count": component_support,
        "winner_local_score": winner,
        "rarity_evidence.score": rarity_score,
    }
    missing = sorted(key for key, value in required_numbers.items() if value is None)
    if missing:
        mismatches.append(f"missing finite numeric fields {missing}")
    if (
        score_value is not None
        and aggregate is not None
        and not math.isclose(score_value, aggregate, rel_tol=0.0, abs_tol=1e-15)
    ):
        mismatches.append("score != components.aggregate_noisy_or")
    if (
        maximum is not None
        and winner is not None
        and not math.isclose(maximum, winner, rel_tol=0.0, abs_tol=1e-15)
    ):
        mismatches.append("components.max_local_score != provenance.winner_local_score")
    if (
        component_support is not None
        and isinstance(provenance_support, int)
        and not isinstance(provenance_support, bool)
        and not math.isclose(
            component_support,
            float(provenance_support),
            rel_tol=0.0,
            abs_tol=0.0,
        )
    ):
        mismatches.append("component/provenance support counts differ")
    if component_support is not None and (
        component_support < 0.0 or not component_support.is_integer()
    ):
        mismatches.append("components.poi_support_count is not a non-negative integer")
    if aggregate is not None and maximum is not None and (
        not 0.0 <= maximum <= aggregate + 1e-15 <= 1.0 + 1e-15
    ):
        mismatches.append("max_local_score is outside [0, aggregate_noisy_or]")
    if (
        component_support is not None
        and aggregate is not None
        and maximum is not None
    ):
        if component_support == 0.0 and (aggregate != 0.0 or maximum != 0.0):
            mismatches.append("zero support requires zero local and aggregate scores")
        if component_support == 1.0 and not math.isclose(
            aggregate, maximum, rel_tol=0.0, abs_tol=1e-15
        ):
            mismatches.append("single support requires aggregate == max local score")

    gated_pairs = (
        ("rarity", "gated_rarity"),
        ("path", "gated_path"),
        ("depimpact", "gated_depimpact"),
        ("behavior", "gated_behavior"),
    )
    if any(gated in components for _, gated in gated_pairs):
        diffusion = number(components, "diffusion")
        for source, gated in gated_pairs:
            source_value = number(components, source)
            gated_value = number(components, gated)
            if diffusion is None or source_value is None or gated_value is None:
                mismatches.append(f"missing finite gated-score fields for {source}")
            elif not math.isclose(
                gated_value,
                diffusion * source_value,
                rel_tol=1e-12,
                abs_tol=1e-15,
            ):
                mismatches.append(f"{gated} != diffusion * {source}")

    if mismatches:
        raise ValueError(f"{label}: noisy_or evidence mismatch: {'; '.join(mismatches)}")


def _write_streamed_json_array_document(
    stream: io.TextIOBase,
    *,
    metadata: Mapping[str, object],
    rows: Iterable[Mapping[str, object]],
) -> int:
    """Write a deterministic JSON object without retaining its row array."""
    stream.write('{"edges":[')
    count = 0
    for row in rows:
        if count:
            stream.write(",")
        stream.write(_canonical_json(row))
        count += 1
    stream.write("]")
    for key in sorted(metadata):
        stream.write(",")
        stream.write(_canonical_json(key))
        stream.write(":")
        stream.write(_canonical_json(metadata[key]))
    stream.write("}\n")
    return count


def _positive_quantile(scores: Sequence[float], quantile: float) -> float:
    positive = sorted(score for score in scores if score > 0.0)
    if not positive:
        return 0.0
    index = max(0, math.ceil(quantile * len(positive)) - 1)
    return positive[index]


def _candidate_identity_records(
    graph: Neighborhood,
) -> Iterable[dict[str, object]]:
    for node in sorted(graph.nodes.values(), key=lambda item: item.uuid):
        yield {
            "schema_version": SCHEMA_VERSION,
            "record_type": "node",
            **asdict(node),
        }
    for edge in sorted(graph.edges, key=lambda item: item.edge_id):
        yield {
            "schema_version": SCHEMA_VERSION,
            "record_type": "edge",
            **asdict(edge),
        }


def _identity_records_digest(records: Iterable[Mapping[str, object]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(_canonical_json(record).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def candidate_graph_digest(graph: Neighborhood) -> str:
    """Hash every field of every node and stored edge in canonical order."""
    return _identity_records_digest(_candidate_identity_records(graph))


def _normalize_local_contributions(
    value: Mapping[str, Mapping[int, float]] | None,
    *,
    edge_ids: Sequence[int],
    aggregate_scores: Mapping[int, float],
    context: Mapping[str, object] | None,
    noisy_or_required: bool,
) -> tuple[dict[str, dict[int, float]], dict[str, str]]:
    """Validate sparse POI-local scores and independently replay noisy-OR."""
    declared_value = (context or {}).get("local_score_digests", {})
    if not isinstance(declared_value, Mapping) or any(
        not isinstance(key, str) or not isinstance(digest, str)
        for key, digest in declared_value.items()
    ):
        raise ValueError("context.local_score_digests must map POI IDs to digests")
    declared_digests = dict(declared_value)
    contributions_required = noisy_or_required and bool(declared_digests)
    if value is None:
        if contributions_required:
            raise ValueError(
                "local_score_contributions are required when noisy-OR local "
                "score digests are declared"
            )
        return {}, {}
    if not isinstance(value, Mapping) or any(
        not isinstance(poi, str) or not poi for poi in value
    ):
        raise ValueError("local_score_contributions must map non-empty POI IDs")
    if declared_digests and set(value) != set(declared_digests):
        raise ValueError(
            "local_score_contributions POI IDs must exactly match "
            "context.local_score_digests"
        )

    edge_id_set = set(edge_ids)
    normalized: dict[str, dict[int, float]] = {}
    computed_digests: dict[str, str] = {}
    replay_scores = {edge_id: 0.0 for edge_id in edge_ids}
    for poi, local_values in value.items():
        if not isinstance(local_values, Mapping):
            raise ValueError(
                f"local_score_contributions[{poi!r}] must be an edge-score object"
            )
        sparse: dict[int, float] = {}
        for edge_id, raw_score in local_values.items():
            if isinstance(edge_id, bool) or not isinstance(edge_id, int):
                raise ValueError("local contribution edge IDs must be integers")
            if edge_id not in edge_id_set:
                raise ValueError(
                    f"local contribution for {poi!r} contains unknown edge {edge_id}"
                )
            if (
                isinstance(raw_score, bool)
                or not isinstance(raw_score, (int, float))
                or not math.isfinite(float(raw_score))
                or not 0.0 <= float(raw_score) <= 1.0
            ):
                raise ValueError(
                    f"local contribution for {poi!r}, edge {edge_id} must be "
                    "finite [0, 1]"
                )
            local_score = float(raw_score)
            if local_score > 0.0:
                sparse[edge_id] = local_score
        normalized[poi] = sparse
        dense_for_digest = {
            edge_id: sparse.get(edge_id, 0.0) for edge_id in edge_ids
        }
        digest = score_map_digest(dense_for_digest)
        computed_digests[poi] = digest
        if declared_digests and declared_digests[poi] != digest:
            raise ValueError(
                f"local score digest mismatch for POI {poi!r}: "
                f"declared={declared_digests[poi]}, recomputed={digest}"
            )
        for edge_id, local_score in sparse.items():
            previous = replay_scores[edge_id]
            replay_scores[edge_id] = min(
                1.0, max(0.0, previous + (1.0 - previous) * local_score)
            )
    if noisy_or_required and normalized:
        mismatched = [
            edge_id
            for edge_id in edge_ids
            if not math.isclose(
                replay_scores[edge_id],
                float(aggregate_scores[edge_id]),
                rel_tol=0.0,
                abs_tol=1e-15,
            )
        ]
        if mismatched:
            raise ValueError(
                "local_score_contributions do not reproduce noisy-OR aggregate; "
                f"mismatched edges={mismatched[:5]}"
            )
    return normalized, computed_digests


def _local_contribution_records(
    contributions: Mapping[str, Mapping[int, float]],
) -> Iterable[dict[str, object]]:
    for poi_event_id, local_scores in contributions.items():
        for edge_id in sorted(local_scores):
            yield {
                "schema_version": SCHEMA_VERSION,
                "poi_event_id": poi_event_id,
                "edge_id": edge_id,
                "local_score": float(local_scores[edge_id]),
            }


def write_score_ledger(
    destination: str | Path,
    *,
    graph: Neighborhood,
    scores: Mapping[int, float],
    components: Mapping[int, Mapping[str, object]],
    rarity_evidence: (
        Mapping[int, Mapping[str, object]]
        | Callable[[StoredEdge], Mapping[str, object]]
    ),
    decisions: Mapping[str, Mapping[int, Sequence[str]]],
    score_provenance: Mapping[int, Mapping[str, object]] | None = None,
    local_score_contributions: Mapping[str, Mapping[int, float]] | None = None,
    absolute_threshold: float = 0.8,
    high_score_quantile: float = 0.99,
    context: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Write one complete, hash-verifiable row per candidate edge.

    ``decisions`` maps a stable budget key to kept edge IDs and their reasons.
    Missing IDs are represented explicitly as ``kept=false`` rows.
    """
    if not 0.0 <= absolute_threshold <= 1.0:
        raise ValueError("absolute_threshold must be in [0, 1]")
    if not 0.0 < high_score_quantile <= 1.0:
        raise ValueError("high_score_quantile must be in (0, 1]")
    mismatched_node_keys = sorted(
        key for key, node in graph.nodes.items() if key != node.uuid
    )
    if mismatched_node_keys:
        raise ValueError(
            "candidate graph node keys must match NodeRecord.uuid; "
            f"mismatched={mismatched_node_keys[:5]}"
        )
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    if len(edge_by_id) != len(graph.edges):
        raise ValueError("candidate graph contains duplicate numeric edge IDs")
    if set(scores) != set(edge_by_id):
        missing = sorted(set(edge_by_id) - set(scores))
        extra = sorted(set(scores) - set(edge_by_id))
        raise ValueError(
            f"scores must cover candidate graph exactly; missing={missing[:5]}, "
            f"extra={extra[:5]}"
        )
    normalized_scores: dict[int, float] = {}
    for edge_id, value in scores.items():
        score = float(value)
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError(f"invalid normalized score for edge {edge_id}: {value}")
        normalized_scores[edge_id] = score

    normalized_decisions: dict[str, dict[int, tuple[str, ...]]] = {}
    for budget_key, kept in decisions.items():
        if not isinstance(budget_key, str):
            raise ValueError("decision budget keys must be strings")
        unknown = sorted(set(kept) - set(edge_by_id))
        if unknown:
            raise ValueError(
                f"decision budget {budget_key} contains unknown edges: {unknown[:5]}"
            )
        normalized_kept: dict[int, tuple[str, ...]] = {}
        for edge_id, reasons in kept.items():
            if isinstance(reasons, (str, bytes)):
                reason_values = (str(reasons),)
            else:
                reason_values = tuple(str(reason) for reason in reasons)
            normalized_reasons = tuple(sorted({
                reason for reason in reason_values if reason.strip()
            }))
            if not normalized_reasons:
                raise ValueError(
                    f"kept edge {edge_id} at budget {budget_key} requires "
                    "at least one non-empty reason"
                )
            normalized_kept[int(edge_id)] = normalized_reasons
        normalized_decisions[budget_key] = normalized_kept

    quantile_cutoff = _positive_quantile(
        list(normalized_scores.values()), high_score_quantile
    )
    effective_cutoff = max(float(absolute_threshold), quantile_cutoff)
    ranked_ids = sorted(
        edge_by_id, key=lambda edge_id: (-normalized_scores[edge_id], edge_id)
    )
    high_ids = {
        edge_id
        for edge_id in ranked_ids
        if normalized_scores[edge_id] > 0.0
        and normalized_scores[edge_id] >= effective_cutoff
    }
    provenance = score_provenance or {}
    budget_keys = sorted(normalized_decisions)
    _validate_keep_ratio_contract(context, budget_keys)
    evidence_required, noisy_or_provenance_required = _scoring_contract(context)
    normalized_local_contributions, computed_local_digests = (
        _normalize_local_contributions(
            local_score_contributions,
            edge_ids=sorted(edge_by_id),
            aggregate_scores=normalized_scores,
            context=context,
            noisy_or_required=noisy_or_provenance_required,
        )
    )
    poi_event_ids_value = (context or {}).get("poi_event_ids", [])
    if not isinstance(poi_event_ids_value, list) or any(
        not isinstance(event_id, str) or not event_id
        for event_id in poi_event_ids_value
    ):
        raise ValueError("context.poi_event_ids must be a list of non-empty strings")
    if len(poi_event_ids_value) != len(set(poi_event_ids_value)):
        raise ValueError("context.poi_event_ids must be unique")
    declared_poi_event_ids = set(poi_event_ids_value)
    non_poi_high_ids = {
        edge_id
        for edge_id in high_ids
        if edge_by_id[edge_id].event_id not in declared_poi_event_ids
    }

    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    candidate_path = output / _CANDIDATE_ARTIFACT
    _atomic_jsonl_gzip(candidate_path, _candidate_identity_records(graph))
    local_contribution_path = output / _LOCAL_CONTRIBUTION_ARTIFACT
    _atomic_jsonl_gzip(
        local_contribution_path,
        _local_contribution_records(normalized_local_contributions),
    )
    score_path = output / _SCORE_ARTIFACT
    temporary_score = output / f".{score_path.name}.tmp"
    high_path = output / _HIGH_SCORE_ARTIFACT
    temporary_high = output / f".{high_path.name}.tmp"
    evidence_key_schema: dict[str, list[str]] = {
        field_name: [] for field_name in _EVIDENCE_FIELDS
    }
    expected_component_keys: tuple[str, ...] | None = None
    expected_rarity_keys: tuple[str, ...] | None = None
    expected_provenance_keys: tuple[str, ...] | None = None
    observed_provenance_keys: set[str] = set()

    high_metadata = {
        "schema_version": SCHEMA_VERSION,
        "score_semantics": _SCORE_SEMANTICS,
        "absolute_threshold": absolute_threshold,
        "positive_score_quantile": high_score_quantile,
        "quantile_cutoff": quantile_cutoff,
        "effective_cutoff": effective_cutoff,
        "tie_policy": "include_all_scores_equal_to_cutoff",
        "interpretation": "high_importance_tail_not_detection_verdict",
        "declared_poi_count": len(declared_poi_event_ids),
        "non_poi_high_score_count": len(non_poi_high_ids),
    }

    def write_rows() -> Iterable[dict[str, object]]:
        nonlocal expected_component_keys
        nonlocal expected_rarity_keys
        nonlocal expected_provenance_keys
        nonlocal observed_provenance_keys
        denominator = max(1, len(ranked_ids) - 1)
        with temporary_score.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with io.TextIOWrapper(
                    compressed, encoding="utf-8", newline="\n"
                ) as text:
                    for rank, edge_id in enumerate(ranked_ids, start=1):
                        edge = edge_by_id[edge_id]
                        score = normalized_scores[edge_id]
                        component_values = _mapping_with_string_keys(
                            components.get(edge_id, {}),
                            label=f"components for edge {edge_id}",
                        )
                        rarity_values = _mapping_with_string_keys(
                            rarity_evidence(edge)
                            if callable(rarity_evidence)
                            else rarity_evidence.get(edge_id, {}),
                            label=f"rarity_evidence for edge {edge_id}",
                        )
                        provenance_values = _mapping_with_string_keys(
                            provenance.get(edge_id, {}),
                            label=f"provenance for edge {edge_id}",
                        )
                        component_keys = tuple(sorted(component_values))
                        rarity_keys = tuple(sorted(rarity_values))
                        provenance_keys = tuple(sorted(provenance_values))
                        observed_provenance_keys.update(provenance_keys)
                        if evidence_required:
                            if not component_keys:
                                raise ValueError(
                                    f"inconsistent components key schema at edge {edge_id}: "
                                    "evidence must not be empty"
                                )
                            if expected_component_keys is None:
                                expected_component_keys = component_keys
                            elif component_keys != expected_component_keys:
                                raise ValueError(
                                    f"inconsistent components key schema at edge {edge_id}: "
                                    f"expected={list(expected_component_keys)}, "
                                    f"actual={list(component_keys)}"
                                )
                            if not rarity_keys:
                                raise ValueError(
                                    f"inconsistent rarity_evidence key schema at edge "
                                    f"{edge_id}: evidence must not be empty"
                                )
                            if expected_rarity_keys is None:
                                expected_rarity_keys = rarity_keys
                            elif rarity_keys != expected_rarity_keys:
                                raise ValueError(
                                    f"inconsistent rarity_evidence key schema at edge "
                                    f"{edge_id}: expected={list(expected_rarity_keys)}, "
                                    f"actual={list(rarity_keys)}"
                                )
                            if noisy_or_provenance_required:
                                if not provenance_keys:
                                    raise ValueError(
                                        f"inconsistent provenance key schema at edge "
                                        f"{edge_id}: noisy_or provenance must not be empty"
                                    )
                                try:
                                    _validate_noisy_or_provenance(
                                        provenance_values,
                                        label=f"provenance for edge {edge_id}",
                                    )
                                except ValueError as exc:
                                    raise ValueError(
                                        "inconsistent provenance key schema at "
                                        f"edge {edge_id}: {exc}"
                                    ) from exc
                                _validate_noisy_or_evidence_consistency(
                                    score=score,
                                    components=component_values,
                                    provenance=provenance_values,
                                    rarity_evidence=rarity_values,
                                    label=f"edge {edge_id}",
                                )
                                if expected_provenance_keys is None:
                                    expected_provenance_keys = provenance_keys
                                elif provenance_keys != expected_provenance_keys:
                                    raise ValueError(
                                        f"inconsistent provenance key schema at edge "
                                        f"{edge_id}: expected={list(expected_provenance_keys)}, "
                                        f"actual={list(provenance_keys)}"
                                    )
                        row = {
                            "schema_version": SCHEMA_VERSION,
                            "edge_id": edge.edge_id,
                            "event_id": edge.event_id,
                            "src": edge.src,
                            "dst": edge.dst,
                            "src_type": edge.src_type,
                            "dst_type": edge.dst_type,
                            "src_semantic": edge.src_semantic,
                            "dst_semantic": edge.dst_semantic,
                            "relation": edge.relation,
                            "timestamp_ns": edge.timestamp_ns,
                            "host": edge.host,
                            "data_size": edge.data_size,
                            "score": score,
                            "score_semantics": _SCORE_SEMANTICS,
                            "rank": rank,
                            "empirical_percentile": (
                                (len(ranked_ids) - rank) / denominator
                                if ranked_ids else 0.0
                            ),
                            "high_score": edge_id in high_ids,
                            "is_declared_poi": (
                                edge.event_id in declared_poi_event_ids
                            ),
                            "components": component_values,
                            "rarity_evidence": rarity_values,
                            "provenance": provenance_values,
                            "decisions": [
                                {
                                    "budget_key": budget_key,
                                    "kept": edge_id
                                    in normalized_decisions[budget_key],
                                    "reasons": list(
                                        normalized_decisions[budget_key].get(
                                            edge_id, ()
                                        )
                                    ),
                                }
                                for budget_key in budget_keys
                            ],
                        }
                        text.write(_canonical_json(row) + "\n")
                        if edge_id in high_ids:
                            yield {
                                "edge_id": edge_id,
                                "event_id": edge.event_id,
                                "score": score,
                                "rank": rank,
                                "is_declared_poi": (
                                    edge.event_id in declared_poi_event_ids
                                ),
                                "relation": edge.relation,
                                "timestamp_ns": edge.timestamp_ns,
                                "components": component_values,
                                "rarity_evidence": rarity_values,
                                "provenance": provenance_values,
                                "decisions": row["decisions"],
                            }

    try:
        with temporary_high.open("w", encoding="utf-8", newline="\n") as high_stream:
            high_score_count = _write_streamed_json_array_document(
                high_stream,
                metadata=high_metadata,
                rows=write_rows(),
            )
        temporary_score.replace(score_path)
        temporary_high.replace(high_path)
    except BaseException:
        temporary_score.unlink(missing_ok=True)
        temporary_high.unlink(missing_ok=True)
        raise

    if evidence_required:
        evidence_key_schema = {
            "components": list(expected_component_keys or ()),
            "provenance": sorted(observed_provenance_keys),
            "rarity_evidence": list(expected_rarity_keys or ()),
        }
    artifact_hashes = {
        candidate_path.name: _sha256_file(candidate_path),
        local_contribution_path.name: _sha256_file(local_contribution_path),
        score_path.name: _sha256_file(score_path),
        high_path.name: _sha256_file(high_path),
    }
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "complete": True,
        "online_uses_groundtruth": False,
        "score_semantics": _SCORE_SEMANTICS,
        "candidate_node_count": len(graph.nodes),
        "candidate_edge_count": len(graph.edges),
        "ledger_row_count": len(ranked_ids),
        "unique_edge_ids": len(set(ranked_ids)),
        "positive_score_count": sum(score > 0.0 for score in normalized_scores.values()),
        "high_score_count": high_score_count,
        "non_poi_high_score_count": len(non_poi_high_ids),
        "absolute_threshold": absolute_threshold,
        "positive_score_quantile": high_score_quantile,
        "quantile_cutoff": quantile_cutoff,
        "effective_cutoff": effective_cutoff,
        "candidate_identity_sha256": candidate_graph_digest(graph),
        "local_contribution_encoding": _LOCAL_CONTRIBUTION_ENCODING,
        "local_contribution_poi_order": list(normalized_local_contributions),
        "local_contribution_poi_count": len(normalized_local_contributions),
        "local_contribution_positive_row_count": sum(
            len(values) for values in normalized_local_contributions.values()
        ),
        "local_contribution_score_digests": computed_local_digests,
        "artifacts": artifact_hashes,
        "decision_budget_keys": budget_keys,
        "context": dict(context or {}),
    }
    if evidence_required:
        manifest["evidence_key_schema"] = evidence_key_schema
    # Preserve an easy-to-audit top-level invariant even if callers place the
    # same declaration in context.
    if "online_uses_groundtruth" in (context or {}):
        manifest["online_uses_groundtruth"] = bool(
            (context or {})["online_uses_groundtruth"]
        )
    _atomic_json(output / "manifest.json", manifest)
    return manifest


def verify_score_ledger(destination: str | Path) -> dict[str, object]:
    """Deeply validate a v2 ledger without requiring the source database."""
    output = Path(destination)
    manifest_path = output / "manifest.json"
    if not manifest_path.is_file():
        return {
            "valid": False,
            "reason": "missing_manifest",
            "hash_mismatches": [],
            "validation_errors": ["manifest.json: missing"],
            "row_count": 0,
            "unique_edge_ids": 0,
            "expected_edge_count": -1,
        }

    errors: list[str] = []
    mismatches: list[str] = []

    def add_error(message: str) -> None:
        if message not in errors:
            errors.append(message)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "valid": False,
            "reason": "invalid_manifest",
            "hash_mismatches": [],
            "validation_errors": [f"manifest.json: invalid JSON ({exc})"],
            "row_count": 0,
            "unique_edge_ids": 0,
            "expected_edge_count": -1,
        }
    if not isinstance(manifest, dict):
        return {
            "valid": False,
            "reason": "invalid_manifest",
            "hash_mismatches": [],
            "validation_errors": ["manifest.json: root must be an object"],
            "row_count": 0,
            "unique_edge_ids": 0,
            "expected_edge_count": -1,
        }

    def manifest_count(name: str) -> int:
        value = manifest.get(name, -1)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            add_error(f"manifest.{name}: expected a non-negative integer")
            return -1
        return value

    expected_count = manifest_count("candidate_edge_count")
    expected_node_count = manifest_count("candidate_node_count")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        actual = manifest.get("schema_version")
        add_error(
            f"manifest.schema_version: unsupported schema {actual!r}; "
            f"expected {SCHEMA_VERSION!r}"
        )
        return {
            "valid": False,
            "reason": "unsupported_schema",
            "hash_mismatches": [],
            "validation_errors": errors,
            "row_count": 0,
            "unique_edge_ids": 0,
            "expected_edge_count": expected_count,
        }
    if manifest.get("complete") is not True:
        add_error("manifest.complete: expected true")
    if manifest.get("score_semantics") != _SCORE_SEMANTICS:
        add_error(f"manifest.score_semantics: expected {_SCORE_SEMANTICS!r}")

    required_artifacts = {
        _CANDIDATE_ARTIFACT,
        _SCORE_ARTIFACT,
        _HIGH_SCORE_ARTIFACT,
        _LOCAL_CONTRIBUTION_ARTIFACT,
    }
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        add_error("manifest.artifacts: expected an object")
        artifacts = {}
    missing_artifacts = sorted(required_artifacts - set(artifacts))
    if missing_artifacts:
        add_error(f"manifest.artifacts: missing {missing_artifacts}")
    unexpected_artifacts = sorted(set(artifacts) - required_artifacts)
    if unexpected_artifacts:
        add_error(f"manifest.artifacts: unexpected {unexpected_artifacts}")
    for name in sorted(required_artifacts):
        expected_hash = artifacts.get(name)
        path = output / name
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            add_error(f"manifest.artifacts.{name}: invalid SHA-256 digest")
            mismatches.append(name)
        elif not path.is_file() or _sha256_file(path) != expected_hash:
            add_error(f"{name}: artifact hash mismatch")
            mismatches.append(name)

    def iter_jsonl_gzip(
        name: str,
    ) -> Iterable[tuple[int, dict[str, object] | None]]:
        """Yield rows one at a time; ``None`` preserves malformed line counts."""
        path = output / name
        if not path.is_file():
            add_error(f"{name}: missing")
            return
        try:
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        add_error(
                            f"{name} line {line_number}: invalid JSON ({exc})"
                        )
                        yield line_number, None
                        continue
                    if not isinstance(row, dict):
                        add_error(f"{name} line {line_number}: expected an object")
                        yield line_number, None
                        continue
                    yield line_number, row
        except (OSError, UnicodeError) as exc:
            add_error(f"{name}: unreadable gzip JSONL ({exc})")

    node_ids: list[object] = []
    candidate_edge_ids: list[int] = []
    candidate_edges: dict[int, tuple[object, ...]] = {}
    candidate_edge_record_count = 0
    candidate_identity_digest = hashlib.sha256()
    seen_edge_record = False
    expected_node_fields = {"schema_version", "record_type", *_NODE_FIELDS}
    expected_edge_fields = {"schema_version", "record_type", *_EDGE_FIELDS}
    for index, record in iter_jsonl_gzip(_CANDIDATE_ARTIFACT):
        if record is None:
            continue
        candidate_identity_digest.update(_canonical_json(record).encode("utf-8"))
        candidate_identity_digest.update(b"\n")
        record_type = record.get("record_type")
        if record.get("schema_version") != SCHEMA_VERSION:
            add_error(
                f"{_CANDIDATE_ARTIFACT} line {index}: invalid schema_version"
            )
        if record_type == "node":
            if seen_edge_record:
                add_error(
                    f"{_CANDIDATE_ARTIFACT}: node records must sort before edge records"
                )
            if set(record) != expected_node_fields:
                add_error(
                    f"{_CANDIDATE_ARTIFACT} line {index}: incomplete NodeRecord fields"
                )
            node_ids.append(record.get("uuid"))
        elif record_type == "edge":
            candidate_edge_record_count += 1
            seen_edge_record = True
            if set(record) != expected_edge_fields:
                add_error(
                    f"{_CANDIDATE_ARTIFACT} line {index}: incomplete StoredEdge fields"
                )
            edge_id = record.get("edge_id")
            if isinstance(edge_id, bool) or not isinstance(edge_id, int):
                add_error(f"{_CANDIDATE_ARTIFACT}: every edge_id must be an integer")
            else:
                candidate_edge_ids.append(edge_id)
                candidate_edges.setdefault(
                    edge_id,
                    tuple(record.get(field_name) for field_name in _EDGE_FIELDS),
                )
        else:
            add_error(
                f"{_CANDIDATE_ARTIFACT} line {index}: invalid record_type {record_type!r}"
            )

    valid_node_ids = [value for value in node_ids if isinstance(value, str)]
    if len(valid_node_ids) != len(node_ids):
        add_error(f"{_CANDIDATE_ARTIFACT}: every node uuid must be a string")
    elif node_ids != sorted(node_ids):
        add_error(f"{_CANDIDATE_ARTIFACT}: node records have invalid sort order")
    duplicate_node_ids = sorted(
        value for value, count in Counter(valid_node_ids).items() if count > 1
    )
    if duplicate_node_ids:
        add_error(f"{_CANDIDATE_ARTIFACT}: duplicate node UUIDs {duplicate_node_ids[:5]}")

    if candidate_edge_ids != sorted(candidate_edge_ids):
        add_error(f"{_CANDIDATE_ARTIFACT}: edge records have invalid sort order")
    duplicate_candidate_ids = sorted(
        edge_id
        for edge_id, count in Counter(candidate_edge_ids).items()
        if count > 1
    )
    if duplicate_candidate_ids:
        add_error(
            f"{_CANDIDATE_ARTIFACT}: duplicate candidate edge IDs "
            f"{duplicate_candidate_ids[:5]}"
        )
    if len(node_ids) != expected_node_count:
        add_error(
            f"candidate node count mismatch: artifact={len(node_ids)}, "
            f"manifest={expected_node_count}"
        )
    if candidate_edge_record_count != expected_count:
        add_error(
            f"candidate edge count mismatch: artifact={candidate_edge_record_count}, "
            f"manifest={expected_count}"
        )
    recorded_identity_digest = manifest.get("candidate_identity_sha256")
    if recorded_identity_digest != candidate_identity_digest.hexdigest():
        add_error(
            "manifest.candidate_identity_sha256: mismatch with canonical "
            "candidate identity artifact"
        )
    del node_ids

    row_count = 0
    ledger_ids: list[int] = []
    ledger_scores: dict[int, float] = {}
    ledger_event_ids: dict[int, str] = {}
    budget_keys_value = manifest.get("decision_budget_keys")
    if not isinstance(budget_keys_value, list) or any(
        not isinstance(key, str) for key in budget_keys_value
    ):
        add_error("manifest.decision_budget_keys: expected a list of strings")
        budget_keys: list[str] = []
    else:
        budget_keys = list(budget_keys_value)
        if budget_keys != sorted(set(budget_keys)):
            add_error("manifest.decision_budget_keys: must be sorted and unique")

    context_value = manifest.get("context")
    if not isinstance(context_value, dict):
        add_error("manifest.context: expected an object")
        context_value = {}
    declared_poi_value = context_value.get("poi_event_ids", [])
    if not isinstance(declared_poi_value, list) or any(
        not isinstance(event_id, str) or not event_id
        for event_id in declared_poi_value
    ):
        add_error("manifest.context.poi_event_ids: expected POI event ID list")
        declared_poi_ids: set[str] = set()
    else:
        declared_poi_ids = set(declared_poi_value)
        if len(declared_poi_ids) != len(declared_poi_value):
            add_error("manifest.context.poi_event_ids: must be unique")
    try:
        _validate_keep_ratio_contract(context_value, budget_keys)
    except ValueError as exc:
        add_error(str(exc))
    try:
        evidence_required, noisy_or_provenance_required = _scoring_contract(
            context_value
        )
    except ValueError as exc:
        add_error(str(exc))
        evidence_required = False
        noisy_or_provenance_required = False

    local_order_value = manifest.get("local_contribution_poi_order")
    if not isinstance(local_order_value, list) or any(
        not isinstance(poi, str) or not poi for poi in local_order_value
    ):
        add_error("manifest.local_contribution_poi_order: expected POI ID list")
        local_order: list[str] = []
    else:
        local_order = list(local_order_value)
        if len(local_order) != len(set(local_order)):
            add_error("manifest.local_contribution_poi_order: must be unique")
    if manifest.get("local_contribution_encoding") != _LOCAL_CONTRIBUTION_ENCODING:
        add_error(
            "manifest.local_contribution_encoding: invalid sparse encoding"
        )
    if manifest.get("local_contribution_poi_count") != len(local_order):
        add_error(
            "manifest.local_contribution_poi_count: does not match POI order"
        )
    local_digest_value = manifest.get("local_contribution_score_digests")
    if not isinstance(local_digest_value, dict) or any(
        not isinstance(poi, str) or not isinstance(digest, str)
        for poi, digest in local_digest_value.items()
    ):
        add_error(
            "manifest.local_contribution_score_digests: expected digest object"
        )
        local_digest_manifest: dict[str, str] = {}
    else:
        local_digest_manifest = dict(local_digest_value)
    if set(local_digest_manifest) != set(local_order):
        add_error(
            "manifest.local_contribution_score_digests: POIs do not match POI order"
        )
    context_digests_value = context_value.get("local_score_digests", {})
    if not isinstance(context_digests_value, dict) or any(
        not isinstance(poi, str) or not isinstance(digest, str)
        for poi, digest in context_digests_value.items()
    ):
        add_error("manifest.context.local_score_digests: expected digest object")
        context_digests: dict[str, str] = {}
    else:
        context_digests = dict(context_digests_value)
    if context_digests and context_digests != local_digest_manifest:
        add_error(
            "local contribution digests disagree with context.local_score_digests"
        )
    if noisy_or_provenance_required and context_digests and not local_order:
        add_error("noisy-OR ledger is missing POI-local contribution coverage")

    local_maps: dict[str, dict[int, float]] = {poi: {} for poi in local_order}
    local_pairs: list[tuple[int, int]] = []
    local_row_count = 0
    order_index = {poi: index for index, poi in enumerate(local_order)}
    expected_local_fields = {
        "schema_version", "poi_event_id", "edge_id", "local_score"
    }
    for line_number, local_row in iter_jsonl_gzip(_LOCAL_CONTRIBUTION_ARTIFACT):
        local_row_count = line_number
        if local_row is None:
            continue
        if set(local_row) != expected_local_fields:
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT} line {line_number}: "
                "invalid field schema"
            )
        if local_row.get("schema_version") != SCHEMA_VERSION:
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT} line {line_number}: "
                "invalid schema_version"
            )
        poi = local_row.get("poi_event_id")
        edge_id = local_row.get("edge_id")
        local_score = local_row.get("local_score")
        if not isinstance(poi, str) or poi not in order_index:
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT} line {line_number}: unknown POI"
            )
            continue
        if (
            isinstance(edge_id, bool)
            or not isinstance(edge_id, int)
            or edge_id not in candidate_edges
        ):
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT} line {line_number}: "
                "unknown edge_id"
            )
            continue
        if (
            isinstance(local_score, bool)
            or not isinstance(local_score, (int, float))
            or not math.isfinite(float(local_score))
            or not 0.0 < float(local_score) <= 1.0
        ):
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT} line {line_number}: "
                "local_score must be finite (0, 1]"
            )
            continue
        pair = (order_index[poi], edge_id)
        local_pairs.append(pair)
        if edge_id in local_maps[poi]:
            add_error(
                f"{_LOCAL_CONTRIBUTION_ARTIFACT}: duplicate POI-edge pair "
                f"({poi!r}, {edge_id})"
            )
        else:
            local_maps[poi][edge_id] = float(local_score)
    if local_pairs != sorted(local_pairs):
        add_error(
            f"{_LOCAL_CONTRIBUTION_ARTIFACT}: rows have invalid POI/edge order"
        )
    if manifest.get("local_contribution_positive_row_count") != local_row_count:
        add_error(
            "manifest.local_contribution_positive_row_count: "
            f"expected {local_row_count}, got "
            f"{manifest.get('local_contribution_positive_row_count')!r}"
        )

    recomputed_local_digests: dict[str, str] = {}
    for poi in local_order:
        recomputed_local_digests[poi] = score_map_digest({
            edge_id: local_maps[poi].get(edge_id, 0.0)
            for edge_id in candidate_edge_ids
        })
    for poi in local_order:
        if local_digest_manifest.get(poi) != recomputed_local_digests[poi]:
            add_error(
                f"local score digest mismatch for POI {poi!r}: artifact rows "
                "do not reproduce the manifest digest"
            )

    replayed_scores: dict[int, float] = {}
    replayed_support: dict[int, int] = {}
    replayed_winner_poi: dict[int, str] = {}
    replayed_winner_score: dict[int, float] = {}
    if local_order:
        for edge_id in candidate_edge_ids:
            aggregate = 0.0
            winner_score = -1.0
            winner_poi = local_order[0]
            support = 0
            for poi in local_order:
                local_score = local_maps[poi].get(edge_id, 0.0)
                aggregate = min(
                    1.0,
                    max(0.0, aggregate + (1.0 - aggregate) * local_score),
                )
                if local_score > 0.0:
                    support += 1
                if local_score > winner_score or (
                    local_score == winner_score and poi < winner_poi
                ):
                    winner_score = local_score
                    winner_poi = poi
            replayed_scores[edge_id] = aggregate
            replayed_support[edge_id] = support
            replayed_winner_poi[edge_id] = winner_poi
            replayed_winner_score[edge_id] = winner_score

    expected_evidence_keys: dict[str, list[str]] = {}
    if evidence_required:
        schema_value = manifest.get("evidence_key_schema")
        if not isinstance(schema_value, dict):
            add_error("manifest.evidence_key_schema: expected an object")
            schema_value = {}
        missing_schema_fields = sorted(set(_EVIDENCE_FIELDS) - set(schema_value))
        extra_schema_fields = sorted(set(schema_value) - set(_EVIDENCE_FIELDS))
        if missing_schema_fields:
            add_error(
                "manifest.evidence_key_schema: missing fields "
                f"{missing_schema_fields}"
            )
        if extra_schema_fields:
            add_error(
                "manifest.evidence_key_schema: unexpected fields "
                f"{extra_schema_fields}"
            )
        for evidence_field in _EVIDENCE_FIELDS:
            keys_value = schema_value.get(evidence_field)
            if not isinstance(keys_value, list) or any(
                not isinstance(key, str) for key in keys_value
            ):
                add_error(
                    f"manifest.evidence_key_schema.{evidence_field}: "
                    "expected a list of strings"
                )
                keys: list[str] = []
            else:
                keys = list(keys_value)
                if keys != sorted(set(keys)):
                    add_error(
                        f"manifest.evidence_key_schema.{evidence_field}: "
                        "must be sorted and unique"
                    )
            if evidence_field in {"components", "rarity_evidence"} and not keys:
                add_error(
                    f"manifest.evidence_key_schema.{evidence_field}: "
                    "must not be empty"
                )
            if (
                evidence_field == "provenance"
                and noisy_or_provenance_required
                and not keys
            ):
                add_error(
                    "manifest.evidence_key_schema.provenance: must not be empty "
                    "for noisy_or"
                )
            expected_evidence_keys[evidence_field] = keys

    ranks_valid = True
    observed_provenance_keys: set[str] = set()
    for position, row in iter_jsonl_gzip(_SCORE_ARTIFACT):
        row_count = position
        if row is None:
            ranks_valid = False
            continue
        edge_id = row.get("edge_id")
        if isinstance(edge_id, bool) or not isinstance(edge_id, int):
            add_error(f"{_SCORE_ARTIFACT} row {position}: edge_id must be an integer")
            ranks_valid = False
            continue
        ledger_ids.append(edge_id)
        if isinstance(row.get("event_id"), str):
            ledger_event_ids.setdefault(edge_id, row["event_id"])
        if row.get("schema_version") != SCHEMA_VERSION:
            add_error(f"{_SCORE_ARTIFACT} row {position}: invalid schema_version")
        candidate = candidate_edges.get(edge_id)
        if candidate is not None:
            missing_identity_fields = [
                name for name in _EDGE_FIELDS if name not in row
            ]
            if missing_identity_fields:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: missing StoredEdge fields "
                    f"{missing_identity_fields}"
                )
            differing_fields = [
                name
                for index, name in enumerate(_EDGE_FIELDS)
                if name in row and row[name] != candidate[index]
            ]
            if differing_fields:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: identity differs from "
                    f"candidate artifact in {differing_fields}"
                )
        score_value = row.get("score")
        if (
            isinstance(score_value, bool)
            or not isinstance(score_value, (int, float))
            or not math.isfinite(float(score_value))
            or not 0.0 <= float(score_value) <= 1.0
        ):
            add_error(
                f"{_SCORE_ARTIFACT} edge {edge_id}: score must be finite [0, 1]"
            )
        else:
            ledger_scores.setdefault(edge_id, float(score_value))
        rank_value = row.get("rank")
        if (
            isinstance(rank_value, bool)
            or not isinstance(rank_value, int)
            or rank_value != position
        ):
            ranks_valid = False
        if row.get("score_semantics") != _SCORE_SEMANTICS:
            add_error(
                f"{_SCORE_ARTIFACT} edge {edge_id}: invalid score_semantics"
            )
        expected_is_poi = row.get("event_id") in declared_poi_ids
        if row.get("is_declared_poi") is not expected_is_poi:
            add_error(
                f"{_SCORE_ARTIFACT} edge {edge_id}: is_declared_poi must be "
                f"{expected_is_poi}"
            )

        evidence_values: dict[str, dict[str, object]] = {}
        for evidence_field in _EVIDENCE_FIELDS:
            try:
                values = _mapping_with_string_keys(
                    row.get(evidence_field),
                    label=(
                        f"{_SCORE_ARTIFACT} edge {edge_id} {evidence_field}"
                    ),
                )
            except ValueError as exc:
                add_error(str(exc))
                continue
            evidence_values[evidence_field] = values
            if evidence_required and evidence_field == "provenance":
                observed_provenance_keys.update(values)
            schema_is_required = evidence_required and (
                evidence_field != "provenance"
                or noisy_or_provenance_required
            )
            if schema_is_required:
                actual_keys = sorted(values)
                expected_keys = expected_evidence_keys.get(evidence_field, [])
                if actual_keys != expected_keys:
                    add_error(
                        f"{_SCORE_ARTIFACT} edge {edge_id}: "
                        f"{evidence_field} key schema mismatch; "
                        f"expected={expected_keys}, actual={actual_keys}"
                    )
        if noisy_or_provenance_required and "provenance" in evidence_values:
            try:
                _validate_noisy_or_provenance(
                    evidence_values["provenance"],
                    label=f"{_SCORE_ARTIFACT} edge {edge_id} provenance",
                )
                if all(
                    field_name in evidence_values
                    for field_name in _EVIDENCE_FIELDS
                ):
                    _validate_noisy_or_evidence_consistency(
                        score=score_value,
                        components=evidence_values["components"],
                        provenance=evidence_values["provenance"],
                        rarity_evidence=evidence_values["rarity_evidence"],
                        label=f"{_SCORE_ARTIFACT} edge {edge_id}",
                    )
            except ValueError as exc:
                add_error(str(exc))
        if local_order and edge_id in replayed_scores:
            expected_aggregate = replayed_scores[edge_id]
            if (
                isinstance(score_value, bool)
                or not isinstance(score_value, (int, float))
                or not math.isclose(
                    float(score_value),
                    expected_aggregate,
                    rel_tol=0.0,
                    abs_tol=1e-15,
                )
            ):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: noisy-OR aggregate "
                    "does not match POI-local contributions"
                )
            provenance_values = evidence_values.get("provenance", {})
            if provenance_values.get("support_count") != replayed_support[edge_id]:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: support_count does not "
                    "match POI-local contributions"
                )
            if (
                provenance_values.get("winner_poi_event_id")
                != replayed_winner_poi[edge_id]
            ):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: winner POI does not "
                    "match POI-local contributions"
                )
            winner_score_value = provenance_values.get("winner_local_score")
            if (
                isinstance(winner_score_value, bool)
                or not isinstance(winner_score_value, (int, float))
                or not math.isclose(
                    float(winner_score_value),
                    replayed_winner_score[edge_id],
                    rel_tol=0.0,
                    abs_tol=1e-15,
                )
            ):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: winner local score does "
                    "not match POI-local contributions"
                )

        decisions_value = row.get("decisions")
        if not isinstance(decisions_value, list):
            add_error(f"{_SCORE_ARTIFACT} edge {edge_id}: decisions must be a list")
            decisions_value = []
        decisions_by_budget: dict[str, list[dict[str, object]]] = {}
        for decision in decisions_value:
            if not isinstance(decision, dict):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: decision must be an object"
                )
                continue
            key = decision.get("budget_key")
            if not isinstance(key, str):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: decision budget_key "
                    "must be a string"
                )
                continue
            decisions_by_budget.setdefault(key, []).append(decision)
        for budget_key in budget_keys:
            matches = decisions_by_budget.get(budget_key, [])
            if not matches:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: missing decision for "
                    f"budget {budget_key}"
                )
                continue
            if len(matches) > 1:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: duplicate decision for "
                    f"budget {budget_key}"
                )
                continue
            decision = matches[0]
            kept = decision.get("kept")
            reasons = decision.get("reasons")
            if not isinstance(kept, bool):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}, budget {budget_key}: "
                    "kept must be boolean"
                )
            if not isinstance(reasons, list) or any(
                not isinstance(reason, str) or not reason.strip()
                for reason in reasons if isinstance(reasons, list)
            ):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}, budget {budget_key}: "
                    "reasons must be non-empty strings"
                )
                reasons = []
            if isinstance(reasons, list) and reasons != sorted(set(reasons)):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}, budget {budget_key}: "
                    "reasons must be sorted and unique"
                )
            if kept is True and not reasons:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}, budget {budget_key}: "
                    "kept decision requires non-empty reasons"
                )
            if kept is False and reasons:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}, budget {budget_key}: "
                    "unkept decision must not have reasons"
                )
        extra_budget_keys = sorted(set(decisions_by_budget) - set(budget_keys))
        if extra_budget_keys:
            add_error(
                f"{_SCORE_ARTIFACT} edge {edge_id}: unexpected decision budgets "
                f"{extra_budget_keys}"
            )

    if evidence_required and sorted(observed_provenance_keys) != (
        expected_evidence_keys.get("provenance", [])
    ):
        add_error(
            f"{_SCORE_ARTIFACT}: observed provenance key schema differs from manifest"
        )

    duplicate_ledger_ids = sorted(
        edge_id for edge_id, count in Counter(ledger_ids).items() if count > 1
    )
    if duplicate_ledger_ids:
        add_error(
            f"{_SCORE_ARTIFACT}: duplicate ledger edge IDs {duplicate_ledger_ids[:5]}"
        )
    if set(ledger_ids) != set(candidate_edge_ids):
        missing = sorted(set(candidate_edge_ids) - set(ledger_ids))
        extra = sorted(set(ledger_ids) - set(candidate_edge_ids))
        add_error(
            f"{_SCORE_ARTIFACT}: candidate edge identity set mismatch; "
            f"missing={missing[:5]}, extra={extra[:5]}"
        )
    if row_count != expected_count:
        add_error(
            f"ledger row count mismatch: rows={row_count}, manifest={expected_count}"
        )
    if manifest.get("ledger_row_count") != row_count:
        add_error(
            f"manifest.ledger_row_count: expected {row_count}, "
            f"got {manifest.get('ledger_row_count')!r}"
        )
    unique_ledger_ids = set(ledger_ids)
    if manifest.get("unique_edge_ids") != len(unique_ledger_ids):
        add_error(
            f"manifest.unique_edge_ids: expected {len(unique_ledger_ids)}, "
            f"got {manifest.get('unique_edge_ids')!r}"
        )
    if not ranks_valid:
        add_error(f"{_SCORE_ARTIFACT}: ranks must be consecutive from 1")
    if len(ledger_scores) == row_count and not duplicate_ledger_ids:
        expected_order = sorted(
            ledger_scores,
            key=lambda edge_id: (-ledger_scores[edge_id], edge_id),
        )
        if ledger_ids != expected_order:
            add_error(
                f"{_SCORE_ARTIFACT}: rows have invalid score sort order"
            )
        denominator = max(1, row_count - 1)
        for position, row in iter_jsonl_gzip(_SCORE_ARTIFACT):
            if row is None:
                continue
            expected_percentile = (
                (row_count - position) / denominator if row_count else 0.0
            )
            percentile = row.get("empirical_percentile")
            if (
                isinstance(percentile, bool)
                or not isinstance(percentile, (int, float))
                or not math.isfinite(float(percentile))
                or abs(float(percentile) - expected_percentile) > 1e-15
            ):
                add_error(
                    f"{_SCORE_ARTIFACT} edge {row.get('edge_id')}: "
                    "invalid empirical_percentile"
                )

    def finite_number(value: object) -> float | None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            return None
        return float(value)

    absolute_threshold = finite_number(manifest.get("absolute_threshold"))
    high_score_quantile = finite_number(manifest.get("positive_score_quantile"))
    if absolute_threshold is None or not 0.0 <= absolute_threshold <= 1.0:
        add_error("manifest.absolute_threshold: expected finite [0, 1]")
        absolute_threshold = None
    if high_score_quantile is None or not 0.0 < high_score_quantile <= 1.0:
        add_error("manifest.positive_score_quantile: expected finite (0, 1]")
        high_score_quantile = None

    high_path = output / _HIGH_SCORE_ARTIFACT
    high_document: dict[str, object] = {}
    if high_path.is_file():
        try:
            parsed_high = json.loads(high_path.read_text(encoding="utf-8"))
            if isinstance(parsed_high, dict):
                high_document = parsed_high
            else:
                add_error(f"{_HIGH_SCORE_ARTIFACT}: root must be an object")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            add_error(f"{_HIGH_SCORE_ARTIFACT}: invalid JSON ({exc})")
    else:
        add_error(f"{_HIGH_SCORE_ARTIFACT}: missing")
    if high_document:
        if high_document.get("schema_version") != SCHEMA_VERSION:
            add_error(f"{_HIGH_SCORE_ARTIFACT}: invalid schema_version")
        if high_document.get("score_semantics") != _SCORE_SEMANTICS:
            add_error(f"{_HIGH_SCORE_ARTIFACT}: invalid score_semantics")
        if high_document.get("tie_policy") != "include_all_scores_equal_to_cutoff":
            add_error(f"{_HIGH_SCORE_ARTIFACT}: invalid tie_policy")
        if high_document.get("interpretation") != (
            "high_importance_tail_not_detection_verdict"
        ):
            add_error(f"{_HIGH_SCORE_ARTIFACT}: invalid interpretation")

    scores_complete = (
        len(ledger_scores) == row_count
        and not duplicate_ledger_ids
        and set(ledger_scores) == set(candidate_edge_ids)
    )
    del candidate_edges
    del candidate_edge_ids
    if scores_complete and absolute_threshold is not None and high_score_quantile is not None:
        quantile_cutoff = _positive_quantile(
            list(ledger_scores.values()), high_score_quantile
        )
        effective_cutoff = max(absolute_threshold, quantile_cutoff)
        expected_high_ids = [
            edge_id
            for edge_id in sorted(
                ledger_scores,
                key=lambda item: (-ledger_scores[item], item),
            )
            if ledger_scores[edge_id] > 0.0
            and ledger_scores[edge_id] >= effective_cutoff
        ]
        expected_positive_count = sum(score > 0.0 for score in ledger_scores.values())
        numeric_expectations = (
            ("quantile_cutoff", quantile_cutoff),
            ("effective_cutoff", effective_cutoff),
        )
        for field_name, expected in numeric_expectations:
            manifest_value = finite_number(manifest.get(field_name))
            if manifest_value is None or abs(manifest_value - expected) > 1e-15:
                add_error(
                    f"manifest.{field_name}: expected {expected}, "
                    f"got {manifest.get(field_name)!r}"
                )
            high_value = finite_number(high_document.get(field_name))
            if high_value is None or abs(high_value - expected) > 1e-15:
                add_error(
                    f"{_HIGH_SCORE_ARTIFACT}.{field_name}: expected {expected}, "
                    f"got {high_document.get(field_name)!r}"
                )
        for field_name, expected in (
            ("absolute_threshold", absolute_threshold),
            ("positive_score_quantile", high_score_quantile),
        ):
            high_value = finite_number(high_document.get(field_name))
            if high_value is None or abs(high_value - expected) > 1e-15:
                add_error(
                    f"{_HIGH_SCORE_ARTIFACT}.{field_name}: expected {expected}, "
                    f"got {high_document.get(field_name)!r}"
                )
        if manifest.get("positive_score_count") != expected_positive_count:
            add_error(
                f"manifest.positive_score_count: expected {expected_positive_count}, "
                f"got {manifest.get('positive_score_count')!r}"
            )
        if manifest.get("high_score_count") != len(expected_high_ids):
            add_error(
                f"manifest.high_score_count: expected {len(expected_high_ids)}, "
                f"got {manifest.get('high_score_count')!r}"
            )
        expected_high_id_set = set(expected_high_ids)
        expected_non_poi_high_count = sum(
            1
            for edge_id in expected_high_ids
            if ledger_event_ids.get(edge_id) not in declared_poi_ids
        )
        for container_name, container in (
            ("manifest", manifest),
            (_HIGH_SCORE_ARTIFACT, high_document),
        ):
            if container.get("non_poi_high_score_count") != (
                expected_non_poi_high_count
            ):
                add_error(
                    f"{container_name}.non_poi_high_score_count: expected "
                    f"{expected_non_poi_high_count}, got "
                    f"{container.get('non_poi_high_score_count')!r}"
                )
        if high_document.get("declared_poi_count") != len(declared_poi_ids):
            add_error(
                f"{_HIGH_SCORE_ARTIFACT}.declared_poi_count: expected "
                f"{len(declared_poi_ids)}"
            )

        high_edges_value = high_document.get("edges")
        if not isinstance(high_edges_value, list):
            add_error(f"{_HIGH_SCORE_ARTIFACT}.edges: expected a list")
            high_edges: list[dict[str, object]] = []
        else:
            high_edges = [
                edge for edge in high_edges_value if isinstance(edge, dict)
            ]
            if len(high_edges) != len(high_edges_value):
                add_error(f"{_HIGH_SCORE_ARTIFACT}.edges: every entry must be an object")
        high_ids = [edge.get("edge_id") for edge in high_edges]
        valid_high_ids = [
            edge_id for edge_id in high_ids
            if isinstance(edge_id, int) and not isinstance(edge_id, bool)
        ]
        if len(valid_high_ids) != len(high_ids):
            add_error(
                f"{_HIGH_SCORE_ARTIFACT}: every edge_id must be an integer"
            )
        if high_ids != expected_high_ids:
            add_error(
                f"{_HIGH_SCORE_ARTIFACT}: high-score edge set/order does not "
                "match the recomputed threshold including ties"
            )
        if len(set(valid_high_ids)) != len(valid_high_ids):
            add_error(f"{_HIGH_SCORE_ARTIFACT}: duplicate high-score edge IDs")
        projection_fields = (
            "edge_id",
            "event_id",
            "score",
            "rank",
            "is_declared_poi",
            "relation",
            "timestamp_ns",
            "components",
            "rarity_evidence",
            "provenance",
            "decisions",
        )
        high_edges_by_id = {
            edge["edge_id"]: edge
            for edge in high_edges
            if isinstance(edge.get("edge_id"), int)
            and not isinstance(edge.get("edge_id"), bool)
        }
        for _, ledger_row in iter_jsonl_gzip(_SCORE_ARTIFACT):
            if ledger_row is None:
                continue
            edge_id = ledger_row.get("edge_id")
            if not isinstance(edge_id, int) or isinstance(edge_id, bool):
                continue
            expected_high = edge_id in expected_high_id_set
            if ledger_row.get("high_score") is not expected_high:
                add_error(
                    f"{_SCORE_ARTIFACT} edge {edge_id}: high_score flag "
                    f"must be {expected_high}"
                )
            high_edge = high_edges_by_id.get(edge_id)
            if high_edge is not None:
                differing = [
                    name for name in projection_fields
                    if high_edge.get(name) != ledger_row.get(name)
                ]
                if differing:
                    add_error(
                        f"{_HIGH_SCORE_ARTIFACT} edge {edge_id}: projection differs "
                        f"from ledger in {differing}"
                    )

    return {
        "valid": not errors,
        "hash_mismatches": sorted(set(mismatches)),
        "validation_errors": errors,
        "row_count": row_count,
        "unique_edge_ids": len(set(ledger_ids)),
        "expected_edge_count": expected_count,
    }


__all__ = [
    "SCHEMA_VERSION",
    "candidate_graph_digest",
    "verify_score_ledger",
    "write_score_ledger",
]
