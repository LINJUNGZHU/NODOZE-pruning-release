from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.score_ledger import (
    candidate_graph_digest,
    score_map_digest,
    verify_score_ledger,
    write_score_ledger,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_ps_rdp_sweep.py"
CONTEXT_DIGEST = "c" * 64


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _candidate_graph() -> Neighborhood:
    nodes = {
        node_id: NodeRecord(node_id, "subject", node_id)
        for node_id in ("a", "b", "c", "d")
    }
    edges = [
        StoredEdge(1, "poi-1", "a", "b", "EVENT_WRITE", 10, "h", "subject", "subject"),
        StoredEdge(2, "bridge", "b", "c", "EVENT_WRITE", 20, "h", "subject", "subject"),
        StoredEdge(3, "poi-2", "c", "d", "EVENT_WRITE", 30, "h", "subject", "subject"),
    ]
    return Neighborhood(nodes=nodes, edges=edges)


def _write_ledger(
    ledger_dir: Path,
    graph: Neighborhood,
    local_contributions: dict[str, dict[int, float]],
    reasons: str,
    ordered_sequences: list[list[str]],
) -> dict[str, object]:
    edge_ids = [edge.edge_id for edge in graph.edges]
    local_digests = {
        poi: score_map_digest(
            {edge_id: values.get(edge_id, 0.0) for edge_id in edge_ids}
        )
        for poi, values in local_contributions.items()
    }
    scores: dict[int, float] = {}
    provenance: dict[int, dict[str, object]] = {}
    for edge_id in edge_ids:
        aggregate = 0.0
        values = {
            poi: local_contributions[poi].get(edge_id, 0.0)
            for poi in local_contributions
        }
        for local_score in values.values():
            aggregate = aggregate + (1.0 - aggregate) * local_score
        scores[edge_id] = aggregate
        winner_score = max(values.values())
        winner_poi = min(
            poi for poi, local_score in values.items()
            if local_score == winner_score
        )
        provenance[edge_id] = {
            "aggregation": "noisy_or",
            "support_count": sum(value > 0.0 for value in values.values()),
            "winner_poi_event_id": winner_poi,
            "winner_local_score": winner_score,
        }
    manifest = write_score_ledger(
        ledger_dir,
        graph=graph,
        scores=scores,
        components={},
        rarity_evidence={},
        decisions={"1": {edge.edge_id: (reasons,) for edge in graph.edges}},
        score_provenance=provenance,
        local_score_contributions=local_contributions,
        context={
            "candidate_graph_sha256": candidate_graph_digest(graph),
            "prefix_score_context_sha256": CONTEXT_DIGEST,
            "local_score_digests": local_digests,
            "poi_event_ids": [
                event_id for sequence in ordered_sequences for event_id in sequence
            ],
            "online_uses_groundtruth": False,
            "pruning_parameters": {
                "keep_ratios": [1.0],
                "budget_rounding_policy": "floor_hard_cap_minimum_one",
                "certificate_topology_policy": "causal_path_cover",
                "ordered_poi_event_sequences": ordered_sequences,
            },
        },
    )
    assert verify_score_ledger(ledger_dir)["valid"] is True
    return manifest


def _make_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    graph = _candidate_graph()
    reference_path = run_dir / "day-x" / "fixed-reference.json"
    _write_json(
        reference_path,
        {
            "name": "fixed reference",
            "seed_uuids": [],
            "seed_event_ids": [],
            "seed_event_groups": [],
            "attack_event_ids": ["poi-1", "bridge", "poi-2"],
            "attack_node_uuids": [],
            "attack_paths": [["poi-1"], ["bridge", "poi-2"]],
            "metadata": {"online_uses_groundtruth": False},
        },
    )
    contribution_versions = (
        {"poi-1": {1: 0.5, 2: 0.2, 3: 0.1}},
        {
            "poi-1": {1: 0.5, 2: 0.2, 3: 0.1},
            "poi-2": {2: 0.25, 3: 7 / 9},
        },
    )
    rows: list[dict[str, object]] = []

    for poi_count in (1, 2):
        selected = ["poi-1", "poi-2"][:poi_count]
        prefix_dir = run_dir / "day-x" / f"poi-prefix-{poi_count}"
        ledger_dir = prefix_dir / "score-ledger"
        manifest = _write_ledger(
            ledger_dir,
            graph,
            contribution_versions[poi_count - 1],
            "causal_path_cover",
            [selected],
        )
        local_digests = manifest["context"]["local_score_digests"]
        first = poi_count == 1
        path_metrics = {
            "reference_paths": 2,
            "retained_reference_paths": 2,
            "complete_path_retention": 1.0,
            "selected_terminal_paths": 1 if first else 2,
            "retained_selected_terminal_paths": 1 if first else 2,
            "selected_terminal_path_retention": 1.0,
            "unselected_terminal_paths": 1 if first else 0,
            "retained_unselected_terminal_paths": 1 if first else 0,
            "unselected_terminal_path_retention": 1.0 if first else None,
        }
        result = {
            "requested_keep_ratio": 1.0,
            "actual_keep_ratio": 1.0,
            "budget_edges": 3,
            "budget_rounding_policy": "floor_hard_cap_minimum_one",
            "minimum_required_edges": 1 if first else 3,
            "budget_feasible": True,
            "budget_overflow_edges": 0,
            "stage_pairs": 0 if first else 1,
            "connected_stage_pairs": 0 if first else 1,
            "retained_stage_pairs": 0 if first else 1,
            "certificate_poi_edges": poi_count,
            "certificate_retained_poi_edges": poi_count,
            "path_certificate_valid": True,
            "path_certificate_status": "poi_only" if first else "valid",
            "strict_multistage_certificate_valid": not first,
            "causal_path_cover_certificate_valid": True,
            "certificate_topology": "singleton" if first else "chain",
            "certificate_branch_count": 1,
            "candidate_disconnected_stage_pairs": [],
            "stage_path_witnesses": [] if first else [[1, 3, [2]]],
            "previous_candidate_edges": 0 if first else 3,
            "retained_previous_edges": 0 if first else 3,
            "added_edges": 0,
            "removed_previous_edges": 0,
            "declared_allowed_removed_previous_edges": 0,
            "allowed_removed_previous_edges": 0,
            "budget_contraction_edges": 0,
            "atomicity_churn_slack_edges": 0,
            "churn_bound_satisfied": True,
            "churn_constraint_status": "not_applicable" if first else "satisfied",
            "prefix_jaccard": None if first else 1.0,
            "unused_budget_edges": 0,
            "zero_score_fill_stopped": False,
            "kept_event_ids": ["poi-1", "bridge", "poi-2"],
        }
        report = {
            "incomplete": False,
            "original_edges": 3,
            "original_nodes": 4,
            "poi_local_scoring": {
                "policy": "immutable_per_poi_scores_aggregated_by_noisy_or",
                "local_score_digests": local_digests,
                "context_digest": CONTEXT_DIGEST,
                "prefix_monotonicity_guarantee": True,
            },
            "poi_prefix_experiment": {
                "scenario": "x",
                "poi_count": poi_count,
                "full_poi_count": 2,
                "selected_poi_event_ids": selected,
                "selected_poi_event_sequences": [selected],
                "certificate_topology_policy": "causal_path_cover",
                "fixed_reference_file": str(reference_path.resolve()),
                "online_uses_groundtruth": False,
                "path_metrics": path_metrics,
            },
            "ordered_poi_event_sequences": [selected],
            "paper_main_results": {
                "available": True,
                "rows": [
                    {
                        "attack_event_recall": 1.0,
                        "complete_path_retention": 1.0,
                    }
                ],
            },
            "score_ledger": {
                "directory": str(ledger_dir.resolve()),
                "manifest": str((ledger_dir / "manifest.json").resolve()),
                "verification": verify_score_ledger(ledger_dir),
                **manifest,
            },
            "results": [result],
        }
        result_path = prefix_dir / "result.json"
        _write_json(
            prefix_dir / "input.json",
            {
                "name": f"prefix-{poi_count}",
                "seed_uuids": [],
                "seed_event_ids": selected,
                "seed_event_groups": [
                    {"group_id": "main", "seed_event_ids": selected}
                ],
                "attack_event_ids": [],
                "attack_node_uuids": [],
                "attack_paths": [],
                "metadata": {
                    "certificate_topology_policy": "causal_path_cover"
                },
            },
        )
        _write_json(result_path, report)
        rows.append(
            {
                "scenario": "x",
                "poi_count": poi_count,
                "full_poi_count": 2,
                "selected_poi_event_ids": selected,
                "candidate_events": 3,
                "candidate_nodes": 4,
                "kept_events": 3,
                "requested_keep_ratio": 1.0,
                "actual_keep_ratio": 1.0,
                "attack_event_recall": 1.0,
                **path_metrics,
                "marginal_restored_paths": 2 if first else 0,
                "path_certificate_valid": True,
                "path_certificate_status": "poi_only" if first else "valid",
                "strict_multistage_certificate_valid": not first,
                "causal_path_cover_certificate_valid": True,
                "certificate_topology": "singleton" if first else "chain",
                "certificate_branch_count": 1,
                "candidate_disconnected_stage_pairs": [],
                "budget_feasible": True,
                "budget_rounding_policy": "floor_hard_cap_minimum_one",
                "budget_overflow_edges": 0,
                "stage_pairs": 0 if first else 1,
                "connected_stage_pairs": 0 if first else 1,
                "retained_stage_pairs": 0 if first else 1,
                "prefix_jaccard": None if first else 1.0,
                "added_edges": 0,
                "removed_previous_edges": 0,
                "declared_allowed_removed_previous_edges": 0,
                "allowed_removed_previous_edges": 0,
                "budget_contraction_edges": 0,
                "atomicity_churn_slack_edges": 0,
                "churn_bound_satisfied": True,
                "churn_constraint_status": "not_applicable" if first else "satisfied",
                "score_monotonicity_violations": 0,
                "local_score_digest_violations": 0,
                "unused_budget_edges": 0,
                "zero_score_fill_stopped": False,
                "score_ledger_manifest": str((ledger_dir / "manifest.json").resolve()),
                "score_ledger_valid": True,
                "result_file": str(result_path.resolve()),
                "input_file": str((prefix_dir / "input.json").resolve()),
            }
        )

    _write_json(run_dir / "process-status.json", {"status": "complete", "exit_code": 0})
    _write_json(run_dir / "progress.json", {"stage": "complete", "incomplete": False})
    _write_json(
        run_dir / "summary.json",
        {
            "schema_version": "cadets-e3-poi-prefix-sweep-v3",
            "online_uses_groundtruth": False,
            "rows": rows,
            "days": [
                {
                    "scenario": "x",
                    "full_poi_count": 2,
                    "minimum_sufficient_poi_count": 1,
                    "earliest_legal_poi_count_at_max_path_retention": 1,
                    "minimum_legal_poi_count_for_full_path_retention": 1,
                    "minimum_observed_poi_count_for_full_path_retention": 1,
                    "maximum_retained_paths": 2,
                    "maximum_observed_retained_paths": 2,
                    "total_reference_paths": 2,
                    "maximum_complete_path_retention": 1.0,
                    "fully_restored": True,
                }
            ],
            "cross_day": {
                "completed_prefix_runs": 2,
                "expected_prefix_runs": 2,
                "minimum_total_pois": 1,
                "mean_minimum_poi_fraction": 0.5,
                "macro_maximum_complete_path_retention": 1.0,
                "macro_unselected_path_retention_at_minimum": 1.0,
                "unselected_path_macro_contributing_days": 1,
                "score_monotonicity_violations": 0,
                "local_score_digest_violations": 0,
                "minimum_consecutive_prefix_jaccard": 1.0,
                "all_churn_bounds_satisfied": True,
                "complete_score_ledgers": 2,
            },
        },
    )
    return run_dir


def _run_validator(run_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(run_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_valid_two_prefix_run_passes(tmp_path: Path) -> None:
    completed = _run_validator(_make_run(tmp_path))

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "atomic_relaxations": 0,
        "prefixes": 2,
        "scenarios": 1,
        "v2_ledgers": 2,
        "valid": True,
    }


def test_valid_explicit_two_branch_forest_passes(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    prefix_dir = run_dir / "day-x" / "poi-prefix-2"
    result_path = prefix_dir / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    sequences = [["poi-1"], ["poi-2"]]
    ledger_dir = prefix_dir / "score-ledger"
    manifest = _write_ledger(
        ledger_dir,
        _candidate_graph(),
        {
            "poi-1": {1: 0.5, 2: 0.2, 3: 0.1},
            "poi-2": {2: 0.25, 3: 7 / 9},
        },
        "causal_path_cover",
        sequences,
    )
    result = report["results"][0]
    result.update(
        {
            "stage_pairs": 0,
            "connected_stage_pairs": 0,
            "retained_stage_pairs": 0,
            "path_certificate_status": "valid_forest",
            "strict_multistage_certificate_valid": False,
            "causal_path_cover_certificate_valid": True,
            "certificate_topology": "forest",
            "certificate_branch_count": 2,
            "candidate_disconnected_stage_pairs": [],
            "stage_path_witnesses": [],
        }
    )
    report["ordered_poi_event_sequences"] = sequences
    report["poi_prefix_experiment"]["selected_poi_event_sequences"] = sequences
    report["poi_prefix_experiment"]["certificate_topology_policy"] = (
        "causal_path_cover"
    )
    report["score_ledger"] = {
        "directory": str(ledger_dir.resolve()),
        "manifest": str((ledger_dir / "manifest.json").resolve()),
        "verification": verify_score_ledger(ledger_dir),
        **manifest,
    }
    _write_json(result_path, report)
    _write_json(
        prefix_dir / "input.json",
        {
            "name": "prefix-2 forest",
            "seed_uuids": [],
            "seed_event_ids": ["poi-1", "poi-2"],
            "seed_event_groups": [
                {"group_id": "main", "seed_event_ids": ["poi-1"]},
                {"group_id": "side", "seed_event_ids": ["poi-2"]},
            ],
            "attack_event_ids": [],
            "attack_node_uuids": [],
            "attack_paths": [],
            "metadata": {
                "certificate_topology_policy": (
                    "causal_path_cover"
                )
            },
        },
    )
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["rows"][1].update(
        {
            "stage_pairs": 0,
            "connected_stage_pairs": 0,
            "retained_stage_pairs": 0,
            "path_certificate_status": "valid_forest",
            "strict_multistage_certificate_valid": False,
            "causal_path_cover_certificate_valid": True,
            "certificate_topology": "forest",
            "certificate_branch_count": 2,
            "candidate_disconnected_stage_pairs": [],
        }
    )
    _write_json(summary_path, summary)

    completed = _run_validator(run_dir)

    assert completed.returncode == 0, completed.stderr


def test_fails_closed_on_forest_branch_count_tampering(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    result_path = run_dir / "day-x" / "poi-prefix-2" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    report["results"][0]["certificate_branch_count"] = 2
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "branch count" in completed.stderr.lower()


def test_fails_closed_when_online_input_contains_attack_path(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    input_path = run_dir / "day-x" / "poi-prefix-2" / "input.json"
    document = json.loads(input_path.read_text(encoding="utf-8"))
    document["attack_paths"] = [["bridge"]]
    _write_json(input_path, document)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "online pruning input must be empty" in completed.stderr.lower()


def test_fails_closed_on_report_input_path_cover_mismatch(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    result_path = run_dir / "day-x" / "poi-prefix-2" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    report["ordered_poi_event_sequences"] = [["poi-1"], ["poi-2"]]
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "report path cover differs" in completed.stderr.lower()


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("budget_overflow_edges", 1, "budget"),
        ("churn_bound_satisfied", False, "churn"),
    ],
)
def test_fails_closed_on_result_contract_violation(
    tmp_path: Path, field: str, value: object, expected_error: str
) -> None:
    run_dir = _make_run(tmp_path)
    result_path = run_dir / "day-x" / "poi-prefix-2" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    report["results"][0][field] = value
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert expected_error in completed.stderr.lower()


def test_fails_closed_on_prior_local_score_rewrite(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    graph = _candidate_graph()
    ledger_dir = run_dir / "day-x" / "poi-prefix-2" / "score-ledger"
    manifest = _write_ledger(
        ledger_dir,
        graph,
        {
            "poi-1": {1: 0.49, 2: 0.2, 3: 0.1},
            "poi-2": {2: 0.25, 3: 7 / 9},
        },
        "causal_path_cover",
        [["poi-1", "poi-2"]],
    )
    result_path = run_dir / "day-x" / "poi-prefix-2" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    report["score_ledger"] = {
        "directory": str(ledger_dir.resolve()),
        "manifest": str((ledger_dir / "manifest.json").resolve()),
        "verification": verify_score_ledger(ledger_dir),
        **manifest,
    }
    report["poi_local_scoring"]["local_score_digests"] = manifest["context"][
        "local_score_digests"
    ]
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "local score digests changed" in completed.stderr.lower()


def test_fails_closed_on_invalid_stage_witness(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    result_path = run_dir / "day-x" / "poi-prefix-2" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    report["results"][0]["stage_path_witnesses"] = [[1, 3, []]]
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "witness" in completed.stderr.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retained_reference_paths", 1),
        ("retained_selected_terminal_paths", 0),
        ("retained_unselected_terminal_paths", 0),
        ("attack_event_recall", 0.5),
        ("marginal_restored_paths", 1),
    ],
)
def test_fails_closed_on_fixed_reference_row_metric_tampering(
    tmp_path: Path, field: str, value: object
) -> None:
    run_dir = _make_run(tmp_path)
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["rows"][0][field] = value
    _write_json(summary_path, summary)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert field.lower() in completed.stderr.lower()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("path_metrics", "complete_path_retention", 0.5),
        ("paper", "attack_event_recall", 0.5),
        ("paper", "complete_path_retention", 0.5),
    ],
)
def test_fails_closed_on_fixed_reference_report_metric_tampering(
    tmp_path: Path, section: str, field: str, value: object
) -> None:
    run_dir = _make_run(tmp_path)
    result_path = run_dir / "day-x" / "poi-prefix-1" / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    if section == "path_metrics":
        report["poi_prefix_experiment"]["path_metrics"][field] = value
    else:
        report["paper_main_results"]["rows"][0][field] = value
    _write_json(result_path, report)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert field.lower() in completed.stderr.lower()


def test_fails_closed_when_fixed_reference_changes_after_scoring(
    tmp_path: Path,
) -> None:
    run_dir = _make_run(tmp_path)
    reference_path = run_dir / "day-x" / "fixed-reference.json"
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    reference["attack_paths"].append(["bridge"])
    _write_json(reference_path, reference)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert "reference_paths" in completed.stderr.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("minimum_sufficient_poi_count", 2),
        ("earliest_legal_poi_count_at_max_path_retention", 2),
        ("maximum_retained_paths", 1),
        ("fully_restored", False),
    ],
)
def test_fails_closed_on_day_summary_tampering(
    tmp_path: Path, field: str, value: object
) -> None:
    run_dir = _make_run(tmp_path)
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["days"][0][field] = value
    _write_json(summary_path, summary)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert field.lower() in completed.stderr.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("minimum_total_pois", 2),
        ("mean_minimum_poi_fraction", 1.0),
        ("macro_maximum_complete_path_retention", 0.5),
        ("macro_unselected_path_retention_at_minimum", 0.0),
        ("unselected_path_macro_contributing_days", 0),
    ],
)
def test_fails_closed_on_cross_day_fixed_reference_tampering(
    tmp_path: Path, field: str, value: object
) -> None:
    run_dir = _make_run(tmp_path)
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["cross_day"][field] = value
    _write_json(summary_path, summary)

    completed = _run_validator(run_dir)

    assert completed.returncode != 0
    assert field.lower() in completed.stderr.lower()


def test_help_is_available() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "run_dir" in completed.stdout
