import json

import pytest

import tc_pruning.evaluation as evaluation_module
import tc_pruning.poi_prefix as poi_prefix_module
from tc_pruning.causal import CausalSearchConfig
from tc_pruning.cli import main
from tc_pruning.evaluation import AttackAnnotations, run_experiment
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.poi_prefix import (
    POIPrefixScenario,
    build_prefix_annotations,
    build_report_reference,
    compute_prefix_path_metrics,
    load_poi_prefix_spec,
    require_complete_prefix_report,
    resolve_poi_timeline,
    select_minimum_sufficient,
)
from tc_pruning.store import ProvenanceStore
from tc_pruning.score_ledger import verify_score_ledger


def _scenario(tmp_path, event_ids, *, start=0, end=100):
    poi_file = tmp_path / "pois.json"
    poi_file.write_text(json.dumps({"event_ids": event_ids}), encoding="utf-8")
    return POIPrefixScenario(
        code="06",
        poi_file=poi_file,
        base_groundtruth_file=tmp_path / "base.json",
        window_start_ns=start,
        window_end_ns=end,
    )


def test_poi_timeline_requires_database_events_in_declared_time_order(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c")
            ]
            + [
                EdgeRecord("first", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("second", "b", "c", "EVENT_SENDTO", 20, "h"),
            ]
        )

        timeline = resolve_poi_timeline(
            store, _scenario(tmp_path, ["first", "second"])
        )
        assert [edge.event_id for edge in timeline] == ["first", "second"]

        with pytest.raises(ValueError, match="chronological"):
            resolve_poi_timeline(
                store, _scenario(tmp_path, ["second", "first"])
            )
        with pytest.raises(ValueError, match="duplicate"):
            resolve_poi_timeline(
                store, _scenario(tmp_path, ["first", "first"])
            )
        with pytest.raises(ValueError, match="missing"):
            resolve_poi_timeline(
                store, _scenario(tmp_path, ["first", "absent"])
            )


def test_prefix_annotations_change_only_seeds_not_fixed_window(tmp_path):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["p1", "p2"], start=5, end=25)
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c")
            ]
            + [
                EdgeRecord("p1", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("p2", "b", "c", "EVENT_SENDTO", 20, "h"),
            ]
        )
        timeline = resolve_poi_timeline(store, scenario)

    first = build_prefix_annotations(scenario, timeline, 1)
    second = build_prefix_annotations(scenario, timeline, 2)

    assert first.seed_event_sequences == [("p1",)]
    assert second.seed_event_sequences == [("p1", "p2")]
    assert first.seed_event_ids == {"p1"}
    assert second.seed_event_ids == {"p1", "p2"}
    assert first.investigation_windows == {"ubc-06-prefix-1": (5, 25)}
    assert second.investigation_windows == {"ubc-06-prefix-2": (5, 25)}


def test_prefix_annotations_preserve_report_declared_causal_path_cover(tmp_path):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["p1", "p2", "branch"], start=5, end=40)
    scenario.poi_file.write_text(
        json.dumps(
            {
                "event_ids": ["p1", "p2", "branch"],
                "certificate_paths": [
                    {"path_id": "main", "event_ids": ["p1", "p2"]},
                    {"path_id": "branch", "event_ids": ["branch"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in "abcd"]
            + [
                EdgeRecord("p1", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("p2", "b", "c", "EVENT_WRITE", 20, "h"),
                EdgeRecord("branch", "c", "d", "EVENT_SENDTO", 30, "h"),
            ]
        )
        timeline = resolve_poi_timeline(store, scenario)

    second = build_prefix_annotations(scenario, timeline, 2)
    third = build_prefix_annotations(scenario, timeline, 3)

    assert second.seed_event_sequences == [("p1", "p2")]
    assert third.seed_event_sequences == [("p1", "p2"), ("branch",)]
    assert third.seed_event_groups == [{"p1", "p2"}, {"branch"}]
    assert third.metadata["certificate_topology_policy"] == (
        "causal_path_cover"
    )
    assert set(third.investigation_windows.values()) == {(5, 40)}


@pytest.mark.parametrize(
    "certificate_paths, message",
    [
        ([{"path_id": "main", "event_ids": ["p1"]}], "partition"),
        (
            [
                {"path_id": "one", "event_ids": ["p1", "p2"]},
                {"path_id": "two", "event_ids": ["p2"]},
            ],
            "exactly once",
        ),
    ],
)
def test_poi_manifest_rejects_invalid_certificate_path_cover(
    tmp_path, certificate_paths, message
):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["p1", "p2"], start=0, end=30)
    scenario.poi_file.write_text(
        json.dumps(
            {
                "event_ids": ["p1", "p2"],
                "certificate_paths": certificate_paths,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=message):
        with ProvenanceStore(database) as store:
            store.ingest(
                [NodeRecord(name, "process", name, "h") for name in "abc"]
                + [
                    EdgeRecord("p1", "a", "b", "EVENT_WRITE", 10, "h"),
                    EdgeRecord("p2", "b", "c", "EVENT_WRITE", 20, "h"),
                ]
            )
            timeline = resolve_poi_timeline(store, scenario)
            build_prefix_annotations(scenario, timeline, 2)


def test_reference_paths_backtrack_through_core_and_end_at_report_poi(tmp_path):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["poi"], start=0, end=40)
    base = AttackAnnotations(
        name="UBC core",
        seed_uuids=set(),
        attack_event_ids={"core-1", "core-2"},
        attack_node_uuids={"a", "b", "c"},
    )
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c", "socket")
            ]
            + [
                EdgeRecord("core-1", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("core-2", "b", "c", "EVENT_WRITE", 20, "h"),
                EdgeRecord("poi", "c", "socket", "EVENT_SENDTO", 30, "h"),
            ]
        )
        timeline = resolve_poi_timeline(store, scenario)
        reference = build_report_reference(store, scenario, base, timeline)

    assert reference.attack_paths == [("core-1", "core-2", "poi")]
    assert reference.attack_event_ids == {"core-1", "core-2", "poi"}
    assert reference.metadata["path_quality"] == (
        "report_poi_anchored_paths_derived_within_manually_reviewed_ubc_core"
    )
    assert reference.metadata["terminal_poi_event_ids"] == ["poi"]


@pytest.mark.parametrize(
    ("core_relation", "core_src", "core_dst", "poi_relation", "poi_src", "poi_dst"),
    [
        ("EVENT_WRITE", "writer", "object", "EVENT_EXECUTE", "child", "object"),
        ("EVENT_WRITE", "writer", "object", "EVENT_READ", "object", "child"),
        ("EVENT_READ", "object", "parent", "EVENT_FORK", "parent", "child"),
    ],
)
def test_reference_paths_use_information_flow_source_for_special_poi_relations(
    tmp_path,
    core_relation,
    core_src,
    core_dst,
    poi_relation,
    poi_src,
    poi_dst,
):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["poi"], start=0, end=40)
    node_names = {core_src, core_dst, poi_src, poi_dst}
    base = AttackAnnotations(
        name="UBC core",
        seed_uuids=set(),
        attack_event_ids={"core"},
        attack_node_uuids=node_names,
    )
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in node_names]
            + [
                EdgeRecord("core", core_src, core_dst, core_relation, 10, "h"),
                EdgeRecord("poi", poi_src, poi_dst, poi_relation, 20, "h"),
            ]
        )
        timeline = resolve_poi_timeline(store, scenario)
        reference = build_report_reference(store, scenario, base, timeline)

    assert reference.attack_paths == [("core", "poi")]


def test_reference_classifies_terminal_only_path_as_temporal_core_entry(tmp_path):
    database = tmp_path / "tc.db"
    scenario = _scenario(tmp_path, ["poi"], start=0, end=40)
    base = AttackAnnotations(
        name="UBC core",
        seed_uuids=set(),
        attack_event_ids=set(),
        attack_node_uuids={"entry"},
    )
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord("entry", "process", "entry", "h"),
                NodeRecord("socket", "socket", "socket", "h"),
                EdgeRecord("poi", "entry", "socket", "EVENT_SENDTO", 20, "h"),
            ]
        )
        timeline = resolve_poi_timeline(store, scenario)
        reference = build_report_reference(store, scenario, base, timeline)

    assert reference.attack_paths == [("poi",)]
    assert reference.metadata["path_boundaries"] == [
        {
            "terminal_poi_event_id": "poi",
            "boundary_kind": "temporal_core_entry",
            "entry_node_uuid": "entry",
            "core_event_count": 0,
        }
    ]


def test_path_metrics_separate_seeded_and_unseeded_terminal_paths():
    paths = [
        ("a", "poi-1"),
        ("b", "c", "poi-2"),
        ("d", "poi-3"),
    ]

    metrics = compute_prefix_path_metrics(
        paths,
        kept_event_ids={"a", "poi-1", "b", "c", "poi-2"},
        selected_poi_event_ids={"poi-1"},
    )

    assert metrics == {
        "reference_paths": 3,
        "retained_reference_paths": 2,
        "complete_path_retention": pytest.approx(2 / 3),
        "selected_terminal_paths": 1,
        "retained_selected_terminal_paths": 1,
        "selected_terminal_path_retention": 1.0,
        "unselected_terminal_paths": 2,
        "retained_unselected_terminal_paths": 1,
        "unselected_terminal_path_retention": 0.5,
    }

    all_seeded = compute_prefix_path_metrics(
        [("a", "poi-1")], {"a", "poi-1"}, {"poi-1"}
    )
    assert all_seeded["unselected_terminal_path_retention"] is None


def test_minimum_sufficient_prefix_is_first_valid_row_at_curve_maximum():
    rows = [
        {
            "poi_count": 1,
            "retained_reference_paths": 2,
            "path_certificate_valid": True,
            "budget_feasible": True,
        },
        {
            "poi_count": 2,
            "retained_reference_paths": 4,
            "path_certificate_valid": False,
            "budget_feasible": True,
        },
        {
            "poi_count": 3,
            "retained_reference_paths": 4,
            "path_certificate_valid": True,
            "budget_feasible": True,
        },
        {
            "poi_count": 4,
            "retained_reference_paths": 4,
            "path_certificate_valid": True,
            "budget_feasible": True,
        },
    ]

    chosen = select_minimum_sufficient(rows, total_paths=5)

    assert chosen == {
        "minimum_sufficient_poi_count": None,
        "earliest_legal_poi_count_at_max_path_retention": 3,
        "minimum_legal_poi_count_for_full_path_retention": None,
        "minimum_observed_poi_count_for_full_path_retention": None,
        "maximum_retained_paths": 4,
        "maximum_observed_retained_paths": 4,
        "total_reference_paths": 5,
        "maximum_complete_path_retention": 0.8,
        "fully_restored": False,
    }


def test_minimum_sufficient_ignores_higher_invalid_observed_result():
    rows = [
        {
            "poi_count": 1,
            "retained_reference_paths": 4,
            "path_certificate_valid": True,
            "budget_feasible": True,
        },
        {
            "poi_count": 2,
            "retained_reference_paths": 5,
            "path_certificate_valid": False,
            "budget_feasible": True,
        },
    ]

    chosen = select_minimum_sufficient(rows, total_paths=5)

    assert chosen["minimum_sufficient_poi_count"] is None
    assert chosen["earliest_legal_poi_count_at_max_path_retention"] == 1
    assert chosen["minimum_legal_poi_count_for_full_path_retention"] is None
    assert chosen["minimum_observed_poi_count_for_full_path_retention"] == 2
    assert chosen["maximum_retained_paths"] == 4
    assert chosen["maximum_observed_retained_paths"] == 5
    assert chosen["fully_restored"] is False


def test_minimum_sufficient_requires_strict_multistage_and_churn_constraints():
    rows = [
        {
            "poi_count": 2,
            "retained_reference_paths": 5,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": False,
            "stage_pairs": 1,
            "budget_feasible": True,
            "churn_bound_satisfied": True,
        },
        {
            "poi_count": 3,
            "retained_reference_paths": 5,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": True,
            "stage_pairs": 2,
            "budget_feasible": True,
            "churn_bound_satisfied": False,
        },
        {
            "poi_count": 4,
            "retained_reference_paths": 4,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": True,
            "stage_pairs": 3,
            "budget_feasible": True,
            "churn_bound_satisfied": True,
        },
    ]

    chosen = select_minimum_sufficient(rows, total_paths=5)

    assert chosen["minimum_sufficient_poi_count"] is None
    assert chosen["earliest_legal_poi_count_at_max_path_retention"] == 4
    assert chosen["maximum_retained_paths"] == 4


def test_minimum_sufficient_accepts_valid_causal_path_cover_forest():
    rows = [
        {
            "poi_count": 1,
            "retained_reference_paths": 1,
            "path_certificate_valid": True,
            "causal_path_cover_certificate_valid": True,
            "strict_multistage_certificate_valid": False,
            "stage_pairs": 0,
            "budget_feasible": True,
        },
        {
            "poi_count": 3,
            "retained_reference_paths": 3,
            "path_certificate_valid": True,
            "causal_path_cover_certificate_valid": True,
            "strict_multistage_certificate_valid": False,
            "certificate_topology": "forest",
            "stage_pairs": 1,
            "budget_feasible": True,
        },
    ]

    chosen = select_minimum_sufficient(rows, total_paths=3)

    assert chosen["minimum_sufficient_poi_count"] == 3
    assert chosen["maximum_retained_paths"] == 3
    assert chosen["fully_restored"] is True


def test_run_experiment_can_skip_redundant_method_comparisons(tmp_path):
    database = tmp_path / "tc.db"
    progress = []
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b")]
            + [EdgeRecord("poi", "a", "b", "EVENT_WRITE", 10, "h")]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="one poi",
                seed_uuids=set(),
                seed_event_ids={"poi"},
                attack_event_ids=set(),
                attack_node_uuids=set(),
            ),
            keep_ratios=[1.0],
            causal_search_config=CausalSearchConfig(
                min_edge_suspicion=0.0,
                min_path_suspicion=0.0,
                min_frontier_relevance=0.0,
            ),
            progress_callback=progress.append,
            include_method_comparison=False,
        )

    assert len(report["results"]) == 1
    assert report["method_comparison"]["methods"] == []
    assert report["method_comparison"]["curve"] == []
    assert not any(item["stage"].startswith("ablation_") for item in progress)


def test_sweep_cli_runs_real_prefix_and_writes_auditable_summaries(
    tmp_path, monkeypatch
):
    phase_trace = []
    original_prune = evaluation_module.adaptive_prune
    original_reference_builder = poi_prefix_module.build_report_reference

    def traced_prune(*args, **kwargs):
        phase_trace.append("online_prune")
        return original_prune(*args, **kwargs)

    def traced_reference_builder(*args, **kwargs):
        phase_trace.append("groundtruth_build")
        return original_reference_builder(*args, **kwargs)

    monkeypatch.setattr(evaluation_module, "adaptive_prune", traced_prune)
    monkeypatch.setattr(
        poi_prefix_module, "build_report_reference", traced_reference_builder
    )
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "socket", "socket-2")
            ]
            + [
                EdgeRecord("core", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("poi", "b", "socket", "EVENT_SENDTO", 20, "h"),
                EdgeRecord("poi-2", "b", "socket-2", "EVENT_SENDTO", 25, "h"),
            ]
        )
    (tmp_path / "pois.json").write_text(
        json.dumps({"event_ids": ["poi", "poi-2"]}), encoding="utf-8"
    )
    (tmp_path / "base.json").write_text(
        json.dumps(
            {
                "name": "base",
                "attack_event_ids": ["core"],
                "attack_node_uuids": ["a", "b"],
            }
        ),
        encoding="utf-8",
    )
    spec_file = tmp_path / "sweep.json"
    spec_file.write_text(
        json.dumps(
            {
                "keep_ratio": 1.0,
                "use_frequency_cache": False,
                "use_frequency_snapshot": False,
                "scenarios": [
                    {
                        "code": "06",
                        "poi_file": "pois.json",
                        "base_groundtruth_file": "base.json",
                        "window_start_ns": 0,
                        "window_end_ns": 30,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "causal_search": {
                    "seed_strategy": "window_context",
                    "min_edge_suspicion": 0.0,
                    "min_path_suspicion": 0.0,
                    "min_frontier_relevance": 0.0,
                    "resource_max_edges": None,
                    "resource_max_states": None,
                },
                "scoring": {
                    "rarity_weight": 0.2,
                    "path_weight": 0.0,
                    "impact_weight": 0.05,
                    "behavior_weight": 0.05,
                    "path_decay": 0.95,
                    "damping": 0.85,
                    "diffusion_mode": "time_respecting_bidir",
                    "fusion_mode": "rdp_guard",
                    "score_mass_target": 0.98,
                    "poi_aggregation": "noisy_or",
                },
                "depimpact": {
                    "merge_threshold_seconds": 10.0,
                    "data_flow_alpha": 0.0001,
                    "kmeans_restarts": 2,
                    "random_seed": 0,
                },
                "behavior": {
                    "min_cluster_size": 2,
                    "fallback_gap_seconds": 30.0,
                    "embedding_dimensions": 4,
                    "minimum_token_frequency": 1,
                },
                "pruning": {
                    "keep_ratios": [1.0],
                    "mode": "rdp_guard",
                    "scope": "merged",
                    "protect_alert_edges": True,
                    "churn_slack_ratio": 0.1,
                    "positive_score_only": True,
                },
                "evidence": {
                    "score_ledger_enabled": True,
                    "high_score_threshold": 0.8,
                    "high_score_quantile": 0.99,
                },
            }
        ),
        encoding="utf-8",
    )

    loaded = load_poi_prefix_spec(spec_file)
    assert loaded.scenarios[0].poi_file == (tmp_path / "pois.json").resolve()

    output_dir = tmp_path / "results"
    assert main(
        [
            "poi-prefix-experiment",
            "--db",
            str(database),
            "--spec",
            str(spec_file),
            "--config",
            str(config_file),
            "--output-dir",
            str(output_dir),
        ]
    ) == 0

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert len(summary["rows"]) == 2
    assert summary["rows"][0]["poi_count"] == 1
    assert summary["rows"][0]["retained_reference_paths"] == 2
    assert summary["days"][0]["minimum_sufficient_poi_count"] == 1
    assert (output_dir / "summary.csv").is_file()
    assert (output_dir / "summary.md").is_file()
    assert (output_dir / "table7-runtime.csv").is_file()
    assert (output_dir / "table7-runtime.md").is_file()
    assert (output_dir / "table8-entry-ranks.csv").is_file()
    assert (output_dir / "table8-entry-ranks.md").is_file()
    result_path = output_dir / "scenario-06" / "poi-prefix-1.json"
    assert result_path.is_file()
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["incomplete"] is False
    assert result["depimpact_table7_runtime"]["schema_version"] == (
        "depimpact-table7-runtime-v1"
    )
    assert result["depimpact_table8_entry_ranks"]["schema_version"] == (
        "depimpact-table8-entry-rank-v1"
    )
    assert set(summary["table8_method_average_ranks"]) == {
        "temporal_only", "temporal_data", "fixed_projection",
        "uniform_random", "depimpact",
    }
    assert result["poi_prefix_experiment"]["path_metrics"][
        "retained_reference_paths"
    ] == 2
    assert summary["cross_day"]["mean_minimum_poi_fraction"] == 0.5
    ledger_dir = output_dir / "scenario-06" / "poi-prefix-1-ledger"
    assert verify_score_ledger(ledger_dir)["valid"] is True
    assert summary["rows"][0]["score_ledger_manifest"] == str(
        (ledger_dir / "manifest.json").resolve()
    )
    second_ledger = output_dir / "scenario-06" / "poi-prefix-2-ledger"
    assert verify_score_ledger(second_ledger)["valid"] is True
    assert summary["cross_day"]["score_monotonicity_violations"] == 0
    assert summary["cross_day"]["local_score_digest_violations"] == 0
    assert summary["cross_day"]["all_churn_bounds_satisfied"] is True
    first_report = json.loads(result_path.read_text(encoding="utf-8"))
    second_report = json.loads(
        (output_dir / "scenario-06" / "poi-prefix-2.json").read_text()
    )
    assert first_report["poi_local_scoring"]["local_score_digests"]["poi"] == (
        second_report["poi_local_scoring"]["local_score_digests"]["poi"]
    )
    assert phase_trace.count("groundtruth_build") == 1
    assert phase_trace.index("groundtruth_build") > phase_trace.index("online_prune")


def test_sweep_spec_rejects_string_boolean_instead_of_silently_enabling_it(tmp_path):
    spec_file = tmp_path / "sweep.json"
    spec_file.write_text(
        json.dumps(
            {
                "keep_ratio": 0.2,
                "use_frequency_cache": "false",
                "scenarios": [
                    {
                        "code": "06",
                        "poi_file": "pois.json",
                        "base_groundtruth_file": "base.json",
                        "window_start_ns": 0,
                        "window_end_ns": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="use_frequency_cache must be a boolean"):
        load_poi_prefix_spec(spec_file)


def test_incomplete_prefix_report_raises_scenario_specific_error():
    with pytest.raises(
        RuntimeError, match="UBC-13 prefix 2 experiment is incomplete.*edge limit"
    ):
        require_complete_prefix_report(
            {
                "incomplete": True,
                "candidate_construction": {"truncation_reason": "edge limit"},
            },
            scenario="13",
            poi_count=2,
        )


def test_complete_prefix_report_rejects_invalid_causal_path_cover():
    with pytest.raises(
        RuntimeError, match="causal path-cover certificate is invalid"
    ):
        require_complete_prefix_report(
            {
                "incomplete": False,
                "results": [
                    {
                        "causal_path_cover_certificate_valid": False,
                        "path_certificate_status": "candidate_disconnected",
                        "churn_bound_satisfied": True,
                    }
                ],
            },
            scenario="13",
            poi_count=2,
        )




def test_incomplete_report_json_copy_omits_nonserializable_online_state():
    marker = object()
    report = {
        "incomplete": False,
        "results": [{"path_certificate_status": "candidate_disconnected"}],
        "_online_state": marker,
    }

    persisted = poi_prefix_module._report_for_json(report)

    assert "_online_state" not in persisted
    assert report["_online_state"] is marker
    assert json.loads(json.dumps(persisted))["results"][0][
        "path_certificate_status"
    ] == "candidate_disconnected"
