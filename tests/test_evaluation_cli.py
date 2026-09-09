import json
from pathlib import Path

import pytest

import tc_pruning.evaluation as evaluation_module
from tc_pruning.cli import main
from tc_pruning.causal import CausalSearchConfig
from tc_pruning.config import load_experiment_config
from tc_pruning.evaluation import (
    AttackAnnotations,
    build_paper_main_result,
    compute_metrics,
    run_experiment,
)
from tc_pruning.models import EdgeRecord, Neighborhood, NodeRecord, StoredEdge
from tc_pruning.store import ProvenanceStore
from tc_pruning.score_ledger import verify_score_ledger


FIXTURES = Path(__file__).parent / "fixtures"


def test_paper_main_result_has_only_compact_publication_columns():
    metrics = build_paper_main_result(
        scenario="UBC06", method="adaptive_fusion_connectivity",
        nodes_before=10, nodes_after=4, events_before=20, events_after=5,
        attack_event_recall=0.6, complete_path_retention=0.5,
        latency_seconds=1.2,
    )

    assert metrics == {
        "scenario": "UBC06", "method": "adaptive_fusion_connectivity",
        "nodes_before": 10, "nodes_after": 4,
        "events_before": 20, "events_after": 5,
        "event_compression_ratio": 0.75, "attack_event_recall": 0.6,
        "complete_path_retention": 0.5, "single_run_latency_seconds": 1.2,
    }


def _write_profile(
    tmp_path,
    *,
    keep_ratios=(1.0,),
    pruning_mode="ratio",
    pruning_scope="per-alert",
    protect_alert_edges=True,
    rarity_weight=0.4,
    path_weight=0.3,
    fusion_mode=None,
    score_mass_target=None,
):
    path = tmp_path / f"profile-{len(list(tmp_path.iterdir()))}.json"
    path.write_text(
        json.dumps(
            {
                "causal_search": {
                    "min_edge_suspicion": 0.0,
                    "min_path_suspicion": 0.0,
                    "suspicion_momentum": 0.8,
                    "branch_suspicion_quantile": 0.0,
                    "resource_max_edges": None,
                    "resource_max_states": None,
                },
                "scoring": {
                    "rarity_weight": rarity_weight,
                    "path_weight": path_weight,
                    "impact_weight": 0.0,
                    "behavior_weight": 0.0,
                    "path_decay": 0.95,
                    "damping": 0.85,
                    **(
                        {"fusion_mode": fusion_mode}
                        if fusion_mode is not None else {}
                    ),
                    **(
                        {"score_mass_target": score_mass_target}
                        if score_mass_target is not None else {}
                    ),
                },
                "depimpact": {
                    "merge_threshold_seconds": 10.0,
                    "data_flow_alpha": 0.0001,
                    "kmeans_restarts": 20,
                    "random_seed": 0,
                },
                "behavior": {
                    "min_cluster_size": 3,
                    "fallback_gap_seconds": 30.0,
                    "embedding_dimensions": 32,
                    "minimum_token_frequency": 1,
                },
                "pruning": {
                    "keep_ratios": list(keep_ratios),
                    "mode": pruning_mode,
                    "scope": pruning_scope,
                    "protect_alert_edges": protect_alert_edges,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_profile_loads_rdp_guard_fusion_and_mass_target(tmp_path):
    profile = _write_profile(
        tmp_path, pruning_mode="rdp_guard", fusion_mode="rdp_guard",
        score_mass_target=0.97,
    )

    loaded = load_experiment_config(profile)

    assert loaded.fusion_mode == "rdp_guard"
    assert loaded.score_mass_target == pytest.approx(0.97)
    assert loaded.pruning_mode == "rdp_guard"


def test_profile_rejects_unknown_fusion_mode(tmp_path):
    profile = _write_profile(tmp_path, fusion_mode="independent-noise")

    with pytest.raises(ValueError, match="fusion_mode"):
        load_experiment_config(profile)


def _edge(edge_id, event_id, src, dst):
    return StoredEdge(
        edge_id,
        event_id,
        src,
        dst,
        "EVENT_TEST",
        edge_id,
        "h",
        "process",
        "process",
    )


def test_metrics_measure_compression_retention_and_reachability():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "attack-1", "a", "b"),
            _edge(2, "attack-2", "b", "c"),
            _edge(3, "benign", "b", "d"),
        ],
    )
    annotations = AttackAnnotations(
        name="case",
        seed_uuids={"a"},
        attack_event_ids={"attack-1", "attack-2"},
        attack_node_uuids={"a", "b", "c"},
        attack_paths=[("attack-1", "attack-2")],
    )

    metrics = compute_metrics(graph, graph.edges[:2], annotations)

    assert metrics.edge_compression == pytest.approx(1 / 3)
    assert metrics.node_compression == pytest.approx(1 / 4)
    assert metrics.attack_edge_retention == 1.0
    assert metrics.attack_node_retention == 1.0
    assert metrics.attack_reachability == 1.0
    assert metrics.attack_edge_coverage == 1.0
    assert metrics.attack_node_coverage == 1.0
    assert metrics.annotated_attack_paths == 1
    assert metrics.matched_attack_paths == 1
    assert metrics.attack_path_coverage == 1.0
    assert metrics.attack_path_retention == 1.0


def test_complete_attack_path_metric_rejects_a_partially_retained_path():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[
            _edge(1, "attack-1", "a", "b"),
            _edge(2, "attack-2", "b", "c"),
        ],
    )
    annotations = AttackAnnotations(
        name="case",
        seed_uuids={"a"},
        attack_event_ids={"attack-1", "attack-2"},
        attack_node_uuids={"a", "b", "c"},
        attack_paths=[("attack-1", "attack-2")],
    )

    metrics = compute_metrics(graph, graph.edges[:1], annotations)

    assert metrics.attack_edge_retention == 0.5
    assert metrics.attack_path_coverage == 1.0
    assert metrics.attack_path_retention == 0.0


def test_attack_path_metrics_are_empty_without_path_level_ground_truth():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "ab"},
        edges=[_edge(1, "attack-1", "a", "b")],
    )
    annotations = AttackAnnotations(
        name="case",
        seed_uuids={"a"},
        attack_event_ids={"attack-1"},
        attack_node_uuids={"a", "b"},
    )

    metrics = compute_metrics(graph, graph.edges, annotations)

    assert metrics.attack_path_coverage is None
    assert metrics.attack_path_retention is None


def test_metrics_do_not_report_perfect_retention_when_annotations_miss_graph():
    graph = Neighborhood(
        nodes={"a": NodeRecord("a", "process", "a")},
        edges=[],
    )
    annotations = AttackAnnotations(
        name="wrong performer",
        seed_uuids={"a"},
        attack_event_ids={"missing-event"},
        attack_node_uuids={"missing-node"},
    )

    metrics = compute_metrics(graph, [], annotations)

    assert metrics.matched_attack_edges == 0
    assert metrics.matched_attack_nodes == 0
    assert metrics.attack_edge_retention is None
    assert metrics.attack_node_retention is None
    assert metrics.attack_reachability is None
    assert metrics.attack_edge_coverage == 0.0
    assert metrics.attack_node_coverage == 0.0


def test_event_seed_reachability_rejects_reverse_direction_distractor():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[
            _edge(1, "alert", "a", "b"),
            _edge(2, "reverse", "c", "b"),
        ],
    )
    annotations = AttackAnnotations(
        name="case",
        seed_uuids={"a", "b"},
        seed_event_ids={"alert"},
        attack_event_ids={"alert", "reverse"},
        attack_node_uuids={"a", "b", "c"},
    )

    metrics = compute_metrics(graph, graph.edges, annotations)

    assert metrics.attack_node_retention == 1.0
    assert metrics.attack_reachability == pytest.approx(2 / 3)


def test_event_seed_metrics_count_only_nodes_with_retained_edges():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[_edge(1, "alert", "a", "b")],
    )
    annotations = AttackAnnotations(
        name="case",
        seed_uuids={"a", "b", "c"},
        seed_event_ids={"alert"},
        attack_event_ids=set(),
        attack_node_uuids=set(),
    )

    metrics = compute_metrics(graph, graph.edges, annotations)

    assert metrics.kept_nodes == 2


def test_cli_ingests_fixture_and_writes_experiment_report(tmp_path):
    database = tmp_path / "tc.db"
    output = tmp_path / "report.json"
    profile = _write_profile(tmp_path, keep_ratios=(0.2, 0.5))

    assert main(
        [
            "ingest",
            "--input",
            str(FIXTURES / "tc-mini.jsonl"),
            "--db",
            str(database),
        ]
    ) == 0
    assert main(["build-frequency-cache", "--db", str(database)]) == 0
    assert main(["compile-frequency-snapshot", "--db", str(database), "--before-timestamp-ns", "3"]) == 0
    assert main(
        [
            "experiment",
            "--db",
            str(database),
            "--annotations",
            str(FIXTURES / "tc-mini-annotations.json"),
            "--config",
            str(profile),
            "--output",
            str(output),
        ]
    ) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["annotation_name"] == "CDM format fixture, not a DARPA benchmark"
    assert report["original_edges"] == 3
    assert report["causal_search_policy"] == "adaptive_window_priority_frontier_relevance"
    assert report["candidate_graph_has_path_limit"] is False
    assert report["causal_search_config"]["min_edge_suspicion"] == 0.0
    assert report["search_diagnostics"] == {
        "complete_path_count": 1,
        "truncated_path_count": 0,
        "termination_reasons": {"natural_head": 1, "natural_tail": 1},
    }
    assert report["results"][0]["group_pruning"][0]["search_diagnostics"] == {
        "complete_path_count": 1,
        "truncated_path_count": 0,
        "termination_reasons": {"natural_head": 1, "natural_tail": 1},
    }
    assert [row["requested_keep_ratio"] for row in report["results"]] == [0.2, 0.5]
    assert report["paper_main_results"]["available"] is False
    assert "edge_compression" not in report["results"][0]
    assert "attack_edge_retention" not in report["results"][0]
    assert report["pruning_mode"] == "ratio"
    assert all(row["selection_mode"] == "ratio" for row in report["results"])
    ledger_dir = tmp_path / "report-ledger"
    assert report["score_ledger"]["candidate_edge_count"] == 3
    assert report["score_ledger"]["ledger_row_count"] == 3
    assert Path(report["score_ledger"]["directory"]) == ledger_dir
    assert verify_score_ledger(ledger_dir)["valid"] is True


def test_cli_reports_rdp_guard_score_mass_certificate_and_recommendation(tmp_path):
    database = tmp_path / "tc.db"
    output = tmp_path / "rdp-guard-report.json"
    profile = _write_profile(
        tmp_path, keep_ratios=(0.5, 1.0), pruning_mode="rdp_guard",
        pruning_scope="merged", fusion_mode="rdp_guard",
        score_mass_target=0.5, rarity_weight=0.2, path_weight=0.0,
    )

    assert main([
        "ingest", "--input", str(FIXTURES / "tc-mini.jsonl"),
        "--db", str(database),
    ]) == 0
    assert main(["build-frequency-cache", "--db", str(database)]) == 0
    assert main([
        "compile-frequency-snapshot", "--db", str(database),
        "--before-timestamp-ns", "3",
    ]) == 0
    assert main([
        "experiment", "--db", str(database),
        "--annotations", str(FIXTURES / "tc-mini-annotations.json"),
        "--config", str(profile), "--output", str(output),
    ]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    first = report["results"][0]
    assert report["fusion_mode"] == "rdp_guard"
    assert first["scoring_mode"] == "rdp_guard"
    assert 0.0 <= first["score_mass_retained"] <= 1.0
    assert first["certificate_poi_edges"] == 1
    assert first["certificate_retained_poi_edges"] == 1
    assert first["path_certificate_valid"] is True
    assert report["rdp_guard_recommendation"]["available"] is True
    assert report["rdp_guard_recommendation"]["online_uses_groundtruth"] is False


def test_noisy_or_prefix_state_freezes_old_poi_scores_and_is_monotone(tmp_path):
    database = tmp_path / "prefix.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c", "d", "x", "y")
            ]
            + [
                EdgeRecord("history", "x", "y", "EVENT_WRITE", 1, "h"),
                EdgeRecord("poi-1", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("bridge", "b", "c", "EVENT_WRITE", 20, "h"),
                EdgeRecord("poi-2", "c", "d", "EVENT_WRITE", 30, "h"),
                EdgeRecord("noise", "x", "y", "EVENT_WRITE", 35, "h"),
            ]
        )

        def annotations(events):
            group_id = "fixed-window"
            return AttackAnnotations(
                name=f"prefix-{len(events)}",
                seed_uuids=set(),
                seed_event_ids=set(events),
                seed_event_groups=[set(events)],
                seed_event_group_ids=[group_id],
                seed_event_sequences=[tuple(events)],
                investigation_windows={group_id: (10, 35)},
                attack_event_ids=set(),
                attack_node_uuids=set(),
            )

        kwargs = dict(
            keep_ratios=(0.8,), rarity_weight=0.2, impact_weight=0.05,
            behavior_weight=0.05, pruning_mode="rdp_guard",
            fusion_mode="rdp_guard", diffusion_mode="time_respecting_bidir",
            causal_search_config=CausalSearchConfig(seed_strategy="window_context"),
            connectivity_protection=True, include_method_comparison=False,
            poi_aggregation="noisy_or", positive_score_only=True,
            churn_slack_ratio=0.2, include_internal_state=True,
            kmeans_restarts=2, behavior_min_cluster_size=2,
        )
        first = run_experiment(store, annotations(["poi-1"]), **kwargs)
        first_state = first["_online_state"]
        second = run_experiment(
            store,
            annotations(["poi-1", "poi-2"]),
            previous_kept_event_ids=first_state["kept_event_ids"],
            prefix_score_accumulator=first_state["prefix_score_accumulator"],
            **kwargs,
        )

    second_state = second["_online_state"]
    first_digest = first["poi_local_scoring"]["local_score_digests"]["poi-1"]
    assert second["poi_local_scoring"]["local_score_digests"]["poi-1"] == first_digest
    assert all(
        second_state["edge_scores"][edge_id] + 1e-15 >= score
        for edge_id, score in first_state["edge_scores"].items()
    )
    assert second["results"][0]["churn_bound_satisfied"] is True
    assert second["results"][0]["path_certificate_status"] == "valid"


def test_run_experiment_threads_explicit_causal_path_cover_to_ledger(tmp_path):
    database = tmp_path / "forest.db"
    ledger_dir = tmp_path / "forest-ledger"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c", "d", "e", "f")
            ]
            + [
                EdgeRecord("poi-1", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("bridge", "b", "c", "EVENT_WRITE", 20, "h"),
                EdgeRecord("poi-2", "c", "d", "EVENT_WRITE", 30, "h"),
                EdgeRecord("branch", "e", "f", "EVENT_SENDTO", 40, "h"),
            ]
        )
        annotations = AttackAnnotations(
            name="explicit causal forest",
            seed_uuids=set(),
            seed_event_ids={"poi-1", "poi-2", "branch"},
            seed_event_groups=[{"poi-1", "poi-2"}, {"branch"}],
            seed_event_group_ids=["main", "side"],
            seed_event_sequences=[("poi-1", "poi-2"), ("branch",)],
            investigation_windows={"main": (10, 40), "side": (10, 40)},
            attack_event_ids=set(),
            attack_node_uuids=set(),
        )
        report = run_experiment(
            store,
            annotations,
            keep_ratios=(1.0,),
            causal_search_config=CausalSearchConfig(seed_strategy="window_context"),
            connectivity_protection=True,
            certificate_topology_policy="causal_path_cover",
            include_method_comparison=False,
            score_ledger_dir=ledger_dir,
        )

    result = report["results"][0]
    assert report["ordered_poi_event_sequences"] == [
        ["poi-1", "poi-2"], ["branch"]
    ]
    assert result["certificate_topology"] == "forest"
    assert result["certificate_branch_count"] == 2
    assert result["path_certificate_status"] == "valid_forest"
    assert result["causal_path_cover_certificate_valid"] is True
    context = json.loads((ledger_dir / "manifest.json").read_text())["context"]
    assert context["pruning_parameters"]["certificate_topology_policy"] == (
        "causal_path_cover"
    )
    assert context["pruning_parameters"]["ordered_poi_event_sequences"] == [
        ["poi-1", "poi-2"], ["branch"]
    ]


def test_cli_runs_from_detector_independent_poi_events_without_kairos(tmp_path):
    database = tmp_path / "tc.db"
    output = tmp_path / "poi-report.json"
    poi_events = tmp_path / "poi-events.json"
    poi_events.write_text(json.dumps(["e-fork"]), encoding="utf-8")
    profile = _write_profile(tmp_path, keep_ratios=(0.5,))

    assert main(
        [
            "ingest",
            "--input",
            str(FIXTURES / "tc-mini.jsonl"),
            "--db",
            str(database),
        ]
    ) == 0
    assert main(["build-frequency-cache", "--db", str(database)]) == 0
    assert main(["compile-frequency-snapshot", "--db", str(database), "--before-timestamp-ns", "3"]) == 0
    assert main(
        [
            "experiment",
            "--db",
            str(database),
            "--poi-events",
            str(poi_events),
            "--config",
            str(profile),
            "--output",
            str(output),
        ]
    ) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["input_mode"] == "event_poi_file"
    assert report["annotated_seed_event_ids"] == ["e-fork"]
    assert report["seeds"] == ["p-attack"]
    assert report["poi_seed_policy"] == "relation_aware_investigation_anchor"
    assert report["poi_events"] == [
        {
            "event_id": "e-fork",
            "src": "p-alert",
            "dst": "p-attack",
            "anchor": "p-attack",
        }
    ]
    assert "e-fork" in report["results"][0]["kept_event_ids"]


def test_cli_evaluates_each_detector_alert_against_independent_groundtruth(tmp_path):
    database = tmp_path / "tc.db"
    detector = tmp_path / "detector.json"
    groundtruth = tmp_path / "groundtruth.json"
    output = tmp_path / "alert-aligned-report.json"
    profile = _write_profile(tmp_path)
    detector.write_text(
        json.dumps(
            {
                "name": "independent detector",
                "seed_event_groups": [
                    {"group_id": "window-1", "seed_event_ids": ["e-fork"]},
                    {"group_id": "node-only", "seed_event_ids": ["e-common-2"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    groundtruth.write_text(
        json.dumps(
            {
                "name": "independent truth without oracle seed",
                "attack_event_ids": ["e-fork", "e-secret", "e-c2"],
                "attack_node_uuids": [
                    "p-alert",
                    "p-attack",
                    "f-secret",
                    "s-c2",
                ],
            }
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "ingest",
            "--input",
            str(FIXTURES / "tc-mini.jsonl"),
            "--db",
            str(database),
        ]
    ) == 0
    assert main(["build-frequency-cache", "--db", str(database)]) == 0
    assert main(["compile-frequency-snapshot", "--db", str(database), "--before-timestamp-ns", "3"]) == 0
    assert main(
        [
            "experiment",
            "--db",
            str(database),
            "--annotations",
            str(detector),
            "--groundtruth-annotations",
            str(groundtruth),
            "--config",
            str(profile),
            "--output",
            str(output),
        ]
    ) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["protect_alert_edges"] is True
    assert report["pruning_scope"] == "per_alert_group"
    assert len(report["results"][0]["group_pruning"]) == 2
    assert "alert_aligned_evaluation" not in report
    assert "stage_evaluation" not in report
    assert "compression_recall_curve" not in report
    metrics = report["paper_main_results"]
    assert metrics["available"] is True
    assert metrics["groundtruth_name"] == "independent truth without oracle seed"
    assert metrics["rows"][0]["attack_event_recall"] == pytest.approx(2 / 3)
    ledger_manifest = json.loads(
        (tmp_path / "alert-aligned-report-ledger" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert ledger_manifest["context"]["scoring_parameters"][
        "edge_score_aggregation"
    ] == "noisy_or"


def test_attack_annotations_loads_kairos_seed_groups(tmp_path):
    path = tmp_path / "annotations.json"
    path.write_text(
        json.dumps(
            {
                "name": "KAIROS windows",
                "seed_event_ids": [],
                "seed_event_groups": [
                    {
                        "group_id": "w1",
                        "seed_event_ids": ["e1", "e2"],
                        "window_start_ns": 100,
                        "window_end_ns": 200,
                    },
                    {"group_id": "w2", "seed_event_ids": ["e3"]},
                ],
                "attack_paths": [["e1", "e2"], ["e3"]],
            }
        ),
        encoding="utf-8",
    )

    annotations = AttackAnnotations.load(path)

    assert annotations.seed_event_ids == {"e1", "e2", "e3"}
    assert annotations.seed_event_groups == [{"e1", "e2"}, {"e3"}]
    assert annotations.seed_event_sequences == [("e1", "e2"), ("e3",)]
    assert annotations.investigation_windows == {"w1": (100, 200)}
    assert annotations.attack_paths == [("e1", "e2"), ("e3",)]


def test_cli_prepares_event_alert_and_runs_nodoze_hybrid_report(tmp_path):
    database = tmp_path / "tc.db"
    groundtruth = tmp_path / "groundtruth.txt"
    annotations = tmp_path / "annotations.json"
    output = tmp_path / "hybrid-report.json"
    profile = _write_profile(
        tmp_path,
        keep_ratios=(0.5,),
        pruning_mode="adaptive",
    )
    groundtruth.write_text(
        "p-alert\np-attack\nf-secret\ns-c2\n", encoding="utf-8"
    )

    assert main(
        [
            "ingest",
            "--input",
            str(FIXTURES / "tc-mini.jsonl"),
            "--db",
            str(database),
        ]
    ) == 0
    assert main(
        [
            "prepare-annotations",
            "--db",
            str(database),
            "--groundtruth",
            str(groundtruth),
            "--output",
            str(annotations),
        ]
    ) == 0
    manifest = json.loads(annotations.read_text(encoding="utf-8"))
    assert manifest["seed_event_ids"] == ["e-fork"]
    assert main(["build-frequency-cache", "--db", str(database)]) == 0
    assert main(["compile-frequency-snapshot", "--db", str(database), "--before-timestamp-ns", "3"]) == 0

    assert main(
        [
            "experiment",
            "--db",
            str(database),
            "--annotations",
            str(annotations),
            "--config",
            str(profile),
            "--output",
            str(output),
        ]
    ) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["analysis_mode"] == "nodoze_hybrid"
    assert report["candidate_path_count"] >= 1
    assert report["matched_seed_event_ids"] == ["e-fork"]
    assert report["pruning_mode"] == "adaptive"
    assert "attack_edge_coverage" not in report["results"][0]
    assert report["paper_main_results"]["available"] is False
    assert "reconstructed_paths" in report["results"][0]


def test_cli_prepares_ubc_scenario_annotations(tmp_path):
    database = tmp_path / "tc.db"
    groundtruth = tmp_path / "E3-CADETS"
    output_dir = tmp_path / "ubc-annotations"
    pois = tmp_path / "pois.json"
    groundtruth.mkdir()
    pois.write_text(json.dumps({"event_ids": ["ubc-alert"]}), encoding="utf-8")
    (groundtruth / "node_Nginx_Backdoor_06.csv").write_text(
        "p-alert,{'subject': 'alert'},1\n"
        "p-attack,{'subject': 'attack'},2\n",
        encoding="utf-8",
    )

    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord("p-alert", "process", "alert", "h"),
                NodeRecord("p-attack", "process", "attack", "h"),
                EdgeRecord(
                    "ubc-alert",
                    "p-alert",
                    "p-attack",
                    "EVENT_FORK",
                    1_523_028_001_000_000_000,
                    "h",
                ),
            ]
        )
    assert main(
        [
            "prepare-ubc-annotations",
            "--db",
            str(database),
            "--groundtruth-dir",
            str(groundtruth),
            "--output-dir",
            str(output_dir),
            "--scenario",
            "06",
            "--poi-events",
            str(pois),
        ]
    ) == 0

    manifest = json.loads(
        (output_dir / "cadets-e3-ubc-06-annotations.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["attack_node_uuids"] == ["p-alert", "p-attack"]
    assert manifest["metadata"]["label_scope"] == "UBC manually reviewed core attack nodes"
    assert manifest["seed_event_groups"][0]["group_id"] == "ubc-06-pdf-incident"


def test_event_seed_experiment_does_not_protect_all_seed_incident_edges(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord(name, "process", name, "h")
                for name in ("a", "b", "c", "d", "e")
            ]
                + [
                    EdgeRecord("history-alert", "a", "b", "ALERT", 5, "h"),
                    EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
                    EdgeRecord("branch-3", "b", "e", "R", 13, "h"),
            ]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="busy alert",
                seed_uuids=set(),
                seed_event_ids={"alert"},
                attack_event_ids=set(),
                attack_node_uuids=set(),
            ),
            keep_ratios=[0.5],
            groundtruth_annotations=AttackAnnotations(
                name="truth",
                seed_uuids=set(),
                attack_event_ids={"alert"},
                attack_node_uuids={"a", "b"},
            ),
            causal_search_config=CausalSearchConfig(
                min_edge_suspicion=0.0,
                min_path_suspicion=0.0,
                resource_max_edges=None,
                resource_max_states=None,
            ),
        )

    assert report["protect_alert_edges"] is False
    assert report["seeds"] == ["a"]
    assert report["poi_seed_policy"] == "relation_aware_investigation_anchor"
    assert report["results"][0]["actual_keep_ratio"] == 0.5
    assert report["paper_main_results"]["event_scope"] == "scenario_unique_event_ids"
    assert report["paper_main_results"]["rows"][0]["attack_event_recall"] == 0.0
    assert report["resource_usage"]["end_to_end_latency_seconds"] > 0
    assert report["resource_usage"]["peak_rss_mb"] > 0
    assert report["resource_usage"]["baseline_rss_mb"] > 0
    assert report["resource_usage"]["peak_rss_increment_mb"] >= 0
    assert report["metric_protocol_version"] == "tc-pruning-evaluation-v2.0"
    assert "method_comparison" in report


def test_sendto_poi_uses_the_process_subject_as_the_scoring_seed(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord("process", "process", "payload", "h"),
                NodeRecord("socket", "socket", "c2", "h"),
                EdgeRecord("poi", "process", "socket", "EVENT_SENDTO", 10, "h"),
            ]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="send symptom",
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
        )

    assert report["seeds"] == ["process"]
    assert report["poi_seed_policy"] == "relation_aware_investigation_anchor"
    assert report["poi_events"] == [
        {
            "event_id": "poi",
            "src": "process",
            "dst": "socket",
            "anchor": "process",
        }
    ]


def test_kairos_forward_cumulative_mode_reports_ordered_graph_updates(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b", "c", "d")]
            + [
                EdgeRecord("early", "a", "b", "ALERT", 10, "h"),
                EdgeRecord("shared", "b", "c", "WRITE", 20, "h"),
                EdgeRecord("late", "b", "c", "ALERT", 30, "h"),
                EdgeRecord("tail", "c", "d", "SEND", 40, "h"),
            ]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="kairos",
                seed_uuids=set(), seed_event_ids={"early", "late"},
                seed_event_groups=[{"late"}, {"early"}],
                seed_event_group_ids=["late-window", "early-window"],
                attack_event_ids=set(), attack_node_uuids=set(),
            ),
            keep_ratios=[0.5],
            causal_search_config=CausalSearchConfig(
                seed_strategy="kairos_forward_cumulative",
                min_edge_suspicion=0.0, min_path_suspicion=0.0,
                min_frontier_relevance=0.0,
            ),
        )

    assert report["analysis_mode"] == "kairos_forward_cumulative"
    assert report["pruning_scope"] == "merged_candidate_graph"
    assert [row["group_id"] for row in report["cumulative_alert_search"]] == [
        "early-window", "late-window"
    ]
    assert report["cumulative_alert_search"][-1]["cumulative_event_count"] == 4
    assert set(report["candidate_event_ids"]) == {"early", "shared", "late", "tail"}


def test_window_context_candidate_is_independent_of_groundtruth(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b", "c")]
            + [
                EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
                EdgeRecord("background", "b", "c", "WRITE", 11, "h"),
            ]
        )
        alerts = AttackAnnotations(
            name="kairos", seed_uuids=set(), seed_event_ids={"alert"},
            seed_event_groups=[{"alert"}], seed_event_group_ids=["synthetic"],
            attack_event_ids=set(), attack_node_uuids=set(),
        )
        config = CausalSearchConfig(seed_strategy="window_context")
        reports = [
            run_experiment(
                store, alerts, keep_ratios=[0.5], causal_search_config=config,
                groundtruth_annotations=AttackAnnotations(
                    name="truth", seed_uuids=set(), attack_event_ids=truth,
                    attack_node_uuids=set(),
                ),
            )
            for truth in ({"alert"}, {"background"})
        ]

    assert reports[0]["candidate_event_ids"] == reports[1]["candidate_event_ids"]
    assert reports[0]["analysis_mode"] == "window_context"
    assert reports[0]["candidate_construction"]["incomplete"] is False


def test_groundtruth_database_reads_happen_after_all_online_pruning(
    tmp_path, monkeypatch
):
    database = tmp_path / "tc.db"
    trace = []
    original_lookup = ProvenanceStore.get_edge_by_event_id
    original_prune = evaluation_module.adaptive_prune

    def traced_lookup(store, event_id):
        if event_id == "groundtruth-only":
            trace.append("groundtruth_lookup")
        return original_lookup(store, event_id)

    def traced_prune(*args, **kwargs):
        trace.append("online_prune")
        return original_prune(*args, **kwargs)

    monkeypatch.setattr(ProvenanceStore, "get_edge_by_event_id", traced_lookup)
    monkeypatch.setattr(evaluation_module, "adaptive_prune", traced_prune)

    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b", "c")]
            + [
                EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
                EdgeRecord("groundtruth-only", "b", "c", "WRITE", 11, "h"),
            ]
        )
        run_experiment(
            store,
            AttackAnnotations(
                name="detector",
                seed_uuids=set(),
                seed_event_ids={"alert"},
                seed_event_groups=[{"alert"}],
                seed_event_group_ids=["incident"],
                attack_event_ids=set(),
                attack_node_uuids=set(),
            ),
            keep_ratios=[0.5, 1.0],
            groundtruth_annotations=AttackAnnotations(
                name="offline truth",
                seed_uuids=set(),
                attack_event_ids={"groundtruth-only"},
                attack_node_uuids={"b", "c"},
            ),
            causal_search_config=CausalSearchConfig(seed_strategy="window_context"),
            include_method_comparison=False,
        )

    assert trace.count("online_prune") == 2
    assert trace.count("groundtruth_lookup") == 1
    assert trace.index("groundtruth_lookup") > max(
        index for index, stage in enumerate(trace) if stage == "online_prune"
    )


def test_lazy_groundtruth_provider_is_not_invoked_until_pruning_is_frozen(
    tmp_path, monkeypatch
):
    trace = []
    original_prune = evaluation_module.adaptive_prune

    def traced_prune(*args, **kwargs):
        trace.append("online_prune")
        return original_prune(*args, **kwargs)

    def groundtruth_provider():
        trace.append("groundtruth_provider")
        return AttackAnnotations(
            name="offline truth",
            seed_uuids=set(),
            attack_event_ids={"background"},
            attack_node_uuids={"b", "c"},
        )

    monkeypatch.setattr(evaluation_module, "adaptive_prune", traced_prune)
    with ProvenanceStore(tmp_path / "tc.db") as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b", "c")]
            + [
                EdgeRecord("alert", "a", "b", "ALERT", 10, "h"),
                EdgeRecord("background", "b", "c", "WRITE", 11, "h"),
            ]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="detector",
                seed_uuids=set(),
                seed_event_ids={"alert"},
                seed_event_groups=[{"alert"}],
                seed_event_group_ids=["incident"],
                attack_event_ids=set(),
                attack_node_uuids=set(),
            ),
            keep_ratios=[0.5, 1.0],
            groundtruth_annotations=groundtruth_provider,
            causal_search_config=CausalSearchConfig(seed_strategy="window_context"),
            include_method_comparison=False,
        )

    assert report["paper_main_results"]["available"] is True
    assert trace.count("online_prune") == 2
    assert trace.count("groundtruth_provider") == 1
    assert trace.index("groundtruth_provider") > max(
        index for index, stage in enumerate(trace) if stage == "online_prune"
    )


def test_window_context_uses_explicit_boundaries_and_relation_aware_seed(tmp_path):
    database = tmp_path / "tc.db"
    with ProvenanceStore(database) as store:
        store.ingest(
            [
                NodeRecord("p", "process", "p", "h"),
                NodeRecord("f", "file", "f", "h"),
                NodeRecord("x", "file", "x", "h"),
            ]
            + [
                EdgeRecord("lower", "p", "x", "EVENT_WRITE", 5, "h"),
                EdgeRecord("poi", "p", "f", "EVENT_WRITE", 10, "h"),
                EdgeRecord("upper", "p", "x", "EVENT_WRITE", 15, "h"),
                EdgeRecord("outside", "p", "x", "EVENT_WRITE", 16, "h"),
            ]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="explicit incident",
                seed_uuids=set(), seed_event_ids={"poi"},
                seed_event_groups=[{"poi"}],
                seed_event_group_ids=["incident"],
                seed_event_sequences=[("poi",)],
                investigation_windows={"incident": (5, 15)},
                attack_event_ids=set(), attack_node_uuids=set(),
            ),
            keep_ratios=[1.0],
            causal_search_config=CausalSearchConfig(seed_strategy="window_context"),
        )

    assert set(report["candidate_event_ids"]) == {"lower", "poi", "upper"}
    assert report["seeds"] == ["p"]
    assert report["cumulative_alert_search"][0]["boundary_source"] == "explicit_manifest"


def test_window_context_incomplete_returns_checkpoint_not_complete_metrics(tmp_path):
    with ProvenanceStore(tmp_path / "tc.db") as store:
        store.ingest(
            [NodeRecord(name, "process", name, "h") for name in ("a", "b", "c")]
            + [EdgeRecord("alert", "a", "b", "R", 10, "h"),
               EdgeRecord("other", "b", "c", "R", 10, "h")]
        )
        report = run_experiment(
            store,
            AttackAnnotations(
                name="partial", seed_uuids=set(), seed_event_ids={"alert"},
                seed_event_groups=[{"alert"}], seed_event_group_ids=["synthetic"],
                attack_event_ids=set(), attack_node_uuids=set(),
            ),
            keep_ratios=[0.5],
            causal_search_config=CausalSearchConfig(
                seed_strategy="window_context", resource_max_edges=1,
            ),
        )

    assert report["incomplete"] is True
    assert report["candidate_construction"]["truncation_reason"] == "candidate_event_limit"
    assert "paper_main_results" not in report
