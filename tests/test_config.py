import json

import pytest

from tc_pruning.config import load_experiment_config
from tc_pruning.cli import build_parser


def _document():
    return {
        "causal_search": {
            "min_edge_suspicion": 0.6,
            "min_path_suspicion": 0.5,
            "suspicion_momentum": 0.8,
            "branch_suspicion_quantile": 0.9,
            "initial_window_seconds": 900.0,
            "window_growth_factor": 2.0,
            "window_boundary_fraction": 0.1,
            "temporal_half_life_seconds": 900.0,
            "rarity_priority_weight": 0.6,
            "temporal_priority_weight": 0.25,
            "fanout_priority_weight": 0.15,
            "path_relevance_decay": 0.95,
            "min_frontier_relevance": 0.45,
            "high_frequency_degree": 1000,
            "high_frequency_partition_seconds": 60.0,
            "resource_max_edges": None,
            "resource_max_states": None,
            "resource_max_hops": None,
            "resource_timeout_seconds": None,
        },
        "scoring": {
            "rarity_weight": 0.3,
            "path_weight": 0.2,
            "impact_weight": 0.2,
            "behavior_weight": 0.1,
            "path_decay": 0.95,
            "damping": 0.85,
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
            "keep_ratios": [0.1, 0.3],
            "mode": "ratio",
            "scope": "per-alert",
            "protect_alert_edges": True,
        },
    }


def test_load_experiment_config_builds_validated_nested_profile(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    config = load_experiment_config(path)

    assert config.causal_search.min_edge_suspicion == 0.6
    assert config.causal_search.resource_max_edges is None
    assert config.keep_ratios == (0.1, 0.3)
    assert config.pruning_scope == "per-alert"
    assert config.protect_alert_edges is True
    assert config.impact_weight == 0.2
    assert config.merge_threshold_seconds == 10.0
    assert config.behavior_min_cluster_size == 3
    assert config.causal_search.seed_strategy == "poi_bidirectional"
    assert config.diffusion_mode == "undirected_ppr"
    assert config.certificate_topology_policy == "strict_chain"


def test_load_experiment_config_accepts_temporal_edge_diffusion_mode(tmp_path):
    document = _document()
    document["scoring"]["diffusion_mode"] = "time_respecting_bidir"
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    config = load_experiment_config(path)

    assert config.diffusion_mode == "time_respecting_bidir"


def test_load_experiment_config_accepts_research_evidence_and_stability_options(tmp_path):
    document = _document()
    document["scoring"]["poi_aggregation"] = "noisy_or"
    document["pruning"]["churn_slack_ratio"] = 0.02
    document["pruning"]["positive_score_only"] = True
    document["pruning"]["certificate_topology_policy"] = "causal_path_cover"
    document["evidence"] = {
        "score_ledger_enabled": True,
        "high_score_threshold": 0.8,
        "high_score_quantile": 0.99,
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    config = load_experiment_config(path)

    assert config.poi_aggregation == "noisy_or"
    assert config.churn_slack_ratio == pytest.approx(0.02)
    assert config.positive_score_only is True
    assert config.certificate_topology_policy == "causal_path_cover"
    assert config.score_ledger_enabled is True
    assert config.high_score_threshold == pytest.approx(0.8)
    assert config.high_score_quantile == pytest.approx(0.99)


def test_load_experiment_config_rejects_unknown_certificate_topology_policy(tmp_path):
    document = _document()
    document["pruning"]["certificate_topology_policy"] = "auto_split"
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="certificate_topology_policy"):
        load_experiment_config(path)


def test_research_boolean_options_are_strict(tmp_path):
    document = _document()
    document["pruning"]["positive_score_only"] = "yes"
    document["evidence"] = {"score_ledger_enabled": 1}
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="must be a boolean"):
        load_experiment_config(path)


def test_protect_alert_edges_rejects_string_boolean(tmp_path):
    document = _document()
    document["pruning"]["protect_alert_edges"] = "false"
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(
        ValueError, match="pruning.protect_alert_edges must be a boolean"
    ):
        load_experiment_config(path)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("scoring", "poi_aggregation", "mean"),
        ("pruning", "churn_slack_ratio", 1.1),
        ("evidence", "high_score_threshold", -0.1),
        ("evidence", "high_score_quantile", 0.0),
    ],
)
def test_research_options_are_range_checked(tmp_path, section, field, value):
    document = _document()
    if section == "evidence":
        document["evidence"] = {field: value}
    else:
        document[section][field] = value
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        load_experiment_config(path)


def test_load_experiment_config_accepts_kairos_cumulative_forward_strategy(tmp_path):
    document = _document()
    document["causal_search"]["seed_strategy"] = "kairos_forward_cumulative"
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    config = load_experiment_config(path)

    assert config.causal_search.seed_strategy == "kairos_forward_cumulative"


def test_load_experiment_config_rejects_unknown_fields(tmp_path):
    document = _document()
    document["causal_search"]["max_hops"] = 6
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown causal_search fields: max_hops"):
        load_experiment_config(path)


def test_load_experiment_config_rejects_missing_required_fields(tmp_path):
    document = _document()
    del document["scoring"]["damping"]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="missing scoring fields: damping"):
        load_experiment_config(path)


def test_load_experiment_config_rejects_score_weights_over_one(tmp_path):
    document = _document()
    document["scoring"]["impact_weight"] = 0.8
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="scoring weights must sum to <= 1"):
        load_experiment_config(path)


def test_experiment_cli_uses_profile_instead_of_search_tuning_flags():
    parser = build_parser()
    args = parser.parse_args(
        [
            "experiment",
            "--db",
            "graph.db",
            "--annotations",
            "alerts.json",
            "--output",
            "report.json",
            "--config",
            "profile.json",
        ]
    )

    assert args.config == "profile.json"
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "experiment",
                "--db",
                "graph.db",
                "--annotations",
                "alerts.json",
                "--output",
                "report.json",
                "--max-hops",
                "6",
            ]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("min_edge_suspicion", -0.1),
        ("min_path_suspicion", 1.1),
        ("suspicion_momentum", 1.0),
        ("resource_max_states", 0),
    ],
)
def test_load_experiment_config_rejects_invalid_search_values(tmp_path, field, value):
    document = _document()
    document["causal_search"][field] = value
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        load_experiment_config(path)
