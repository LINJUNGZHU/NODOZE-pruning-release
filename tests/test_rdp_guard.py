import pytest

from tc_pruning.rdp_guard import (
    PrefixScoreAccumulator,
    RDPGuardScores,
    aggregate_poi_scores,
    fuse_rarity_diffusion,
    recommend_operating_point,
)


def test_diffusion_gate_prevents_remote_rare_noise_from_beating_common_bridge():
    result = fuse_rarity_diffusion(
        (1, 2),
        rarity={1: 0.0, 2: 1.0},
        diffusion={1: 0.8, 2: 0.0},
        rarity_weight=0.2,
    )

    assert result.scores[1] > result.scores[2]
    assert result.scores[2] == 0.0
    assert result.components[2]["gated_rarity"] == 0.0


def test_rarity_breaks_ties_only_inside_diffusion_supported_corridor():
    result = fuse_rarity_diffusion(
        (1, 2),
        rarity={1: 0.1, 2: 0.9},
        diffusion={1: 0.6, 2: 0.6},
        rarity_weight=0.2,
    )

    assert result.scores[2] > result.scores[1] > 0.0
    # Diffusion is normalized by the strongest candidate edge before gating.
    assert result.components[2]["gated_rarity"] == pytest.approx(0.9)


def test_gated_fusion_normalizes_and_handles_empty_or_zero_scores():
    empty = fuse_rarity_diffusion((), rarity={}, diffusion={}, rarity_weight=0.2)
    zero = fuse_rarity_diffusion(
        (7,), rarity={7: 1.0}, diffusion={7: 0.0}, rarity_weight=0.2
    )

    assert empty.scores == {}
    assert empty.components == {}
    assert zero.scores == {7: 0.0}


def test_gated_fusion_rejects_invalid_weight_sum():
    with pytest.raises(ValueError, match="sum to <= 1"):
        fuse_rarity_diffusion(
            (1,), rarity={1: 1.0}, diffusion={1: 1.0},
            rarity_weight=0.8, impact_weight=0.3,
        )


def test_noisy_or_poi_aggregation_is_monotone_and_keeps_winner_provenance():
    first = fuse_rarity_diffusion(
        (1, 2), rarity={1: 0.2, 2: 0.2}, diffusion={1: 0.8, 2: 0.2},
        rarity_weight=0.2,
    )
    second = fuse_rarity_diffusion(
        (1, 2), rarity={1: 0.2, 2: 0.9}, diffusion={1: 0.1, 2: 0.9},
        rarity_weight=0.2,
    )

    prefix_one = aggregate_poi_scores([("poi-1", first)])
    prefix_two = aggregate_poi_scores([("poi-1", first), ("poi-2", second)])

    assert all(prefix_two.scores[edge_id] >= prefix_one.scores[edge_id] for edge_id in (1, 2))
    assert prefix_two.provenance[1]["winner_poi_event_id"] == "poi-1"
    assert prefix_two.provenance[2]["winner_poi_event_id"] == "poi-2"
    assert prefix_two.provenance[1]["support_count"] == 2
    assert prefix_two.components[2]["aggregate_noisy_or"] == pytest.approx(
        prefix_two.scores[2]
    )


def test_sparse_noisy_or_aggregation_unions_overlapping_per_alert_graphs():
    accumulator = PrefixScoreAccumulator(require_same_edge_ids=False)
    accumulator.add(
        "group-1",
        RDPGuardScores(
            scores={1: 0.4, 2: 0.8},
            components={1: {"local": 0.4}, 2: {"local": 0.8}},
        ),
    )
    accumulator.add(
        "group-2",
        RDPGuardScores(
            scores={2: 0.5, 3: 0.9},
            components={2: {"local": 0.5}, 3: {"local": 0.9}},
        ),
    )

    result = accumulator.finalize()

    assert result.scores == pytest.approx({1: 0.4, 2: 0.9, 3: 0.9})
    assert result.provenance[2]["support_count"] == 2
    assert result.provenance[2]["winner_poi_event_id"] == "group-1"
    assert result.components[2]["local"] == 0.8
    assert result.local_score_contributions == {
        "group-1": {1: 0.4, 2: 0.8},
        "group-2": {2: 0.5, 3: 0.9},
    }


def test_noisy_or_records_every_positive_local_contribution_and_implicit_zeros():
    accumulator = PrefixScoreAccumulator()
    accumulator.add(
        "poi-a",
        RDPGuardScores(
            scores={1: 0.25, 2: 0.0},
            components={1: {}, 2: {}},
        ),
    )
    accumulator.add(
        "poi-b",
        RDPGuardScores(
            scores={1: 0.5, 2: 1.0},
            components={1: {}, 2: {}},
        ),
    )

    result = accumulator.finalize()

    assert result.local_score_contributions == {
        "poi-a": {1: 0.25},
        "poi-b": {1: 0.5, 2: 1.0},
    }
    assert result.scores == pytest.approx({1: 0.625, 2: 1.0})


def test_noisy_or_tie_winner_is_deterministic():
    local = fuse_rarity_diffusion(
        (1,), rarity={1: 0.0}, diffusion={1: 1.0}, rarity_weight=0.0
    )

    result = aggregate_poi_scores([("poi-z", local), ("poi-a", local)])

    assert result.provenance[1]["winner_poi_event_id"] == "poi-a"


def test_noisy_or_winner_provenance_never_treats_nearby_lower_score_as_tie():
    accumulator = PrefixScoreAccumulator()
    accumulator.add(
        "poi-z",
        RDPGuardScores(scores={1: 0.5 + 5e-16}, components={1: {"winner": 1.0}}),
    )
    accumulator.add(
        "poi-a",
        RDPGuardScores(scores={1: 0.5}, components={1: {"winner": 0.0}}),
    )

    result = accumulator.finalize()

    assert result.provenance[1]["winner_poi_event_id"] == "poi-z"
    assert result.components[1]["winner"] == 1.0


def test_noisy_or_preserves_tiny_positive_score_without_cancellation():
    accumulator = PrefixScoreAccumulator()
    accumulator.add(
        "poi-1",
        RDPGuardScores(
            scores={1: 1e-20},
            components={1: {"diffusion": 1e-20}},
        ),
    )

    result = accumulator.finalize()

    assert result.scores[1] == 1e-20
    assert result.provenance[1]["support_count"] == 1


def test_noisy_or_never_decreases_a_saturated_aggregate():
    accumulator = PrefixScoreAccumulator()
    accumulator.add("poi-1", RDPGuardScores(scores={1: 1.0}, components={1: {}}))
    accumulator.add(
        "poi-2", RDPGuardScores(scores={1: 1e-16}, components={1: {}})
    )

    assert accumulator.finalize().scores[1] == 1.0


def test_prefix_accumulator_rejects_nonfinite_scores_and_context_changes():
    accumulator = PrefixScoreAccumulator(context_digest="context-a")
    with pytest.raises(ValueError, match="finite"):
        accumulator.add(
            "bad-poi", RDPGuardScores(scores={1: float("nan")}, components={})
        )

    accumulator.add(
        "poi-1", RDPGuardScores(scores={1: 0.5}, components={1: {}})
    )
    with pytest.raises(ValueError, match="context"):
        accumulator.bind_context("context-b")


def test_operating_point_rejects_non_strict_multistage_or_churn_violation():
    rows = [
        {
            "requested_keep_ratio": 0.1,
            "actual_keep_ratio": 0.1,
            "score_mass_retained": 1.0,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": False,
            "stage_pairs": 1,
            "budget_feasible": True,
            "churn_bound_satisfied": True,
        },
        {
            "requested_keep_ratio": 0.2,
            "actual_keep_ratio": 0.2,
            "score_mass_retained": 1.0,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": True,
            "stage_pairs": 1,
            "budget_feasible": True,
            "churn_bound_satisfied": False,
        },
        {
            "requested_keep_ratio": 0.3,
            "actual_keep_ratio": 0.3,
            "score_mass_retained": 1.0,
            "path_certificate_valid": True,
            "strict_multistage_certificate_valid": True,
            "stage_pairs": 1,
            "budget_feasible": True,
            "churn_bound_satisfied": True,
        },
    ]

    recommendation = recommend_operating_point(rows, score_mass_target=0.95)

    assert recommendation["requested_keep_ratio"] == 0.3


def test_operating_point_accepts_valid_causal_path_cover_forest():
    rows = [
        {
            "requested_keep_ratio": 0.1,
            "actual_keep_ratio": 0.1,
            "score_mass_retained": 1.0,
            "path_certificate_valid": True,
            "causal_path_cover_certificate_valid": True,
            "strict_multistage_certificate_valid": False,
            "certificate_topology": "forest",
            "stage_pairs": 1,
            "budget_feasible": True,
            "churn_bound_satisfied": True,
        }
    ]

    recommendation = recommend_operating_point(rows, score_mass_target=0.95)

    assert recommendation["available"] is True
    assert recommendation["requested_keep_ratio"] == 0.1


def test_recommendation_uses_certificate_and_score_mass_not_groundtruth_metrics():
    rows = [
        {
            "requested_keep_ratio": 0.05,
            "actual_keep_ratio": 0.049,
            "score_mass_retained": 0.80,
            "path_certificate_valid": True,
            "budget_feasible": True,
            "attack_path_retention": 1.0,
        },
        {
            "requested_keep_ratio": 0.10,
            "actual_keep_ratio": 0.099,
            "score_mass_retained": 0.96,
            "path_certificate_valid": True,
            "budget_feasible": True,
            "attack_path_retention": 0.0,
        },
        {
            "requested_keep_ratio": 0.20,
            "actual_keep_ratio": 0.199,
            "score_mass_retained": 0.99,
            "path_certificate_valid": True,
            "budget_feasible": True,
            "attack_path_retention": 1.0,
        },
    ]

    recommendation = recommend_operating_point(rows, score_mass_target=0.95)

    assert recommendation["requested_keep_ratio"] == 0.10
    assert recommendation["selection_reason"] == "minimum_ratio_meeting_certificate_and_score_mass"
    assert "attack_path_retention" not in recommendation["online_inputs"]


def test_recommendation_falls_back_to_highest_mass_valid_certificate():
    rows = [
        {
            "requested_keep_ratio": 0.05,
            "actual_keep_ratio": 0.05,
            "score_mass_retained": 0.6,
            "path_certificate_valid": False,
            "budget_feasible": True,
        },
        {
            "requested_keep_ratio": 0.10,
            "actual_keep_ratio": 0.10,
            "score_mass_retained": 0.9,
            "path_certificate_valid": True,
            "budget_feasible": True,
        },
    ]

    recommendation = recommend_operating_point(rows, score_mass_target=0.95)

    assert recommendation["requested_keep_ratio"] == 0.10
    assert recommendation["selection_reason"] == "highest_score_mass_with_valid_certificate"
