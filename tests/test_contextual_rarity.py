"""Frozen historical baselines must distinguish resource novelty from behavior."""

from copy import deepcopy
import pytest

from tc_pruning.contextual_rarity import ContextualRarityModel


def _model():
    return ContextualRarityModel()


def _row(**changes):
    row = {
        "src_type": "process", "dst_type": "file", "src_semantic": "process:/usr/bin/python3",
        "dst_semantic": "file:/home/alice/.cache/report-a17f903b.tmp",
        "relation": "EVENT_WRITE", "host": "host-a", "timestamp_ns": 10,
    }
    row.update(changes)
    return row


def test_history_excludes_cutoff_ties_and_future_even_if_they_are_frequent():
    candidate = _row(dst_semantic="file:/etc/shadow", timestamp_ns=100)
    baseline = _model().fit([_row(count=50)], cutoff_ns=100)
    mixed = _model().fit([
        _row(count=50), {**candidate, "count": 100000},
        {**candidate, "timestamp_ns": 101, "count": 100000},
    ], cutoff_ns=100)
    assert mixed.score_rows([candidate]) == baseline.score_rows([candidate])
    assert mixed.history_count == 50


def test_cold_start_records_novelty_without_claiming_anomaly():
    score = _model().fit([], cutoff_ns=100).score_rows([_row()])[0]
    assert score["novelty"] == 1.0
    assert score["confidence"] == 0.0
    assert score["contextual_surprise"] == 0.0
    assert score["anomaly_score"] == 0.0
    assert score["context_count"] == 0
    assert score["context_level"] == "unseen"


def test_new_user_resource_is_less_anomalous_than_rare_behavior_in_known_context():
    model = _model().fit([
        _row(dst_semantic="file:/home/alice/.cache/report.json", count=500),
        _row(dst_semantic="file:/etc/shadow", relation="EVENT_READ", count=1),
    ], cutoff_ns=100)
    ordinary, unusual = model.score_rows([
        _row(dst_semantic="file:/home/bob/.cache/report.json", timestamp_ns=100),
        _row(dst_semantic="file:/etc/shadow", relation="EVENT_READ", timestamp_ns=100),
    ])
    assert ordinary["novelty"] == 1.0
    assert ordinary["pattern_count"] == 500
    assert unusual["pattern_count"] == 1
    assert unusual["anomaly_score"] > ordinary["anomaly_score"]
    assert unusual["contextual_surprise"] > ordinary["contextual_surprise"]


def test_temporary_random_suffix_is_generalized_but_executable_names_are_preserved():
    model = _model().fit([
        _row(dst_semantic="file:/tmp/cache-a17f903b.tmp", count=500),
        _row(dst_semantic="file:/tmp/runner-a17f903b", relation="EVENT_EXECUTE", count=500),
    ], cutoff_ns=100)
    temp, executable = model.score_rows([
        _row(dst_semantic="file:/tmp/cache-ff771902.tmp"),
        _row(dst_semantic="file:/tmp/runner-ff771902", relation="EVENT_EXECUTE"),
    ])
    assert temp["pattern_count"] == 500
    assert executable["pattern_count"] == 0
    assert executable["anomaly_score"] > temp["anomaly_score"]


def test_ephemeral_ports_generalize_but_service_ports_and_addresses_do_not():
    model = _model().fit([
        _row(dst_type="socket", dst_semantic="socket:10.0.0.8:50100", relation="EVENT_SENDTO", count=100),
    ], cutoff_ns=100)
    ephemeral, service, other_ip = model.score_rows([
        _row(dst_type="socket", dst_semantic="socket:10.0.0.8:62200", relation="EVENT_SENDTO"),
        _row(dst_type="socket", dst_semantic="socket:10.0.0.8:443", relation="EVENT_SENDTO"),
        _row(dst_type="socket", dst_semantic="socket:203.0.113.9:62200", relation="EVENT_SENDTO"),
    ])
    assert ephemeral["pattern_count"] == 100
    assert service["pattern_count"] == other_ip["pattern_count"] == 0
    assert ephemeral["anomaly_score"] < service["anomaly_score"]


def test_peer_program_baseline_backs_off_for_new_host_but_unseen_program_has_no_confidence():
    model = _model().fit([_row(count=100)], cutoff_ns=100)
    peer, unknown = model.score_rows([
        _row(host="host-b"),
        _row(src_semantic="process:/tmp/previously_unseen_program"),
    ])
    assert peer["context_level"] == "peer_program"
    assert peer["context_count"] == 100
    assert peer["pattern_count"] == 100
    assert peer["confidence"] > 0.0
    assert unknown["context_count"] == unknown["confidence"] == unknown["anomaly_score"] == 0.0


def test_low_history_support_shrinks_same_novel_behavior_score():
    candidate = _row(dst_semantic="file:/etc/shadow", relation="EVENT_READ")
    few = _model().fit([_row(count=1)], cutoff_ns=100).score_rows([candidate])[0]
    many = _model().fit([_row(count=1000)], cutoff_ns=100).score_rows([candidate])[0]
    assert few["confidence"] < many["confidence"]
    assert few["anomaly_score"] < many["anomaly_score"]


def test_weighted_history_matches_expanded_rows_and_keeps_type_relation_counts():
    weighted = _model().fit([_row(count=3)], cutoff_ns=100)
    expanded = _model().fit([_row(), _row(), _row()], cutoff_ns=100)
    candidates = [_row(), _row(dst_semantic="file:/etc/shadow")]
    assert weighted.score_rows(candidates) == expanded.score_rows(candidates)
    score = weighted.score_rows(candidates)[0]
    assert score["src_type_count"] == score["dst_type_count"] == 3
    assert score["relation_count"] == score["type_relation_count"] == 3
    assert score["exact_count"] == 3


@pytest.mark.parametrize("count", [0, -1, True, 1.5, float("nan"), float("inf"), "2", None])
def test_invalid_history_weights_are_rejected(count):
    with pytest.raises(ValueError, match="count"):
        _model().fit([_row(count=count)], cutoff_ns=100)


@pytest.mark.parametrize("timestamp", [None, True, 1.5, float("nan"), "10", -1])
def test_invalid_history_timestamps_are_rejected(timestamp):
    with pytest.raises(ValueError, match="timestamp_ns"):
        _model().fit([_row(timestamp_ns=timestamp)], cutoff_ns=100)


def test_scoring_does_not_learn_from_candidates_and_is_label_independent():
    model = _model().fit([_row(count=10)], cutoff_ns=100)
    candidate = _row(dst_semantic="file:/etc/shadow", relation="EVENT_READ")
    before = deepcopy(candidate)
    first = model.score_rows([candidate])[0]
    duplicated = model.score_rows([candidate] * 20)
    assert duplicated == [first] * 20
    assert model.score_rows([candidate])[0] == first
    assert candidate == before
    assert model.score_rows([{**candidate, "is_attack": True, "ground_truth": ["secret"], "label": "malicious"}])[0] == first


def test_unknown_fields_and_candidate_weights_are_not_consumed():
    class ForbiddenValue:
        def __str__(self):
            raise AssertionError("untrusted metadata was read")
        def __float__(self):
            raise AssertionError("untrusted metadata was read")
        def __iter__(self):
            raise AssertionError("untrusted metadata was read")

    extra = {"ground_truth": ForbiddenValue(), "anomaly_score": ForbiddenValue(), "label": ForbiddenValue()}
    clean = _model().fit([_row(count=10)], cutoff_ns=100)
    decorated = _model().fit([{**_row(count=10), **extra}], cutoff_ns=100)
    assert clean.score_rows([_row()]) == decorated.score_rows([{**_row(), **extra, "count": ForbiddenValue()}])


def test_fit_is_order_independent_and_resets_previous_history():
    first = _row(count=10)
    second = _row(dst_semantic="file:/etc/shadow", relation="EVENT_READ", count=3)
    model = _model().fit([first, second], cutoff_ns=100)
    reverse = _model().fit([second, first], cutoff_ns=100)
    assert model.score_rows([first, second]) == reverse.score_rows([first, second])
    model.fit([], cutoff_ns=100)
    assert model.score_rows([first])[0]["confidence"] == 0.0


def test_process_destination_can_supply_context_without_flipping_edge_direction():
    history = _row(src_type="file", dst_type="process", src_semantic="file:/etc/passwd",
                   dst_semantic="process:/usr/bin/python3", relation="EVENT_READ", count=50)
    candidate = {**history, "src_semantic": "file:/etc/shadow", "timestamp_ns": 100}
    original = deepcopy(candidate)
    score = _model().fit([history], cutoff_ns=100).score_rows([candidate])[0]
    assert score["context_count"] == 50
    assert score["pattern_count"] == 0
    assert score["semantic_pattern"][0] == "file"
    assert score["semantic_pattern"][1] == "process"
    assert candidate == original


def test_same_program_context_covers_changes_in_stored_edge_orientation():
    model = _model().fit([_row(count=100)], cutoff_ns=100)
    score = model.score_rows([_row(
        src_type="file", dst_type="process", src_semantic="file:/etc/shadow",
        dst_semantic="process:/usr/bin/python3", relation="EVENT_READ",
    )])[0]
    assert score["context_count"] == 100
    assert score["pattern_count"] == 0
    assert score["anomaly_score"] > 0.0


def test_failed_refit_preserves_the_last_valid_baseline():
    model = _model().fit([_row(count=10)], cutoff_ns=100)
    before = model.score_rows([_row()])
    with pytest.raises(ValueError, match="count"):
        model.fit([_row(count=200), _row(count=-1)], cutoff_ns=200)
    assert model.score_rows([_row()]) == before


def test_ipv6_ephemeral_port_is_generalized_without_losing_address_identity():
    model = _model().fit([_row(dst_type="socket", dst_semantic="socket:[2001:db8::8]:50100", count=20)], cutoff_ns=100)
    same, other = model.score_rows([
        _row(dst_type="socket", dst_semantic="socket:[2001:0db8:0:0:0:0:0:8]:60000"),
        _row(dst_type="socket", dst_semantic="socket:[2001:db8::9]:60000"),
    ])
    assert same["pattern_count"] == 20
    assert other["pattern_count"] == 0
