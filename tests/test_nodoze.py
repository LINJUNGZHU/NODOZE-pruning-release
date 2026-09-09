import pytest

from tc_pruning.models import EdgeRecord, NodeRecord, StoredEdge
from tc_pruning.nodoze import NODOZEFrequencyModel
from tc_pruning.store import ProvenanceStore


DAY_NS = 86_400_000_000_000


def test_nodoze_frequency_deduplicates_host_day_and_conditions_on_source_relation(
    tmp_path,
):
    observations = [
        NodeRecord("p", "process", "/bin/cat", "h1"),
        NodeRecord("f1", "file", "/etc/passwd", "h1"),
        NodeRecord("f2", "file", "/etc/hosts", "h1"),
        EdgeRecord("e1", "p", "f1", "EVENT_WRITE", DAY_NS, "h1"),
        EdgeRecord("e1-duplicate", "p", "f1", "EVENT_WRITE", DAY_NS + 1, "h1"),
        EdgeRecord("e2", "p", "f2", "EVENT_WRITE", DAY_NS + 2, "h1"),
        EdgeRecord("e3", "p", "f1", "EVENT_WRITE", 2 * DAY_NS, "h2"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        graph = store.extract_neighborhood(["p"], max_hops=1, max_edges=20)
        model = NODOZEFrequencyModel.from_store(store)

    probabilities = {
        edge.event_id: model.transition_probability(edge) for edge in graph.edges
    }
    assert probabilities["e1"] == 1.0
    assert probabilities["e1-duplicate"] == 1.0
    assert probabilities["e2"] == 0.5


def test_nodoze_path_score_multiplies_transition_stability_and_decay():
    edge = StoredEdge(
        edge_id=1,
        event_id="e",
        src="a",
        dst="b",
        relation="R",
        timestamp_ns=1,
        host="h",
        src_type="process",
        dst_type="file",
        src_semantic="process:a",
        dst_semantic="file:b",
    )
    model = NODOZEFrequencyModel(
        exact_counts={("process:a", "file:b", "R"): 1},
        source_relation_counts={("process:a", "R"): 2},
        total_days=4,
        incoming_active_days={"process:a": 1},
        outgoing_active_days={"file:b": 1},
    )

    score = model.score_path([edge], decay=0.9)

    assert score.regularity == pytest.approx(0.75 * 0.5 * 0.75 * 0.9)
    assert score.anomaly == pytest.approx(1.0 - score.regularity)


def test_path_score_normalizes_length_and_applies_decay_once():
    first = StoredEdge(
        1, "e1", "a", "b", "R", 1, "h", "process", "process",
        "process:a", "process:b",
    )
    second = StoredEdge(
        2, "e2", "b", "c", "R", 2, "h", "process", "process",
        "process:b", "process:c",
    )
    model = NODOZEFrequencyModel(
        exact_counts={
            ("process:a", "process:b", "R"): 1,
            ("process:b", "process:c", "R"): 1,
        },
        source_relation_counts={
            ("process:a", "R"): 2,
            ("process:b", "R"): 2,
        },
        total_days=1,
    )

    short = model.score_path([first], decay=0.9)
    long = model.score_path([first, second], decay=0.9)

    assert short.regularity == pytest.approx(0.45)
    assert long.regularity == pytest.approx(0.45)
    assert long.anomaly == pytest.approx(short.anomaly)


def test_unseen_transition_does_not_force_every_context_path_to_exactly_one():
    alert = StoredEdge(
        1, "alert", "a", "b", "ALERT", 1, "h", "process", "process",
        "process:a", "process:b",
    )
    normal = StoredEdge(
        2, "normal", "b", "c", "R", 2, "h", "process", "process",
        "process:b", "process:c",
    )
    model = NODOZEFrequencyModel(
        exact_counts={("process:b", "process:c", "R"): 1},
        source_relation_counts={("process:b", "R"): 2},
        total_days=10,
    )

    score = model.score_path([alert, normal])

    assert 0.0 < score.regularity < 0.5
    assert score.anomaly < 1.0


def test_alert_anchor_is_excluded_when_scoring_its_context():
    alert = StoredEdge(
        1, "alert", "a", "b", "ALERT", 1, "h", "process", "process",
        "process:a", "process:b",
    )
    context = StoredEdge(
        2, "context", "b", "c", "R", 2, "h", "process", "process",
        "process:b", "process:c",
    )
    model = NODOZEFrequencyModel(
        exact_counts={("process:b", "process:c", "R"): 1},
        source_relation_counts={("process:b", "R"): 2},
        total_days=10,
    )

    anchored = model.score_path(
        [alert, context], decay=1.0, excluded_event_ids={"alert"}
    )
    context_only = model.score_path([context], decay=1.0)

    assert anchored.regularity == pytest.approx(context_only.regularity)
    assert anchored.anomaly == pytest.approx(context_only.anomaly)


def test_unseen_semantic_transition_backs_off_to_type_relation_frequency():
    edge = StoredEdge(
        1, "e", "a", "b", "R", 1, "h", "process", "file",
        "process:unseen", "file:/unseen",
    )
    model = NODOZEFrequencyModel(
        exact_counts={},
        source_relation_counts={},
        total_days=10,
        type_exact_counts={("process", "file", "R"): 5},
        type_source_relation_counts={("process", "R"): 10},
        backoff_discount=0.1,
    )

    assert model.transition_probability(edge) == pytest.approx(0.05)


def test_zero_stability_does_not_erase_transition_frequency_difference():
    common = StoredEdge(
        1, "common", "a", "b", "R", 1, "h", "process", "process",
        "process:a", "process:b",
    )
    less_common = StoredEdge(
        2, "less", "a", "c", "R", 2, "h", "process", "process",
        "process:a", "process:c",
    )
    model = NODOZEFrequencyModel(
        exact_counts={
            ("process:a", "process:b", "R"): 2,
            ("process:a", "process:c", "R"): 1,
        },
        source_relation_counts={("process:a", "R"): 2},
        total_days=1,
        incoming_active_days={"process:a": 1},
        outgoing_active_days={"process:b": 1, "process:c": 1},
        stability_floor=0.05,
    )

    common_score = model.score_path([common], decay=1.0)
    less_common_score = model.score_path([less_common], decay=1.0)

    assert common_score.regularity == pytest.approx(0.0025)
    assert less_common_score.regularity == pytest.approx(0.00125)
    assert common_score.anomaly < less_common_score.anomaly


def test_score_paths_projects_max_path_anomaly_to_each_contained_edge():
    def edge(edge_id, src, dst, probability_count):
        return StoredEdge(
            edge_id,
            f"e{edge_id}",
            src,
            dst,
            "R",
            edge_id,
            "h",
            "process",
            "process",
            f"process:{src}",
            f"process:{dst}",
        )

    common = edge(1, "a", "b", 1)
    rare = edge(2, "b", "c", 1)
    model = NODOZEFrequencyModel(
        exact_counts={
            ("process:a", "process:b", "R"): 2,
            ("process:b", "process:c", "R"): 1,
        },
        source_relation_counts={
            ("process:a", "R"): 2,
            ("process:b", "R"): 4,
        },
        total_days=1,
    )

    result = model.score_paths([[common], [common, rare]], decay=1.0)

    assert result.edge_importance[1] == result.path_scores[1].anomaly
    assert result.edge_importance[2] == result.path_scores[1].anomaly
    assert result.path_scores[1].anomaly > result.path_scores[0].anomaly


def test_frequency_cutoff_excludes_alert_and_future_events(tmp_path):
    observations = [
        NodeRecord("p", "process", "p", "h"),
        NodeRecord("normal", "file", "/normal", "h"),
        NodeRecord("rare", "file", "/rare", "h"),
        EdgeRecord("history", "p", "normal", "R", DAY_NS, "h"),
        EdgeRecord("alert", "p", "rare", "R", 2 * DAY_NS, "h"),
    ]
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(observations)
        graph = store.extract_neighborhood(["p"], max_hops=1, max_edges=10)
        model = NODOZEFrequencyModel.from_store(
            store, before_timestamp_ns=2 * DAY_NS
        )

    edges = {edge.event_id: edge for edge in graph.edges}
    assert model.transition_probability(edges["history"]) == 1.0
    assert model.transition_probability(edges["alert"]) == pytest.approx(0.1)


def test_data_entity_in_out_scores_follow_nodoze_file_heuristics():
    model = NODOZEFrequencyModel(
        exact_counts={},
        source_relation_counts={},
        total_days=10,
        incoming_active_days={"file:/tmp/output": 2},
        outgoing_active_days={"file:/tmp/output": 0},
        semantic_types={
            "file:/tmp/output": "file",
            "file:/opt/payload.exe": "file",
            "file:/etc/hosts": "file",
            "socket:203.0.113.1:443": "socket",
        },
    )

    assert model.in_score("file:/tmp/output") == 1.0
    assert model.out_score("file:/tmp/output") == 1.0
    assert model.in_score("file:/opt/payload.exe") == 0.1
    assert model.out_score("file:/opt/payload.exe") == 0.1
    assert model.in_score("file:/etc/hosts") == 0.5
    assert model.out_score("socket:203.0.113.1:443") == 0.5
