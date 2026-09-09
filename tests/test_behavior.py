import pytest

from tc_pruning.behavior import (
    OOVEmbeddingCache,
    analyze_behaviors,
    entity_similarity,
    operation_transition_similarity,
)
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge


def _edge(edge_id, dst, relation, timestamp_ns):
    return StoredEdge(
        edge_id=edge_id,
        event_id=f"e{edge_id}",
        src="process",
        dst=dst,
        relation=relation,
        timestamp_ns=timestamp_ns,
        host="h",
        src_type="process",
        dst_type="file",
    )


def test_oov_embedding_reuses_exact_vectors_and_composes_known_tokens():
    cache = OOVEmbeddingCache(dimensions=16, minimum_token_frequency=1)
    cache.fit(["/usr/bin/nginx worker", "/usr/bin/nginx master"])

    known_first = cache.embed("/usr/bin/nginx worker")
    known_second = cache.embed("/usr/bin/nginx worker")
    partially_oov = cache.embed("/usr/bin/nginx unseen")
    entirely_oov = cache.embed("totally novel tokens")

    assert known_first == known_second
    assert any(value != 0.0 for value in partially_oov)
    assert entirely_oov == (0.0,) * 16


def test_entity_similarity_uses_path_and_ip_prefix_structure():
    cache = OOVEmbeddingCache(dimensions=8, minimum_token_frequency=1)
    cache.fit(["nginx", "bash"])

    assert entity_similarity("file", "/srv/www/a.txt", "/srv/www/b.txt", cache) > 0.7
    assert entity_similarity("socket", "192.168.1.10:80", "192.168.1.99:443", cache) == pytest.approx(25 / 32)
    assert entity_similarity("socket", "10.0.0.1", "192.168.1.1", cache) < 0.1


def test_operation_transition_recognizes_common_behavior_pairs():
    assert operation_transition_similarity("EVENT_READ", "EVENT_WRITE") == 1.0
    assert operation_transition_similarity("EVENT_WRITE", "EVENT_UNLINK") == 1.0
    assert operation_transition_similarity("EVENT_READ", "EVENT_ACCEPT") == 0.0


def test_long_process_is_partitioned_and_only_poi_behavior_gets_full_importance():
    second = 1_000_000_000
    graph = Neighborhood(
        nodes={
            "process": NodeRecord("process", "process", "nginx"),
            "a": NodeRecord("a", "file", "/srv/www/a"),
            "b": NodeRecord("b", "file", "/srv/www/b"),
            "secret": NodeRecord("secret", "file", "/etc/shadow"),
            "leak": NodeRecord("leak", "file", "/tmp/leak"),
        },
        edges=[
            _edge(1, "a", "EVENT_READ", 0),
            _edge(2, "b", "EVENT_WRITE", second),
            _edge(3, "secret", "EVENT_READ", 3_600 * second),
            _edge(4, "leak", "EVENT_WRITE", 3_601 * second),
        ],
    )

    result = analyze_behaviors(
        graph,
        poi_edge_ids={4},
        min_cluster_size=2,
        fallback_gap_seconds=30.0,
    )

    assert result.cluster_count == 2
    assert result.edge_importance[3] == 1.0
    assert result.edge_importance[4] == 1.0
    assert result.edge_importance[1] == 0.0
    assert result.edge_importance[2] == 0.0
