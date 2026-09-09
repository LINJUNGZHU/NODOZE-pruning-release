import math

import pytest

from tc_pruning.depimpact import (
    backpropagate_dependency_impact,
    compute_depimpact_relevance,
    concentration_ratio,
    data_flow_relevance,
    merge_parallel_edges,
    temporal_relevance,
)
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge


SECOND = 1_000_000_000


def _edge(edge_id, src, dst, timestamp_ns, data_size=None, relation="EVENT_WRITE"):
    return StoredEdge(
        edge_id=edge_id,
        event_id=f"e{edge_id}",
        src=src,
        dst=dst,
        relation=relation,
        timestamp_ns=timestamp_ns,
        host="h",
        src_type="process",
        dst_type="file",
        data_size=data_size,
    )


def test_parallel_edges_merge_only_within_ten_seconds():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "ab"},
        edges=[
            _edge(1, "a", "b", 0, 10),
            _edge(2, "a", "b", 10 * SECOND, 20),
            _edge(3, "a", "b", 21 * SECOND, 30),
        ],
    )

    merged = merge_parallel_edges(graph, threshold_seconds=10.0)

    assert merged.merged_edge_count == 2
    assert merged.groups[1] == (1, 2)
    assert merged.groups[3] == (3,)
    assert merged.edges[0].data_size == 30
    assert merged.edges[0].timestamp_ns == 10 * SECOND


def test_depimpact_feature_formulas_match_the_paper():
    assert data_flow_relevance(90, 100, alpha=1e-4) == pytest.approx(1 / 10.0001)
    assert data_flow_relevance(None, 100, alpha=1e-4) is None
    assert temporal_relevance(2 * SECOND, 1 * SECOND) == pytest.approx(math.log(2.0))
    assert temporal_relevance(1 * SECOND, 1 * SECOND) == pytest.approx(math.log1p(1e10))

    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "a", "b", 1),
            _edge(2, "c", "b", 2),
            _edge(3, "b", "d", 3),
        ],
    )
    assert concentration_ratio(graph, graph.edges[0]) == pytest.approx(1 / 2)


def test_projection_prefers_poi_like_edge_and_normalizes_per_source():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcde"},
        edges=[
            _edge(1, "a", "b", 100 * SECOND, 100),
            _edge(2, "a", "c", 101 * SECOND, 105),
            _edge(3, "a", "d", 10 * SECOND, 10_000),
            _edge(4, "e", "d", 9 * SECOND, None),
        ],
    )

    result = compute_depimpact_relevance(graph, poi_edge_ids={1})

    assert result.normalized_edge_weights[2] > result.normalized_edge_weights[3]
    assert sum(result.normalized_edge_weights[index] for index in (1, 2, 3)) == pytest.approx(0.99)
    assert result.data_size_coverage == pytest.approx(0.75)
    assert len(result.projection) == 3


def test_depimpact_propagates_once_per_merged_dependency():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abc"},
        edges=[
            _edge(1, "a", "b", 1 * SECOND),
            _edge(2, "a", "b", 2 * SECOND),
            _edge(3, "b", "c", 20 * SECOND),
        ],
    )

    result = compute_depimpact_relevance(graph, poi_edge_ids={3})

    assert result.merged_edge_count == 2
    assert result.edge_importance[1] == pytest.approx(result.edge_importance[2])
    assert result.node_impacts["a"] < result.node_impacts["b"]
    assert result.node_impacts["a"] <= 0.99 * result.node_impacts["b"] + 1e-12


def test_missing_data_size_does_not_create_a_synthetic_projection_signal():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[
            _edge(1, "a", "b", 1 * SECOND),
            _edge(2, "b", "c", 2 * SECOND),
            _edge(3, "c", "d", 3 * SECOND),
        ],
    )

    result = compute_depimpact_relevance(graph, poi_edge_ids={3})

    assert result.data_size_coverage == 0.0
    assert result.projection[0] == pytest.approx(0.0)


def test_dependency_impact_backpropagates_to_frequent_bridge_until_convergence():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcde"},
        edges=[
            _edge(1, "a", "b", 1),
            _edge(2, "b", "c", 2),
            _edge(3, "b", "d", 2),
            _edge(4, "c", "e", 3),
        ],
    )
    weights = {1: 1.0, 2: 0.9, 3: 0.1, 4: 1.0}

    result = backpropagate_dependency_impact(
        graph,
        poi_edge_ids={4},
        edge_weights=weights,
        tolerance=1e-13,
    )

    assert result.converged is True
    assert result.node_impacts["e"] == pytest.approx(1.0)
    assert result.node_impacts["c"] == pytest.approx(1.0)
    assert result.node_impacts["b"] == pytest.approx(0.9)
    assert result.node_impacts["a"] == pytest.approx(0.9)
    assert result.edge_impacts[2] > result.edge_impacts[3]
    assert result.diagnostics
    assert max(row["max_reached_hop"] for row in result.diagnostics) >= 2
    assert result.diagnostics[-1]["nonzero_nodes"] == 4


def test_depimpact_precomputes_degrees_instead_of_rescanning_edges_per_feature():
    class CountingEdges(list):
        iterations = 0

        def __iter__(self):
            type(self).iterations += 1
            return super().__iter__()

    edges = CountingEdges(
        [_edge(index, f"n{index}", f"n{index + 1}", index * SECOND)
         for index in range(1, 21)]
    )
    graph = Neighborhood(nodes={}, edges=edges)

    compute_depimpact_relevance(graph, poi_edge_ids={19, 20}, kmeans_restarts=1)

    assert CountingEdges.iterations < 20


def test_depimpact_exposes_table7_phase_timings_and_fixed_projection():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[_edge(1, "a", "b", 1), _edge(2, "b", "c", 2), _edge(3, "c", "d", 3)],
    )
    result = compute_depimpact_relevance(
        graph, poi_edge_ids={3}, projection_override=(0.334, 0.333, 0.333)
    )
    assert result.projection == (0.334, 0.333, 0.333)
    assert set(result.phase_seconds) == {
        "edge_merge", "dependency_weight_computation",
        "dependency_impact_propagation", "total",
    }


def test_depimpact_temporal_only_feature_ablation_is_auditable():
    graph = Neighborhood(
        nodes={name: NodeRecord(name, "process", name) for name in "abcd"},
        edges=[_edge(1, "a", "b", 1), _edge(2, "b", "c", 2), _edge(3, "c", "d", 3)],
    )
    result = compute_depimpact_relevance(
        graph, poi_edge_ids={3}, feature_mask=(False, True, False)
    )
    assert result.feature_mask == (False, True, False)
    assert result.projection == (0.0, 1.0, 0.0)
