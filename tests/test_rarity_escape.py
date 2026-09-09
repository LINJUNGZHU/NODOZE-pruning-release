from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.nodoze import NODOZEFrequencyModel
from tc_pruning.rarity_escape import compute_rarity_escape


def _edge(edge_id: int, dst: str, timestamp: int = 1) -> StoredEdge:
    return StoredEdge(
        edge_id=edge_id,
        event_id=f"event-{edge_id}",
        src="process",
        dst=dst,
        relation="EVENT_SENDTO",
        timestamp_ns=timestamp,
        host="host",
        src_type="process",
        dst_type="socket",
        src_semantic="process:sshd",
        dst_semantic=f"socket:{dst}:80",
        data_size=1,
    )


def test_escape_promotes_historically_novel_diffusion_disconnected_transition():
    edges = [_edge(1, "known"), _edge(2, "unseen"), _edge(3, "other")]
    graph = Neighborhood(
        {
            "process": NodeRecord("process", "process", "sshd"),
            **{
                edge.dst: NodeRecord(edge.dst, "socket", edge.dst)
                for edge in edges
            },
        },
        edges,
    )
    model = NODOZEFrequencyModel(
        exact_counts={
            ("process:sshd", "socket:known:80", "EVENT_SENDTO"): 9,
        },
        source_relation_counts={("process:sshd", "EVENT_SENDTO"): 10},
        total_days=10,
        incoming_active_days={"socket:known:80": 10},
        type_exact_counts={
            ("process", "socket", "EVENT_SENDTO"): 10,
        },
        type_source_relation_counts={("process", "EVENT_SENDTO"): 10},
    )

    result = compute_rarity_escape(
        graph,
        rarity={1: 0.8, 2: 0.8, 3: 0.8},
        diffusion_support={1: 0.0, 2: 0.0, 3: 0.5},
        history=model,
        absolute_threshold=0.5,
        score_quantile=0.5,
        maximum_diffusion=0.05,
    )

    assert result.scores[2] > result.scores[1]
    assert result.evidence[2]["destination_novelty"] == 1.0
    assert result.evidence[1]["destination_novelty"] == 0.0
    assert 2 in result.eligible_edge_ids
    assert 3 not in result.eligible_edge_ids
    assert result.evidence[3]["escape_eligible"] == 0.0


def test_escape_quantile_includes_all_cutoff_ties():
    edges = [_edge(1, "a"), _edge(2, "b"), _edge(3, "c")]
    graph = Neighborhood({}, edges)
    model = NODOZEFrequencyModel({}, {}, total_days=1)

    result = compute_rarity_escape(
        graph,
        rarity={1: 1.0, 2: 1.0, 3: 0.01},
        diffusion_support={1: 0.0, 2: 0.0, 3: 0.0},
        history=model,
        absolute_threshold=0.0,
        score_quantile=0.5,
        maximum_diffusion=0.05,
    )

    assert result.eligible_edge_ids == frozenset({1, 2})
    assert result.threshold == result.scores[1] == result.scores[2]
