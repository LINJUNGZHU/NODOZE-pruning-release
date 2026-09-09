from tc_pruning.entry_ranking import (
    discover_attack_entries,
    discover_candidate_entries,
    evaluate_entry_ranks,
    noisy_or_node_scores,
)
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge


def _edge(edge_id, src, dst, relation="read", timestamp_ns=1):
    return StoredEdge(
        edge_id, f"e{edge_id}", src, dst, relation, timestamp_ns, "h",
        "file" if src.startswith("f") else "process",
        "socket" if dst.startswith("n") else "process",
    )


def test_discovers_candidate_and_truth_entries_without_using_scores():
    graph = Neighborhood(
        {
            "f": NodeRecord("f", "file", "/tmp/x"),
            "p": NodeRecord("p", "process", "sh"),
            "q": NodeRecord("q", "process", "curl"),
            "n": NodeRecord("n", "socket", "1.2.3.4"),
        },
        [_edge(1, "f", "p"), _edge(2, "p", "q"), _edge(3, "q", "n")],
    )
    assert discover_candidate_entries(graph) == {"f", "n"}
    assert discover_attack_entries(graph, {"f", "p", "q"}) == {"f"}


def test_entry_rank_is_per_category_uses_midranks_and_reports_coverage():
    graph = Neighborhood(
        {
            "f1": NodeRecord("f1", "file", "a"),
            "f2": NodeRecord("f2", "file", "b"),
            "p1": NodeRecord("p1", "process", "x"),
            "x": NodeRecord("x", "process", "sink"),
        },
        [_edge(1, "f1", "x"), _edge(2, "f2", "x"), _edge(3, "p1", "x")],
    )
    result = evaluate_entry_ranks(
        graph,
        method_node_scores={"depimpact": {"f1": 0.5, "f2": 0.5, "p1": 0.2}},
        attack_entry_nodes={"f1", "p1", "missing"},
        random_seed=7,
    )
    assert result["attack_entry_count"] == 3
    assert result["covered_attack_entry_count"] == 2
    assert result["attack_entry_coverage"] == 2 / 3
    assert result["methods"]["depimpact"]["ranks_by_node"]["f1"] == 1.5
    assert result["methods"]["depimpact"]["ranks_by_node"]["p1"] == 1.0
    assert result["methods"]["depimpact"]["average_rank"] == 1.25


def test_random_ranking_is_reproducible_and_noisy_or_is_monotone():
    graph = Neighborhood(
        {"f1": NodeRecord("f1", "file", "a"), "x": NodeRecord("x", "process", "x")},
        [_edge(1, "f1", "x")],
    )
    one = evaluate_entry_ranks(graph, method_node_scores={}, attack_entry_nodes={"f1"}, random_seed=11)
    two = evaluate_entry_ranks(graph, method_node_scores={}, attack_entry_nodes={"f1"}, random_seed=11)
    assert one["methods"]["uniform_random"] == two["methods"]["uniform_random"]
    assert noisy_or_node_scores([{"a": 0.2}, {"a": 0.5, "b": 0.4}]) == {"a": 0.6, "b": 0.4}
