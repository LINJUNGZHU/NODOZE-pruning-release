from tc_pruning.frequency_cache import FrequencyCache
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.nodoze import DAY_NS, NODOZEFrequencyModel
from tc_pruning.frequency import FrequencyModel
from tc_pruning.store import ProvenanceStore
from tc_pruning.causal import DirectionalEdgeCache


def test_offline_cache_serves_nodoze_and_rarity_without_raw_edge_group_by(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h", "proc:p"),
            NodeRecord("f", "file", "f", "h", "file:f"),
            EdgeRecord("e1", "p", "f", "WRITE", DAY_NS + 1, "h"),
            EdgeRecord("e2", "p", "f", "WRITE", DAY_NS + 2, "h"),
            EdgeRecord("e3", "p", "f", "WRITE", 2 * DAY_NS + 1, "h"),
        ])
        summary = FrequencyCache(store).build()
        assert summary["source_edges"] == 3

        store.conn.set_authorizer(
            lambda action, arg1, arg2, db, trigger: (
                1 if action == 20 and arg1 == "edges" else 0
            )
        )
        nodoze = NODOZEFrequencyModel.from_cache(
            store, before_timestamp_ns=3 * DAY_NS
        )
        rarity = FrequencyModel.from_cache(store, before_timestamp_ns=3 * DAY_NS)
        store.conn.set_authorizer(None)

    assert nodoze.exact_counts[("proc:p", "file:f", "WRITE")] == 2
    assert nodoze.source_relation_counts[("proc:p", "WRITE")] == 2
    assert rarity.relation_counts["WRITE"] == 3
    assert rarity.pattern_counts[("process", "WRITE", "file")] == 3


def test_cache_uses_completed_days_only_to_prevent_future_leakage(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h", "p"),
            NodeRecord("f", "file", "f", "h", "f"),
            EdgeRecord("old", "p", "f", "WRITE", DAY_NS + 1, "h"),
            EdgeRecord("future-same-day", "p", "f", "WRITE", 2 * DAY_NS + 100, "h"),
        ])
        FrequencyCache(store).build()
        model = FrequencyModel.from_cache(
            store, before_timestamp_ns=2 * DAY_NS + 50
        )

    assert model.relation_counts == {"WRITE": 1}


def test_ubc_manifest_places_each_poi_in_an_independent_group(tmp_path):
    # The manifest contract itself is enough to ensure run_experiment does not
    # merge multiple POIs into one initial search group.
    from tc_pruning.ubc_groundtruth import _poi_groups

    assert _poi_groups(["p1", "p2"]) == [
        {"group_id": "poi:p1", "seed_event_ids": ["p1"]},
        {"group_id": "poi:p2", "seed_event_ids": ["p2"]},
    ]


def test_directional_cache_loads_each_node_direction_once(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([
            NodeRecord("a", "process", "a", "h"),
            NodeRecord("b", "process", "b", "h"),
            EdgeRecord("e1", "a", "b", "R", 10, "h"),
            EdgeRecord("e2", "a", "b", "R", 20, "h"),
        ])
        cache = DirectionalEdgeCache(store)
        assert [e.event_id for e in cache.get("b", "backward", 25)] == ["e2", "e1"]
        assert [e.event_id for e in cache.get("b", "backward", 15)] == ["e1"]
        assert cache.db_queries == 1
        assert cache.cache_hits == 1


def test_directional_edge_query_uses_covering_edge_index_without_per_row_node_joins(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([
            NodeRecord("a", "process", "a", "h", "a"),
            NodeRecord("b", "file", "b", "h", "b"),
            EdgeRecord("e", "a", "b", "WRITE", 10, "h"),
        ])
        statements = []
        store.conn.set_trace_callback(statements.append)
        edges = store.get_directional_edges(
            "b", direction="backward", minimum_time_ns=None, maximum_time_ns=10
        )
        store.conn.set_trace_callback(None)

    assert edges[0].src_type == "process"
    directional = [sql for sql in statements if "FROM edges" in sql]
    assert directional
    assert all("JOIN nodes" not in sql for sql in directional)
