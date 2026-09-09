import sqlite3

from tc_pruning.frequency import FrequencyModel
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _observations():
    return [
        EdgeRecord("e-before", "p-late", "f-1", "EVENT_READ", 1, "h"),
        NodeRecord("p-late", "process", "/bin/cat", "h"),
        NodeRecord("p-2", "process", "/bin/cat", "h"),
        NodeRecord("f-1", "file", "/etc/hosts", "h"),
        NodeRecord("f-2", "file", "/etc/passwd", "h"),
        NodeRecord("s-1", "socket", "10.0.0.9:4444", "h"),
        EdgeRecord("e-1", "f-1", "p-late", "EVENT_READ", 2, "h"),
        EdgeRecord("e-2", "f-2", "p-2", "EVENT_READ", 3, "h"),
        EdgeRecord("e-rare", "p-late", "s-1", "EVENT_CONNECT", 4, "h"),
    ]


def test_ingest_is_idempotent_and_late_node_replaces_placeholder(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        first = store.ingest(_observations())
        second = store.ingest(_observations())

        assert first.nodes_seen == 5
        assert first.edges_inserted == 4
        assert second.edges_inserted == 0
        assert store.node_count() == 5
        assert store.edge_count() == 4
        assert store.get_node("p-late") == NodeRecord(
            "p-late", "process", "/bin/cat", "h"
        )


def test_extract_neighborhood_walks_both_edge_directions(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_observations())

        graph = store.extract_neighborhood(["p-late"], max_hops=1, max_edges=20)

        assert set(graph.nodes) == {"p-late", "f-1", "s-1"}
        assert {edge.event_id for edge in graph.edges} == {
            "e-before",
            "e-1",
            "e-rare",
        }


def test_frequency_model_scores_rare_relation_above_common_relation(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(_observations())
        graph = store.extract_neighborhood(["p-late"], max_hops=2, max_edges=20)
        model = FrequencyModel.from_store(store)

        scores = {edge.event_id: model.edge_rarity(edge) for edge in graph.edges}

        assert 0.0 <= min(scores.values()) <= max(scores.values()) <= 1.0
        assert scores["e-rare"] > scores["e-1"]


def test_store_migrates_legacy_nodes_and_persists_semantic_fields(tmp_path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE nodes (
                uuid TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                host TEXT NOT NULL
            );
            CREATE TABLE edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                relation TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                host TEXT NOT NULL
            );
            INSERT INTO nodes VALUES ('old-p', 'process', '/bin/cat', 'h');
            """
        )

    with ProvenanceStore(database) as store:
        migrated = store.get_node("old-p")
        store.ingest(
            [
                NodeRecord(
                    "new-f",
                    "file",
                    "/home/bob/a.txt",
                    "h",
                    semantic_key="file:/home/*/a.txt",
                    properties={"path": "/home/bob/a.txt"},
                )
            ]
        )

        assert migrated.semantic_key == "/bin/cat"
        assert migrated.properties == {}
        assert store.get_node("new-f").semantic_key == "file:/home/*/a.txt"
        assert store.get_node("new-f").properties == {"path": "/home/bob/a.txt"}


def test_repeated_semantic_node_observation_does_not_write_again(tmp_path):
    node = NodeRecord(
        "p",
        "process",
        "python3",
        "h",
        properties={"exec": "python3"},
    )
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest([node])
        before = store.conn.total_changes
        store.ingest([node])

        assert store.conn.total_changes == before


def test_conflicting_event_uuid_keeps_both_distinct_events(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(
            [
                NodeRecord("a", "process", "a", "h"),
                NodeRecord("b", "file", "b", "h"),
                EdgeRecord("same-event", "a", "b", "EVENT_WRITE", 10, "h"),
                EdgeRecord("same-event", "a", "b", "EVENT_WRITE", 20, "h"),
            ]
        )

        rows = list(
            store.conn.execute(
                "SELECT event_id, original_event_id, timestamp_ns FROM edges ORDER BY timestamp_ns"
            )
        )

    assert len(rows) == 2
    assert [row["original_event_id"] for row in rows] == ["same-event", "same-event"]
    assert rows[0]["event_id"] == "same-event"
    assert rows[1]["event_id"].startswith("same-event#")


def test_frequency_model_excludes_events_at_or_after_cutoff(tmp_path):
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(
            [
                NodeRecord("p", "process", "p", "h"),
                NodeRecord("before", "file", "before", "h"),
                NodeRecord("future", "socket", "future", "h"),
                EdgeRecord("before", "p", "before", "EVENT_READ", 10, "h"),
                EdgeRecord("future", "p", "future", "EVENT_CONNECT", 20, "h"),
            ]
        )

        model = FrequencyModel.from_store(store, before_timestamp_ns=20)

    assert model.relation_counts == {"EVENT_READ": 1}
    assert ("process", "EVENT_CONNECT", "socket") not in model.pattern_counts
