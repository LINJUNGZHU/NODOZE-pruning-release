import sqlite3

from tc_pruning.frequency_cache import FrequencyCache
from tc_pruning.frequency_snapshot import compile_snapshot, load_snapshot
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.nodoze import DAY_NS
from tc_pruning.store import ProvenanceStore


def test_compiled_snapshot_round_trips_both_models_without_database_queries(tmp_path):
    database = tmp_path / "graph.db"
    output = tmp_path / "before-day-2.pkl.gz"
    with ProvenanceStore(database) as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h", "proc:p"),
            NodeRecord("f", "file", "f", "h", "file:f"),
            EdgeRecord("e", "p", "f", "WRITE", DAY_NS + 1, "h"),
        ])
        FrequencyCache(store).build()
        metadata = compile_snapshot(store, 2 * DAY_NS, output)
        assert metadata["cutoff_day_exclusive"] == 2

    connection = sqlite3.connect(database)
    connection.set_authorizer(lambda *args: 7)
    snapshot = load_snapshot(output)
    connection.close()

    assert snapshot.nodoze.exact_counts[("proc:p", "file:f", "WRITE")] == 1
    assert snapshot.rarity.relation_counts == {"WRITE": 1}
    assert snapshot.cutoff_day_exclusive == 2
