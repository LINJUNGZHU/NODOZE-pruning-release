"""Window history is strictly past, bounded, and never changes legacy rarity."""
from copy import deepcopy
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from tc_pruning.frequency import FrequencyModel
from tc_pruning.frequency_cache import DAY_NS, FrequencyCache
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def api():
    from scripts import chain_workbench_history
    return chain_workbench_history


def candidate(**changes):
    value = {"event_id": "CANDIDATE", "src": "P", "dst": "F", "src_type": "process",
             "dst_type": "file", "src_semantic": "process:/bin/app",
             "dst_semantic": "file:/etc/config", "relation": "EVENT_WRITE",
             "timestamp_ns": 2 * DAY_NS + 100, "host": "H1",
             "components": {"rarity": 0.314159}}
    value.update(changes)
    return value


@pytest.fixture
def raw_database(tmp_path):
    path = tmp_path / "source data.db"
    with ProvenanceStore(path) as store:
        store.ingest([
            NodeRecord("P", "process", "app", "H1", "process:/bin/app"),
            NodeRecord("Q", "process", "other", "H1", "process:/bin/other"),
            NodeRecord("F", "file", "config", "H1", "file:/etc/config"),
            EdgeRecord("TOO_OLD", "P", "F", "EVENT_WRITE", DAY_NS - 1, "H1"),
            EdgeRecord("LOWER_BOUND", "P", "F", "EVENT_WRITE", DAY_NS, "H1"),
            EdgeRecord("HISTORY", "P", "F", "EVENT_WRITE", DAY_NS + 3, "H1"),
            EdgeRecord("OTHER_HOST", "P", "F", "EVENT_WRITE", DAY_NS + 4, "H2"),
            EdgeRecord("OTHER_PROGRAM", "Q", "F", "EVENT_WRITE", DAY_NS + 5, "H1"),
            EdgeRecord("RECENT", "P", "F", "EVENT_READ", 2 * DAY_NS - 1, "H1"),
            EdgeRecord("AT_CUTOFF", "P", "F", "EVENT_WRITE", 2 * DAY_NS, "H1"),
            EdgeRecord("CANDIDATE", "P", "F", "EVENT_WRITE", 2 * DAY_NS + 100, "H1"),
        ])
    return path


@pytest.fixture
def cached_database(raw_database):
    with ProvenanceStore(raw_database) as store:
        FrequencyCache(store).build()
    return raw_database


def test_raw_history_strict_past_exact_context_and_weighted_aggregation(raw_database):
    history, provenance = api().prepare_history(raw_database, [candidate()], 2 * DAY_NS)
    assert {(r["relation"], r["count"], r["timestamp_ns"]) for r in history} == {
        ("EVENT_WRITE", 2, DAY_NS + 3), ("EVENT_READ", 1, 2 * DAY_NS - 1)}
    assert all(r["timestamp_ns"] < 2 * DAY_NS and r["host"] == "H1" for r in history)
    assert provenance["mode"] == "recent_raw_history"
    assert provenance["history_certified_benign"] is False
    assert provenance["node_metadata_time_safety_verified"] is False
    assert provenance["history_truncated"] is False
    assert any("SEARCH edges USING INDEX idx_edges_time" in p for p in provenance["query_plan"])


def test_raw_limit_is_global_last_events_before_postfilter(raw_database):
    history, provenance = api().prepare_history(raw_database, [candidate()], 2 * DAY_NS,
                                                max_recent_events=2)
    assert sum(r["count"] for r in history) == 1
    assert history[0]["relation"] == "EVENT_READ"
    assert provenance["history_truncated"] is True
    assert provenance["raw_rows_fetched"] == 3
    assert provenance["raw_rows_considered"] == 2
    assert provenance["history_limit_scope"] == "global_pre_window_events_before_host_and_program_filter"


def test_cache_history_excludes_entire_current_day(cached_database):
    history, provenance = api().prepare_history(cached_database, [candidate()], 2 * DAY_NS + 50)
    assert sum(r["count"] for r in history) == 4
    assert all(r["timestamp_ns"] == 2 * DAY_NS - 1 for r in history)
    assert provenance["mode"] == "completed_day_cache"
    assert provenance["complete_days_only"] is True
    assert provenance["program_semantics"] == ["process:/bin/app"]


def test_explicit_history_database_is_used_not_candidates(raw_database, tmp_path):
    other = tmp_path / "history.db"
    with ProvenanceStore(other) as store:
        store.ingest([NodeRecord("P", "process", "app", "H1", "process:/bin/app"),
                      NodeRecord("F", "file", "config", "H1", "file:/etc/config"),
                      EdgeRecord("EXPLICIT", "P", "F", "EVENT_EXECUTE", DAY_NS + 2, "H1")])
        FrequencyCache(store).build()
    history, provenance = api().prepare_history(raw_database, [candidate()], 2 * DAY_NS,
                                                history_database=other)
    assert len(history) == 1 and history[0]["relation"] == "EVENT_EXECUTE"
    assert provenance["history_database_explicit"] is True
    assert provenance["database"] == str(other.resolve())


def test_no_prewindow_data_is_explicit_cold_start(raw_database):
    history, provenance = api().prepare_history(raw_database, [candidate()], DAY_NS - 5)
    assert history == [] and provenance["cold_start"] is True
    assert provenance["historical_event_count"] == 0


@pytest.mark.parametrize("key,value", [("stale", "1"), ("version", "999"), ("maximum_timestamp_ns", "0")])
def test_stale_cache_never_silently_uses_raw_history(cached_database, key, value):
    with sqlite3.connect(cached_database) as conn:
        conn.execute("UPDATE frequency_cache_meta SET value=? WHERE key=?", (value, key))
    with pytest.raises(RuntimeError, match="cache"):
        api().prepare_history(cached_database, [candidate()], 2 * DAY_NS)
    with pytest.raises(RuntimeError, match="cache"):
        api().complete_missing_rarity(cached_database, [candidate(components={})], 2 * DAY_NS)


def test_missing_time_index_fails_instead_of_scanning(raw_database):
    with sqlite3.connect(raw_database) as conn:
        conn.execute("DROP INDEX idx_edges_time")
    with pytest.raises(RuntimeError, match="index"):
        api().prepare_history(raw_database, [candidate()], 2 * DAY_NS)


@pytest.mark.parametrize("cutoff,limit", [(True, 10), (-1, 10), (1.5, 10), (2 * DAY_NS, 0),
                                          (2 * DAY_NS, True), (2 * DAY_NS, 250001)])
def test_invalid_window_or_limit_is_rejected(raw_database, cutoff, limit):
    with pytest.raises(ValueError):
        api().prepare_history(raw_database, [candidate()], cutoff, max_recent_events=limit)


def test_history_ignores_labels_and_input_order(raw_database):
    rows = [candidate(), candidate(event_id="SECOND")]
    first = api().prepare_history(raw_database, rows, 2 * DAY_NS)
    for row in rows:
        row.update(is_attack=True, ground_truth={"semantic": "EVIL"}, attack_label="exploit")
    assert api().prepare_history(raw_database, rows[::-1], 2 * DAY_NS) == first


def test_fill_rarity_uses_original_frequency_model_and_preserves_values(cached_database):
    rows = [candidate(), candidate(event_id="NEW", components={"diffusion": 0.5})]
    original = deepcopy(rows)
    with sqlite3.connect(cached_database) as conn:
        model = FrequencyModel.from_cache(SimpleNamespace(conn=conn), before_timestamp_ns=2 * DAY_NS)
        expected = model.edge_rarity(SimpleNamespace(src_type="process", dst_type="file", relation="EVENT_WRITE"))
    filled, provenance = api().complete_missing_rarity(cached_database, rows, 2 * DAY_NS)
    assert rows == original
    assert filled[0]["components"]["rarity"] == 0.314159
    assert filled[1]["components"] == {"rarity": expected, "diffusion": 0.5}
    assert provenance["filled_rows"] == 1 and provenance["preserved_rows"] == 1
    assert provenance["model"] == "tc_pruning.frequency.FrequencyModel"


def test_fill_existing_values_needs_no_cache(raw_database):
    rows = [candidate()]
    filled, provenance = api().complete_missing_rarity(raw_database, rows, 2 * DAY_NS)
    assert filled == rows and provenance["filled_rows"] == 0


def test_fill_missing_values_requires_valid_cache(raw_database):
    with pytest.raises(RuntimeError, match="cache"):
        api().complete_missing_rarity(raw_database, [candidate(components={})], 2 * DAY_NS)


def test_readonly_methods_do_not_mutate_db(cached_database):
    before = hashlib.sha256(cached_database.read_bytes()).digest()
    api().prepare_history(cached_database, [candidate()], 2 * DAY_NS)
    api().complete_missing_rarity(cached_database, [candidate(components={})], 2 * DAY_NS)
    assert hashlib.sha256(cached_database.read_bytes()).digest() == before


def test_readonly_fallback_does_not_create_cache(raw_database):
    before = hashlib.sha256(raw_database.read_bytes()).digest()
    api().prepare_history(raw_database, [candidate()], 2 * DAY_NS)
    assert hashlib.sha256(raw_database.read_bytes()).digest() == before


def test_count_scan_is_not_used_to_fill_rarity(cached_database, monkeypatch):
    import scripts.adaptive_chain_inputs as inputs
    original_connect = inputs._connect
    statements = []

    def connect(path):
        conn = original_connect(path)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(api(), "_connect", connect)
    api().complete_missing_rarity(cached_database, [candidate(components={})], 2 * DAY_NS)
    assert not any("COUNT(" in statement.upper() for statement in statements)
    assert any("freq_node_type_first_daily" in statement for statement in statements)


@pytest.mark.parametrize("value", [None, float("nan"), float("inf"), -0.1, 1.1, True])
def test_invalid_existing_rarity_is_not_silently_replaced(raw_database, value):
    with pytest.raises(ValueError, match="rarity"):
        api().complete_missing_rarity(raw_database, [candidate(components={"rarity": value})], 2 * DAY_NS)
