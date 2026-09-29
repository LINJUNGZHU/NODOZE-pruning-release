"""Historical frequencies and reference paths remain independent of online scores."""
from copy import deepcopy
import hashlib
import importlib.util
import sqlite3

import pytest

from tc_pruning.frequency_cache import DAY_NS, FrequencyCache
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def api():
    assert importlib.util.find_spec("scripts.adaptive_chain_inputs") is not None, "offline input helpers have not been implemented"
    from scripts import adaptive_chain_inputs
    return adaptive_chain_inputs


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "source data.db"
    with ProvenanceStore(path) as store:
        store.ingest([
            NodeRecord("P", "process", "app", "H1", "process:/bin/app"),
            NodeRecord("F", "file", "config", "H1", "file:/etc/config"),
            EdgeRecord("UUID#abcdef", "P", "F", "EVENT_WRITE", DAY_NS + 1, "H1"),
            EdgeRecord("E2", "P", "F", "EVENT_WRITE", DAY_NS + 2, "H1"),
            EdgeRecord("E3", "P", "F", "EVENT_WRITE", 2 * DAY_NS + 1, "H1"),
            EdgeRecord("OTHER", "P", "F", "EVENT_WRITE", DAY_NS + 3, "H2"),
            EdgeRecord("UNKNOWN", "P", "F", "EVENT_WRITE", DAY_NS + 4, ""),
        ])
        FrequencyCache(store).build()
    return path


def edge(event, src, dst, timestamp, relation="EVENT_WRITE", host="H1"):
    return {"event_id": event, "src": src, "dst": dst,
            "timestamp_ns": timestamp, "relation": relation, "host": host}


def test_history_sums_counts_with_host_separation_and_excludes_current_day(database):
    rows, provenance = api().load_historical_rows(database, 2 * DAY_NS + 50, ["H1", "H2"])
    assert {(r["host"], r["count"]) for r in rows} == {("H1", 2), ("H2", 1)}
    assert all(r["src_type"] == "process" and r["dst_type"] == "file" for r in rows)
    assert all(r["timestamp_ns"] == 2 * DAY_NS - 1 for r in rows)
    assert all(r["event_count"] == r["count"] for r in rows)
    assert provenance["cutoff_day_exclusive"] == 2
    assert provenance["complete_days_only"] is True
    assert provenance["timestamp_is_aggregate_boundary"] is True
    assert "current day" in provenance["temporal_scope"]
    assert any("SEARCH freq_event_daily" in plan for plan in provenance["query_plan"])
    assert all("SCAN edges" not in plan for plan in provenance["freshness_query_plan"])


def test_history_aggregates_multiple_completed_days_for_one_semantic_pattern(database):
    rows, provenance = api().load_historical_rows(database, 3 * DAY_NS, ["H1"])
    assert len(rows) == 1
    assert rows[0]["count"] == 3
    assert rows[0]["src_semantic"] == "process:/bin/app"
    assert rows[0]["dst_semantic"] == "file:/etc/config"
    assert provenance["historical_event_count"] == 3


@pytest.mark.parametrize("hosts", [[], [None], [""], ["  "], ["H1", None]])
def test_history_requires_explicit_known_hosts(database, hosts):
    with pytest.raises(ValueError, match="host"):
        api().load_historical_rows(database, 2 * DAY_NS, hosts)


def test_missing_frequency_cache_fails_without_scanning_raw_events(tmp_path):
    path = tmp_path / "no_cache.db"
    with ProvenanceStore(path):
        pass
    with pytest.raises(RuntimeError, match="build-frequency-cache"):
        api().load_historical_rows(path, 2 * DAY_NS, ["H1"])


@pytest.mark.parametrize("key,value", [("stale", "1"), ("version", "999"), ("maximum_timestamp_ns", "1")])
def test_stale_or_incompatible_cache_is_rejected(database, key, value):
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE frequency_cache_meta SET value=? WHERE key=?", (value, key))
    with pytest.raises(RuntimeError, match="cache"):
        api().load_historical_rows(database, 2 * DAY_NS, ["H1"])


def test_source_lookup_resolves_hash_case_and_returns_semantic_fields(database):
    rows = api().load_source_events(database, ["UUID#ABCDEF", "E2", "MISSING", "uuid#abcdef"])
    assert {r["event_id"] for r in rows} == {"UUID#ABCDEF", "E2"}
    first = next(r for r in rows if r["event_id"] == "UUID#ABCDEF")
    assert first["src_semantic"] == "process:/bin/app"
    assert first["dst_semantic"] == "file:/etc/config"
    assert first["src_type"] == "process"
    assert first["edge_id"] > 0


def test_readonly_input_loaders_do_not_change_database_bytes(database):
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    api().load_historical_rows(database, 2 * DAY_NS, ["H1"])
    api().load_source_events(database, ["UUID#ABCDEF"])
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_empty_source_lookup_returns_no_events(database):
    assert api().load_source_events(database, []) == []


def test_reference_derivation_preserves_every_branch_or_reports_singletons():
    rows = [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2),
            edge("E3", "B", "D", 3), edge("E4", "C", "E", 4),
            edge("SINGLE", "X", "Y", 5)]
    chains, diagnostics = api().derive_reference_chains(rows, "reference.json:sha256:abcd")
    assert {tuple(c["event_ids"]) for c in chains} == {("E1", "E2", "E4"), ("E1", "E3")}
    assert diagnostics["singletons"] == ["SINGLE"]
    assert diagnostics["covered_event_count"] == 4
    assert diagnostics["source_positive_event_count"] == 5
    assert diagnostics["length_min"] == 2 and diagnostics["length_max"] == 3
    assert diagnostics["exhaustive_path_enumeration"] is False
    assert all(c["provenance"]["kind"] == "derived_reference" and c["scope_complete"] is False for c in chains)
    assert all("not complete attacks" in c["provenance"]["scope"] for c in chains)


def test_reference_derivation_covers_short_branch_at_merge_even_when_longest_path_omits_it():
    rows = [edge("LONG1", "A", "B", 1), edge("LONG2", "B", "C", 2),
            edge("SHORT", "X", "C", 3), edge("END", "C", "D", 4)]
    chains, diagnostics = api().derive_reference_chains(rows, "positive-reference")
    covered = {event for c in chains for event in c["event_ids"]}
    assert covered == {r["event_id"] for r in rows}
    assert ("LONG1", "LONG2", "END") in {tuple(c["event_ids"]) for c in chains}
    assert ("SHORT", "END") in {tuple(c["event_ids"]) for c in chains}
    assert diagnostics["singletons"] == []


def test_reference_derivation_enforces_strict_time_and_execute_causal_direction():
    rows = [edge("E1", "PARENT", "BIN", 1), edge("E2", "CHILD", "BIN", 2, "EVENT_EXECUTE"),
            edge("E3", "CHILD", "NET", 3), edge("SIMULTANEOUS", "NET", "OUT", 3)]
    chains, diagnostics = api().derive_reference_chains(rows, "positive-reference")
    assert ("E1", "E2", "E3") in {tuple(c["event_ids"]) for c in chains}
    assert diagnostics["singletons"] == ["SIMULTANEOUS"]


def test_reference_derivation_is_deterministic_and_independent_of_scores():
    rows = [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2)]
    first, first_diagnostics = api().derive_reference_chains(rows, "source-hash")
    changed = deepcopy(rows)
    for index, row in enumerate(changed):
        row.update(score=999 - index, decisions={"method": False}, components={"rarity": 1.0})
    second, second_diagnostics = api().derive_reference_chains(reversed(changed), "source-hash")
    assert first == second
    assert first_diagnostics == second_diagnostics
    assert rows == [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2)]


def test_reference_derivation_never_connects_events_across_different_hosts():
    rows = [edge("E1", "A", "B", 1, host="H1"), edge("E2", "B", "C", 2, host="H2")]
    chains, diagnostics = api().derive_reference_chains(rows, "positive-reference")
    assert chains == []
    assert diagnostics["singletons"] == ["E1", "E2"]


def test_reference_derivation_empty_input_has_no_fake_paths():
    chains, diagnostics = api().derive_reference_chains([], "positive-reference")
    assert chains == []
    assert diagnostics["length_min"] is None and diagnostics["length_max"] is None
    assert diagnostics["source_positive_event_count"] == 0


def test_program_filter_excludes_unrelated_programs_and_current_day_but_includes_both_directions(database):
    with ProvenanceStore(database) as store:
        store.ingest([
            NodeRecord("OTHER_P", "process", "helper", "H1", "process:/bin/app-helper"),
            EdgeRecord("OTHER_PROGRAM", "OTHER_P", "F", "EVENT_WRITE", DAY_NS + 10, "H1"),
            EdgeRecord("READ_TO_PROGRAM", "F", "P", "EVENT_READ", DAY_NS + 20, "H1"),
            EdgeRecord("FUTURE_READ", "F", "P", "EVENT_READ", 2 * DAY_NS + 10, "H1"),
        ])
        FrequencyCache(store).build()
    rows, provenance = api().load_historical_rows(
        database, 2 * DAY_NS + 50, ["H1"], program_semantics=["process:/bin/app"])
    assert sum(row["count"] for row in rows) == 3
    assert len(rows) == 2
    assert {row["relation"] for row in rows} == {"EVENT_WRITE", "EVENT_READ"}
    assert all("process:/bin/app-helper" not in (row["src_semantic"], row["dst_semantic"]) for row in rows)
    assert provenance["program_semantics"] == ["process:/bin/app"]
    assert provenance["history_scope"] == "explicit_hosts_and_program_semantics"
    assert "exact" in provenance["semantic_filter_rule"]
    assert "unmatched peers" in provenance["history_scope_limitations"]


@pytest.mark.parametrize("programs", [[], [None], [""], ["   "], "process:/bin/app"])
def test_program_filter_requires_nonempty_explicit_semantics(database, programs):
    with pytest.raises(ValueError, match="program_semantics"):
        api().load_historical_rows(database, 2 * DAY_NS, ["H1"], program_semantics=programs)


def test_default_historical_scope_still_admits_all_programs_for_the_explicit_host(database):
    rows, provenance = api().load_historical_rows(database, 2 * DAY_NS, ["H1"])
    assert provenance["program_semantics"] is None
    assert provenance["history_scope"] == "explicit_hosts_all_patterns"
    assert sum(row["count"] for row in rows) == 2
