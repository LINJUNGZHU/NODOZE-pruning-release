"""Production admission/streaming tests use real files and SQLite, not adapters."""
from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tracemalloc

import pytest

from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def production():
    assert importlib.util.find_spec("tc_pruning.detector_seed_production"), "sealed production harness is missing"
    return importlib.import_module("tc_pruning.detector_seed_production")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True))
    return pin(path)


def pin(path):
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def shard(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    return pin(path)


def edge(event="e1", score=4, **updates):
    value = dict(event_uuid=event, stored_event_id=event, original_event_id=event,
                 identity_origin="OTHER_STORED_ID", identity_collision=False,
                 src_node_uuid="p", dst_node_uuid="f", raw_relation="EVENT_WRITE",
                 model_operation="EVENT_WRITE", time=10, loss=score,
                 supporting_event_ids=[event], native_decision=True, scope="day1")
    value.update(updates)
    return value


def graph(path):
    with ProvenanceStore(path) as store:
        store.ingest([NodeRecord("p", "process", "p"), NodeRecord("f", "file", "f"),
                      NodeRecord("r", "file", "r"), NodeRecord("q", "process", "q"),
                      EdgeRecord("e0", "r", "p", "EVENT_READ", 5, "h"),
                      EdgeRecord("e1", "p", "f", "EVENT_WRITE", 10, "h"),
                      EdgeRecord("e2", "f", "q", "EVENT_READ", 15, "h"),
                      EdgeRecord("e3", "p", "f", "EVENT_WRITE", 18, "h")])


def test_streaming_csv_accepts_large_bounded_pidsmaker_field(tmp_path):
    source = tmp_path / "velox.csv"
    oversized = "e" * 800_000
    source.write_text("loss,event_uuid\n1," + oversized + "\n")

    rows = list(production().iter_shards([pin(source)]))

    assert rows == [{"loss": "1", "event_uuid": oversized}]


def test_fused_velox_support_is_visible_in_direct_coverage_stages(tmp_path):
    p = production()
    cfg = config(tmp_path)
    with sqlite3.connect(cfg["database"]["path"]) as conn:
        conn.execute("INSERT INTO edges(event_id,original_event_id,src,dst,relation,timestamp_ns,host,data_size) VALUES (?,?,?,?,?,?,?,?)",
                     ("e1b", "e1b", "p", "f", "EVENT_WRITE", 11, "h", 0))
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "fused.jsonl", [edge(supporting_event_ids=["e1", "e1b"])])]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        summary = p.stage_population("VELOX", source, store, tmp_path / "population")
    assert summary["counts"]["supporting_event_rows"] == 2
    with sqlite3.connect(tmp_path / "population/stage.sqlite") as conn:
        for stage in ("preprocessing", "inference", "scored", "native_threshold", "evidence"):
            assert conn.execute("SELECT identity FROM stage_identity WHERE stage=? AND kind='event' ORDER BY identity", (stage,)).fetchall() == [("e1",), ("e1b",)]


def test_velox_population_rejects_duplicate_scored_or_supporting_event_identity(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "duplicates.jsonl", [edge(), edge()])]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        with pytest.raises(ValueError, match="duplicate.*event"):
            p.stage_population("VELOX", source, store, tmp_path / "population")


def config(tmp_path):
    p = production()
    db = tmp_path / "source.db"
    graph(db)
    runtime_file = tmp_path / "runtime.py"
    runtime_file.write_text("# exact runtime\n")
    runtime = {"commit": "a" * 40, "files": {str(runtime_file): pin(runtime_file)["sha256"]}}
    runtime["sha256"] = p.digest_json(runtime)
    identity = {"status": "COMPLETED", "source_sha256": pin(db)["sha256"],
                "test_only": True, "production_admissible": False,
                "reconciliation": {"exact": True}, "model_views_sha256": "b" * 64,
                "model_eligible_identity_origin_counts": {"OTHER_STORED_ID": 3},
                "pidsmaker_runtime_seal": runtime}
    identity["manifest_sha256"] = p.digest_json(identity)
    manifest = write_json(tmp_path / "identity.json", identity)
    name = "VELOX"
    populations = {name: {
        "native": [shard(tmp_path / name / "native.jsonl", [edge()])],
        "development": [shard(tmp_path / name / "development.jsonl", [{"loss": 1}, {"loss": 3}])],
        "version": "fixture", "native_threshold": 3, "threshold_method": "max_val_loss",
        "inference_seconds": 1.0,
    }}
    derivation = {
        "status": "COMPLETED", "detector_id": name, "source_sha256": pin(db)["sha256"],
        "identity_manifest_sha256": identity["manifest_sha256"], "runtime_sha256": runtime["sha256"],
        "native": populations[name]["native"], "development": populations[name]["development"],
        "training_status": write_json(tmp_path / name / "training-status.json", {
            "status": "COMPLETED", "detector": "velox", "identity_manifest_sha256": identity["manifest_sha256"]}),
        "runtime_audit": shard(tmp_path / name / "runtime.jsonl", [{"epoch": 0, "splits": {"test": {"seconds": 1}}}]),
        "generator": pin(Path("tc_pruning/velox_production_recipe.py")),
        "epoch_selection": {"epoch": 0, "selection_rule": "minimum_mean_validation_edge_loss",
                            "inference_seconds": 1.0}}
    populations[name]["derivation"] = write_json(tmp_path / name / "derivation.json", derivation)
    return {"schema_version": "cadets-velox-production-v1", "dataset": "DARPA_TC_E3_CADETS",
            "database": pin(db), "identity_manifest": manifest, "runtime_root": str(tmp_path),
            "code": p.current_code_manifest(), "runs": list(p.RUN_IDS), "populations": populations,
            "candidate": dict(candidate_cap=10, history_start_ns=0, cutoff_ns=20, max_strict_depth=3,
                              max_control_depth=2, enable_common_cause=True, scan_multiplier=2),
            "projection": {"mode": "DEPIMPACT_COMPATIBLE", "merge_window_ns": 900000000000},
            "raw_event_cap": 8, "proxy_event_cap": 8, "percentile_threshold": 0.99}


@pytest.mark.parametrize("authority", ["knowncriticaleventids", "ATTACKTIMESBACKUP", "pdfCriticalEdges",
    "criticaledgecache", "ytrue", "y_true", "ground-truth", "candidateFunnel", "OracleCache", "nodeLABELS", "GT"])
@pytest.mark.parametrize("location", ["key", "value", "path", "metadata"])
def test_all_authority_spellings_rejected_before_input_open(authority, location):
    value = {authority: "x"} if location == "key" else {location: {"nested": [authority]}}
    with pytest.raises(ValueError, match="authority"):
        production().reject_authorities(value)


def test_streaming_rank_ties_scope_and_indexed_lookup(tmp_path):
    p = production()
    db = tmp_path / "source.db"
    graph(db)
    rows = [edge("e0", 2, native_decision=False, scope="A", src_node_uuid="r", dst_node_uuid="p", raw_relation="EVENT_READ", model_operation="EVENT_READ", time=5),
            edge("e1", 2, native_decision=False, scope="A"),
            edge("e2", 9, native_decision=True, scope="A", src_node_uuid="f", dst_node_uuid="q", raw_relation="EVENT_READ", model_operation="EVENT_READ", time=15),
            edge("e3", 2, native_decision=False, scope="B", time=18)]
    source = {"native": [shard(tmp_path / "native.jsonl", rows)],
              "development": [shard(tmp_path / "development.jsonl", [{"loss": 1}, {"loss": 2}, {"loss": 2}, {"loss": 5}])],
              "native_threshold": 5, "threshold_method": "max_val_loss", "version": "v"}
    with p.ReadOnlyStore(db) as store:
        summary = p.stage_population("VELOX", source, store, tmp_path / "population")
    evidence = [json.loads(line) for line in (tmp_path / "population/evidence.jsonl").open()]
    assert [x["development_percentile"] for x in evidence] == [.75, .75, 1, .75]
    assert [x["query_local_percentile"] for x in evidence] == [2 / 3, 2 / 3, 1, 1]
    assert summary["counts"]["exact"] == 4
    with sqlite3.connect(tmp_path / "population/stage.sqlite") as conn:
        plan = " ".join(str(row) for row in conn.execute("EXPLAIN QUERY PLAN SELECT percentile FROM development_rank WHERE score<=2 ORDER BY score DESC LIMIT 1"))
        assert "SEARCH" in plan
        assert conn.execute("SELECT percentile FROM local_rank WHERE scope='A' AND score=2").fetchone()[0] == 2 / 3


@pytest.mark.parametrize("change", ["configured_threshold", "row_decision", "row_threshold", "threshold_method"])
def test_velox_native_threshold_is_exactly_development_max(tmp_path, change):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    row = edge(score=4)
    if change == "configured_threshold":
        source["native_threshold"] = 2
    elif change == "row_decision":
        row["native_decision"] = False
        source["native"] = [shard(tmp_path / "wrong-decision.jsonl", [row])]
    elif change == "row_threshold":
        row["threshold"] = 2
        source["native"] = [shard(tmp_path / "wrong-threshold.jsonl", [row])]
    else:
        source["threshold_method"] = "test_percentile"
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        with pytest.raises(ValueError, match="threshold|decision|max_val_loss"):
            p.stage_population("VELOX", source, store, tmp_path / "population")


def test_velox_stages_with_bounded_memory_and_single_shard_pass(tmp_path, monkeypatch):
    p = production()
    cfg = config(tmp_path)
    detector = "VELOX"
    source = cfg["populations"][detector]
    source["native_threshold"] = 499
    rows = [edge(f"bulk-{i}", i % 500, native_decision=False if i % 500 <= 499 else True,
                 time=100 + i) for i in range(5000)]
    with sqlite3.connect(cfg["database"]["path"]) as conn:
        conn.executemany("INSERT INTO edges(event_id,original_event_id,src,dst,relation,timestamp_ns,host,data_size) VALUES (?,?,?,?,?,?,?,?)",
                         ((f"bulk-{i}", f"bulk-{i}", "p", "f", "EVENT_WRITE", 100 + i, "h", 0) for i in range(5000)))
    source["native"] = [shard(tmp_path / "large.jsonl", rows)]
    source["development"] = [shard(tmp_path / "devlarge.jsonl", ({"loss": i % 500} for i in range(5000)))]
    original = p.iter_shards
    reads = []
    def once(files):
        reads.append(tuple(item["path"] for item in files))
        yield from original(files)
    monkeypatch.setattr(p, "iter_shards", once)
    tracemalloc.start()
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        result = p.stage_population(detector, source, store, tmp_path / "population")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result["counts"]["total"] == 5000
    assert len(reads) == 2
    assert peak < 16_000_000


@pytest.mark.parametrize("corruption", ["missing_fields", "legacy", "timestamp", "origin", "collision", "support", "relation", "endpoint"])
def test_exact_identity_corruption_never_becomes_exact(tmp_path, corruption):
    p = production()
    cfg = config(tmp_path)
    row = edge()
    if corruption == "missing_fields": row.pop("original_event_id")
    if corruption == "legacy": row.update(event_uuid="legacy-row-1", stored_event_id="legacy-row-1")
    if corruption == "timestamp": row["time"] = 10.0
    if corruption == "origin": row["identity_origin"] = "RAW_TC_EVENT"
    if corruption == "collision": row["identity_collision"] = True
    if corruption == "support": row["supporting_event_ids"] = ["another"]
    if corruption == "relation": row["raw_relation"] = "EVENT_READ"
    if corruption == "endpoint": row["src_node_uuid"] = "f"
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "bad.jsonl", [row])]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        with pytest.raises(ValueError, match="identity|timestamp|relation|endpoint"):
            p.stage_population("VELOX", source, store, tmp_path / "population")


def test_four_profiles_share_one_population_and_keep_priority_semantics(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "scores.jsonl", [edge(score=4), edge("e2", 1, src_node_uuid="f", dst_node_uuid="q", raw_relation="EVENT_READ", model_operation="EVENT_READ", time=15, native_decision=False)])]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        summary = p.stage_population("VELOX", source, store, tmp_path / "population")
    hashes = []
    for run in ("VXL-0", "VXL-1", "VXL-2", "VXL-3"):
        with p.population_inputs(tmp_path / "population", run, 10, .99) as (anchors, priority, identity):
            hashes.append(identity)
            assert [x.event_ids for x in anchors] == [("e1",)]
            if run in ("VXL-0", "VXL-1"):
                assert priority is None
            else:
                assert priority.score_for_event("e2") == (1 if run == "VXL-2" else .5)
    assert len(set(hashes)) == 1 and hashes[0] == summary["evidence_sha256"]


def test_anchor_overflow_fails_instead_of_truncating(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "scores.jsonl", [edge(), edge("e2", 4, src_node_uuid="f", dst_node_uuid="q", raw_relation="EVENT_READ", model_operation="EVENT_READ", time=15)])]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        p.stage_population("VELOX", source, store, tmp_path / "population")
    with pytest.raises(ValueError, match="anchor.*cap"):
        with p.population_inputs(tmp_path / "population", "VXL-0", 1, .99): pass


@pytest.mark.parametrize("field", ["runs", "code", "identity_manifest", "development", "runtime", "native", "database", "training_status"])
def test_admission_rejects_changed_sealed_authority(tmp_path, field):
    p = production()
    cfg = config(tmp_path)
    if field == "runs": cfg["runs"][-1] = "VXL-0"
    elif field == "code": next(iter(cfg["code"]["files"].values()))["sha256"] = "0" * 64
    elif field == "identity_manifest": cfg["identity_manifest"]["sha256"] = "0" * 64
    elif field == "runtime": (tmp_path / "runtime.py").write_text("changed")
    elif field == "database": cfg["database"]["sha256"] = "0" * 64
    elif field == "training_status": Path(json.loads(Path(cfg["populations"]["VELOX"]["derivation"]["path"]).read_text())["training_status"]["path"]).write_text("changed")
    else: cfg["populations"]["VELOX"][field][0]["sha256"] = "0" * 64
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "external-pin.json", allow_test=True)
    assert result["status"] == "NOT_COMPLETED"
    assert not (tmp_path / "result").exists()
    assert json.loads(Path(result["attempt_directory"]).joinpath("status.json").read_text())["status"] == "NOT_COMPLETED"


def test_four_profile_atomic_publication_and_offline_attribution(tmp_path):
    p = production()
    cfg = config(tmp_path)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "external-pin.json", allow_test=True)
    assert result["status"] == "COMPLETED", result
    assert set(result["runs"]) == set(p.RUN_IDS)
    assert len(list((tmp_path / "result/populations").glob("*/stage.sqlite"))) == 1
    before = pin(tmp_path / "result/manifest.json")
    offline = importlib.import_module("tc_pruning.detector_seed_production_evaluation")
    evaluation = offline.evaluate_production(tmp_path / "external-pin.json", {"e1"}, {"p"}, tmp_path / "offline")
    assert evaluation["status"] == "COMPLETED", evaluation
    assert set(evaluation["runs"]) == set(p.RUN_IDS)
    for run, value in evaluation["runs"].items():
        assert value["run_id"] == run and value["candidate"]["known_TP"] == 1
        assert value["A_rasp"]["known_TP"] == 1
        assert value["A_rasp"]["node_recall"] == 1
        assert value["A_rasp"]["raw_events"] >= 1
        assert value["C_branch_fair"]["node_recall"] == 1
        assert value["direct_attack_node_hits"] == ["p"]
    assert before == pin(tmp_path / "result/manifest.json")


def test_zero_alert_profile_is_a_completed_empty_result_not_outer_failure(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    source["native"] = [shard(tmp_path / "quiet.jsonl", [edge(score=2, native_decision=False)])]
    derivation_path = Path(source["derivation"]["path"])
    derivation = json.loads(derivation_path.read_text())
    derivation["native"] = source["native"]
    source["derivation"] = write_json(derivation_path, derivation)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "COMPLETED", result
    for run_id in p.RUN_IDS:
        candidate = json.loads((tmp_path / "result/runs" / run_id / "candidate.json").read_text())
        final = json.loads((tmp_path / "result/runs" / run_id / "A_rasp.json").read_text())
        assert candidate["raw_events"] == 0
        assert final["selected_raw_event_ids"] == []


@pytest.mark.parametrize("stage", ["attempt_mkdir", "store_open", "store_close", "priority_close", "seal", "publish", "freeze"])
def test_outer_attempt_seals_every_injected_failure(tmp_path, monkeypatch, stage):
    p = production()
    cfg = config(tmp_path)
    target = {"attempt_mkdir": "make_attempt", "store_open": "open_store", "store_close": "close_store",
              "priority_close": "close_priority", "seal": "seal_attempt", "publish": "publish_attempt", "freeze": "freeze_artifacts"}[stage]
    def fail(*args, **kwargs): raise OSError("injected " + stage)
    monkeypatch.setattr(p, target, fail)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "external-pin.json", allow_test=True)
    assert result["status"] == "NOT_COMPLETED" and stage in result["reason"]
    attempt = Path(result["attempt_directory"])
    assert json.loads((attempt / "status.json").read_text())["status"] == "NOT_COMPLETED"
    assert (attempt / "failure-pin.json").is_file()
    assert not (tmp_path / "result").exists()


@pytest.mark.parametrize("target", ["development", "code", "native", "evidence", "result", "database", "manifest"])
def test_offline_external_pin_detects_every_derivation_and_result_mutation(tmp_path, target):
    p = production()
    cfg = config(tmp_path)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "COMPLETED", result
    paths = {"development": Path(cfg["populations"]["VELOX"]["development"][0]["path"]),
             "native": Path(cfg["populations"]["VELOX"]["native"][0]["path"]),
             "evidence": tmp_path / "result/populations/VELOX/evidence.jsonl",
             "result": tmp_path / "result/runs/VXL-0/A_rasp.json",
             "database": Path(cfg["database"]["path"]), "manifest": tmp_path / "result/manifest.json"}
    if target == "code":
        # Mutate the pinned code snapshot, never the working repository.
        paths[target] = tmp_path / "result/code/tc_pruning/detector_seed_production.py"
    path = paths[target]
    path.chmod(0o600)
    with path.open("ab") as stream: stream.write(b" ")
    offline = importlib.import_module("tc_pruning.detector_seed_production_evaluation")
    result = offline.evaluate_production(tmp_path / "pin.json", {"e1"}, {"p"}, tmp_path / "offline")
    assert result["status"] == "NOT_COMPLETED"


def test_offline_cli_nonzero_on_failed_pin(tmp_path):
    production()
    write_json(tmp_path / "pin.json", {"status": "NOT_COMPLETED"})
    write_json(tmp_path / "positives.json", {"event_ids": ["e1"], "node_ids": ["p"]})
    result = subprocess.run([sys.executable, "scripts/evaluate_detector_seed_production.py", "--pin", str(tmp_path / "pin.json"), "--positives", str(tmp_path / "positives.json"), "--output", str(tmp_path / "offline")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "NOT_COMPLETED" in result.stdout


def test_max_priority_and_multiple_common_cause_origins(tmp_path):
    from tc_pruning.evidence_candidate_builder import SQLiteEvidencePriority, EvidenceDrivenCandidateBuilder, CandidateSearchConfig
    from tc_pruning.detectors.alert_evidence import AlertEvidence
    priority = SQLiteEvidencePriority(str(tmp_path / "prior.sqlite"))
    try:
        priority.add_many([("e", .9), ("e", .1)])
        priority.add_nodes([("p", .9), ("p", .1)])
        assert priority.score_for_event("e") == .9
        assert priority.score_for_node("p") == .9
    finally: priority.close()
    with ProvenanceStore(tmp_path / "branches.db") as store:
        store.ingest([*(NodeRecord(n, "process", n) for n in ("parent", "child", "sibling")),
                      EdgeRecord("fork", "parent", "child", "EVENT_FORK", 3, "h"),
                      EdgeRecord("sib", "parent", "sibling", "EVENT_FORK", 4, "h")])
        anchors = [AlertEvidence(str(t), "X", "v", "NODE", 1, .9, True, node_ids=("child",), timestamp_start=t, timestamp_end=t) for t in (10, 11)]
        result = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(100, 0, 20, 0, 2, True)).build(anchors)
    branches = [b for b in result.branch_provenance["sib"] if "common-cause" in b]
    assert len(branches) >= 2
    assert any("10" in b for b in branches) and any("11" in b for b in branches)


def test_no_development_inference_population_overlap(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = cfg["populations"]["VELOX"]
    source["development"] = source["native"]
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "NOT_COMPLETED"
    assert "overlap" in result["reason"]


def test_invalid_config_file_has_canonical_failure_receipt(tmp_path):
    p = production()
    source = tmp_path / "broken.json"
    source.write_text("not JSON")
    result = p.run_production(source, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "NOT_COMPLETED"
    assert result["stage"] == "config_read"
    assert (Path(result["attempt_directory"]) / "failure-pin.json").is_file()


def test_actual_config_file_runs_and_is_externally_pinned(tmp_path):
    p = production()
    cfg = config(tmp_path)
    source = tmp_path / "actual.json"
    write_json(source, cfg)
    result = p.run_production(source, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "COMPLETED", result
    source.write_text(source.read_text() + " ")
    offline = importlib.import_module("tc_pruning.detector_seed_production_evaluation")
    assert offline.evaluate_production(tmp_path / "pin.json", {"e1"}, {"p"}, tmp_path / "offline")["status"] == "NOT_COMPLETED"


def test_strict_direction_is_retained_in_branch_provenance(tmp_path):
    from tc_pruning.evidence_candidate_builder import EvidenceDrivenCandidateBuilder, CandidateSearchConfig
    from tc_pruning.detectors.alert_evidence import AlertEvidence
    db = tmp_path / "db"
    graph(db)
    with ProvenanceStore(db) as store:
        seed = AlertEvidence("one", "X", "v", "NODE", 1, 1, True, node_ids=("p",), timestamp_start=9, timestamp_end=9)
        result = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(100, 0, 20)).build([seed])
    assert any("backward" in branch for branch in result.branch_provenance["e0"])
    assert any("forward" in branch for branch in result.branch_provenance["e1"])


def test_csv_exact_identity_and_scope_from_frozen_shard_manifest(tmp_path):
    import csv
    p = production()
    cfg = config(tmp_path)
    row = edge()
    row.pop("scope")
    row["supporting_event_ids"] = json.dumps(row["supporting_event_ids"])
    path = tmp_path / "native.csv"
    with path.open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    source = cfg["populations"]["VELOX"]
    source["native"] = [dict(pin(path), scope="window-one")]
    with p.ReadOnlyStore(cfg["database"]["path"]) as store:
        result = p.stage_population("VELOX", source, store, tmp_path / "population")
    assert result["counts"]["exact"] == 1
    item = json.loads((tmp_path / "population/evidence.jsonl").read_text())
    assert item["detector_metadata"]["scope"] == "window-one"


@pytest.mark.parametrize("change", ["runtime", "identity", "native", "development", "missing"])
def test_derivation_seal_is_checked_against_actual_input_population(tmp_path, change):
    p = production()
    cfg = config(tmp_path)
    spec = cfg["populations"]["VELOX"]
    if change == "missing":
        spec.pop("derivation")
    else:
        path = Path(spec["derivation"]["path"])
        value = json.loads(path.read_text())
        if change in ("runtime", "identity"):
            value["runtime_sha256" if change == "runtime" else "identity_manifest_sha256"] = "0" * 64
        else:
            value[change][0]["sha256"] = "0" * 64
        spec["derivation"] = write_json(path, value)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "NOT_COMPLETED" and "derivation" in result["reason"]


def test_offline_invalid_output_never_writes_to_sealed_online_tree(tmp_path):
    p = production()
    cfg = config(tmp_path)
    result = p.run_production(cfg, tmp_path / "result", tmp_path / "pin.json", allow_test=True)
    assert result["status"] == "COMPLETED", result
    offline = importlib.import_module("tc_pruning.detector_seed_production_evaluation")
    result = offline.evaluate_production(tmp_path / "pin.json", {"e1"}, {"p"}, tmp_path / "result")
    assert result["status"] == "NOT_COMPLETED"
    assert not (tmp_path / "result/evaluation.json").exists()
