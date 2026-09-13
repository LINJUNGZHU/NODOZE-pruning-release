import gzip
import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_rcvp.py"
SPEC = importlib.util.spec_from_file_location("run_rcvp", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


def _candidates():
    return [
        {
            "event_id": "e1", "edge_id": 11, "src": "a", "dst": "b",
            "src_type": "process", "dst_type": "file", "relation": "EVENT_WRITE",
            "timestamp_ns": 1, "host": "h", "data_size": 1,
            "components": {"rarity": .2, "path": .3, "depimpact": .4, "behavior": .5},
            "score": .8, "is_declared_poi": False,
        },
        {
            "event_id": "e2", "edge_id": 12, "src": "b", "dst": "c",
            "src_type": "file", "dst_type": "process", "relation": "EVENT_READ",
            "timestamp_ns": 2, "host": "h", "data_size": None,
            "components": {"rarity": .7, "path": .1, "depimpact": .2, "behavior": .0},
            "score": 1., "is_declared_poi": True,
        },
    ]


def test_frozen_audit_is_deterministic_complete_and_truth_independent(tmp_path):
    candidates = _candidates()
    candidates[0]["decisions"] = [{"budget_key": "0.2", "kept": True}]
    decisions = {
        "A_rasp@0.5": np.array([False, True]),
        "G@1": np.array([True, True]),
    }
    evidence = {
        "relation_family": np.array(["write", "read"]),
        "temporal_weight": np.array([.9, 1.]),
        "roundtrip_verification_score": np.array([.4, .8]),
    }
    roots = [{"node_index": 0, "timestamp_ns": 0, "score": .4, "witness": [0, 1]}]
    config = {"budgets": [.5, 1.], "methods": ["A_rasp", "G"]}

    first = runner.freeze_online_artifacts(
        tmp_path / "one", candidates, decisions, evidence, roots, config,
        implementation_paths=[SCRIPT],
    )
    second = runner.freeze_online_artifacts(
        tmp_path / "two", candidates, decisions, evidence, roots, config,
        implementation_paths=[SCRIPT],
    )

    assert first["decision_sha256"] == second["decision_sha256"]
    assert first["candidate_sha256"] == second["candidate_sha256"]
    assert runner.validate_frozen_artifacts(tmp_path / "one")["valid"] is True
    with gzip.open(tmp_path / "one" / "rcvp-edge-audit.jsonl.gz", "rt") as stream:
        rows = [json.loads(line) for line in stream]
    assert [row["event_id"] for row in rows] == ["e1", "e2"]
    assert all(set(decisions) == set(row["decisions"]) for row in rows)
    assert all(set(evidence) == set(row["rcvp_evidence"]) for row in rows)
    assert rows[0]["source_decisions"] == candidates[0]["decisions"]

    before = runner.sha256_file(tmp_path / "one" / "rcvp-edge-audit.jsonl.gz")
    a = runner.evaluate_frozen_positive_ids(rows, {"a", "missing"}, {"e1"})
    b = runner.evaluate_frozen_positive_ids(rows, {"c"}, {"e2"})
    after = runner.sha256_file(tmp_path / "one" / "rcvp-edge-audit.jsonl.gz")
    assert before == after
    assert a != b


def test_validator_detects_audit_tampering(tmp_path):
    output = tmp_path / "run"
    decisions = {"G@0.5": np.array([False, True])}
    runner.freeze_online_artifacts(
        output, _candidates(), decisions, {"diffusion_verified": np.array([.1, .9])},
        [], {"budgets": [.5]}, implementation_paths=[SCRIPT],
    )
    audit = output / "rcvp-edge-audit.jsonl.gz"
    with gzip.open(audit, "rt") as stream:
        rows = [json.loads(line) for line in stream]
    rows[0]["decisions"]["G@0.5"] = True
    runner._write_deterministic_gzip(audit, rows)

    with pytest.raises(ValueError, match="hash|summary"):
        runner.validate_frozen_artifacts(output)


def test_validator_detects_manifest_diagnostic_tampering(tmp_path):
    output = tmp_path / "run"
    runner.freeze_online_artifacts(output, _candidates(), {"G@0.5": [False, True]},
        {"diffusion_verified": [.1, .9]}, [], {"budgets": [.5]}, implementation_paths=[SCRIPT],
        method_diagnostics={"G@0.5": {"budget_feasible": True}})
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["method_diagnostics"]["G@0.5"]["budget_feasible"] = False
    manifest["method_diagnostics"]["G@0.5"]["retained_raw_events"] = 2
    manifest["integrity_sha256"] = runner._sha256_json({key: value for key, value in manifest.items() if key != "integrity_sha256"})
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="diagnostic"):
        runner.validate_frozen_artifacts(output)


def test_freeze_rejects_missing_or_duplicate_raw_edge_ids(tmp_path):
    missing = _candidates(); missing[0].pop("edge_id")
    with pytest.raises(ValueError, match="edge_id"):
        runner.freeze_online_artifacts(tmp_path / "missing", missing, {"G@1": [True, True]}, {}, [], {}, implementation_paths=[SCRIPT])
    duplicate = _candidates(); duplicate[1]["edge_id"] = duplicate[0]["edge_id"]
    with pytest.raises(ValueError, match="unique"):
        runner.freeze_online_artifacts(tmp_path / "duplicate", duplicate, {"G@1": [True, True]}, {}, [], {}, implementation_paths=[SCRIPT])


def test_metric_triplets_separate_coverage_conditional_and_end_to_end():
    rows = _candidates()
    rows[0]["decisions"] = {"G@0.5": False}
    rows[1]["decisions"] = {"G@0.5": True}
    result = runner.evaluate_frozen_positive_ids(
        rows, positive_node_ids={"a", "c", "outside"}, reference_event_ids={"e1", "e2", "outside"}
    )["G@0.5"]

    assert result["candidate_context_edge_recall"] == {"numerator": 2, "denominator": 3, "value": pytest.approx(2 / 3)}
    assert result["conditional_context_edge_retention"] == {"numerator": 1, "denominator": 2, "value": .5}
    assert result["pruned_context_edge_recall"] == {"numerator": 1, "denominator": 3, "value": pytest.approx(1 / 3)}
    assert result["verified_attack_path_retention"] == {"value": None, "reason": "no_independently_human_reviewed_paths"}


def test_online_smoke_runs_all_required_methods_without_labels(tmp_path):
    rows = []
    for index in range(20):
        rows.append({
            "event_id": f"e{index}", "edge_id": index + 1,
            "src": f"n{index}", "dst": f"n{index + 1}",
            "src_type": "process", "dst_type": "process",
            "relation": "EVENT_FORK", "timestamp_ns": index + 1,
            "host": "h", "data_size": None,
            "components": {"rarity": .2, "path": .3, "depimpact": .4, "behavior": .1},
            "score": (index + 1) / 20, "is_declared_poi": index == 19,
        })
    ledger = tmp_path / "input.jsonl.gz"
    runner._write_deterministic_gzip(ledger, rows)
    output = tmp_path / "output"

    runner.run_online_case("toy", ledger, output, {
        "budgets": [.3], "methods": ["A_rasp", "A_rdp", "B", "C", "D", "E", "F", "G", "G_no_redundancy"],
        "pruning_weights": {"rarity": .1, "path": .1, "impact": .1, "behavior": .1},
    })

    result = runner.validate_frozen_artifacts(output)
    assert result["valid"]
    assert set(result["methods"]) == {f"{name}@0.3" for name in ("A_rasp", "A_rdp", "B", "C", "D", "E", "F", "G", "G_no_redundancy")}


def test_progressive_adapter_uses_redundancy_key_and_both_witness_orientations():
    rows = _candidates()
    rows.append({**rows[0], "event_id": "e3", "edge_id": 13, "timestamp_ns": 3, "is_declared_poi": False})
    rows[0].update(src="x", dst="y", relation="COMMON")
    rows[1].update(src="a", dst="b", relation="COMMON")
    rows[2].update(src="a", dst="b", relation="COMMON")
    scores = np.array([.5, .5, .5])
    plain, _ = runner._adaptive_mask(rows, scores, 2 / 3, "progressive", progressive_config={"consistency_weight": 0., "redundancy_weight": 0.})
    regularized, _ = runner._adaptive_mask(rows, scores, 2 / 3, "progressive", progressive_config={"consistency_weight": 0., "redundancy_weight": .2})
    assert not np.array_equal(plain, regularized)

    chain = _candidates()
    runner._adaptive_mask(chain, np.array([.5, .5]), .5, "progressive", parents=[-1, 0])
    runner._adaptive_mask(chain, np.array([.5, .5]), .5, "progressive", parents=[1, -1])
    chain[1]["timestamp_ns"] = chain[0]["timestamp_ns"]
    with pytest.raises(ValueError, match="equal timestamps"):
        runner._adaptive_mask(chain, np.array([.5, .5]), .5, "progressive", parents=[1, -1])
