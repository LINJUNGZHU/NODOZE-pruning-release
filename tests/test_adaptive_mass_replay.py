import gzip
import json

from scripts.run_adaptive_mass import run


def test_ground_truth_changes_metrics_not_decisions(tmp_path):
    ledger = tmp_path / "scores.gz"
    with gzip.open(ledger, "wt") as stream:
        for i, score in enumerate([1., .001, .9]):
            stream.write(json.dumps({"event_id": f"event-{i}", "score": score,
                "src": str(i), "dst": str(i+1), "timestamp_ns": i,
                "src_type": "process", "dst_type": "process", "relation": "EVENT_WRITE",
                "is_declared_poi": i == 2, "decisions": [{"budget_key": "0.2", "kept": i == 2}]}) + "\n")
    decisions = []
    for j, attacks in enumerate([["event-0"], ["event-1", "event-2"]]):
        reference = tmp_path / f"truth-{j}.json"
        reference.write_text(json.dumps({"attack_event_ids": attacks, "attack_paths": [attacks]}))
        output = tmp_path / f"run-{j}"
        report = run(ledger, reference, output, losses=(.1,))
        with gzip.open(output / "adaptive-decisions.jsonl.gz", "rt") as stream:
            decisions.append(stream.read())
        assert report["ground_truth_used_for_selection"] is False
        primary = next(r for r in report["results"] if r["method"] == "t_mass_0.1")
        assert primary["retained_edges"] == 3
        assert primary["witness_added_edges"] == 1
    assert decisions[0] == decisions[1]
