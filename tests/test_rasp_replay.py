import gzip
import json

from scripts.run_rasp import run
from tests.test_rasp import CONFIG


def test_new_method_does_not_use_truth_or_old_ranking(tmp_path):
    config = tmp_path/"config.json"
    config.write_text(json.dumps({**CONFIG, "algorithm": "test", "budgets": [.5], "primary_budget": .5, "escape_floor": 1e-6}))
    selections = []
    for revision in (0, 1):
        ledger = tmp_path/f"ledger-{revision}.gz"
        with gzip.open(ledger, "wt") as stream:
            for i in range(10):
                stream.write(json.dumps({"event_id": f"event-{i}", "src": str(i), "dst": str(i+1),
                    "src_type": "process", "dst_type": "process", "relation": "EVENT_WRITE", "timestamp_ns": i,
                    "components": {"rarity": .2+.01*i}, "is_declared_poi": i == 5,
                    "score": float(i if revision else 10-i),
                    "decisions": [{"budget_key": "0.2", "kept": i in ([8, 9] if revision else [0, 1])}]})+"\n")
        truth = tmp_path/f"truth-{revision}.json"
        truth.write_text(json.dumps({"attack_event_ids": [f"event-{revision}"], "attack_paths": [[f"event-{revision}"]]}))
        output = tmp_path/f"output-{revision}"
        run(ledger, truth, output, config)
        with gzip.open(output/"rasp-edge-scores.jsonl.gz", "rt") as stream:
            selections.append([(r["score"], r["retained"]) for r in map(json.loads, stream)])
    assert selections[0] == selections[1]
