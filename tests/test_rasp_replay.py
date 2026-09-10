import gzip
import json
import pytest

from scripts.run_rasp import run
from tests.test_rasp import CONFIG


@pytest.mark.parametrize('diverse', [False, True])
def test_new_method_does_not_use_truth_or_old_ranking(tmp_path, diverse):
    config = tmp_path/"config.json"
    config.write_text(json.dumps({**CONFIG, "algorithm": "test", "budgets": [.5], "primary_budget": .5, "escape_floor": 1e-6}))
    runner = run
    if diverse:
        from scripts.run_rasp_diverse import run as runner
        scoring = config
        config = tmp_path/'diverse.json'
        config.write_text(json.dumps({'algorithm': 'test-diverse', 'scoring_config': str(scoring),
            'budgets': [.5], 'primary_budget': .5, 'quality_weights': [0, .05, .25], 'primary_quality_weight': .05}))
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
        runner(ledger, truth, output, config)
        filename = 'diverse-decisions.jsonl.gz' if diverse else 'rasp-edge-scores.jsonl.gz'
        with gzip.open(output/filename, "rt") as stream:
            selections.append([(r["score"], r["decisions"] if diverse else r["retained"]) for r in map(json.loads, stream)])
    assert selections[0] == selections[1]
