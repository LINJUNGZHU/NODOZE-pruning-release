import time

from tc_pruning.detectors.kairos_adapter import KairosEvidence
from tc_pruning.models import StoredEdge
from tc_pruning.investigation.mosaic_experiment import run_online_experiment


def test_synthetic_large_query_selection_finishes_under_five_seconds():
    count = 20_000
    evidence = tuple(
        KairosEvidence(
            f"e{i}", f"p{i % 100}", f"f{i % 500}", "EVENT_WRITE", i,
            float(i % 17), (i % 100) / 100, i % 11 == 0, (f"q{i % 4}",),
            10.0, i % 11 == 0, f"s{i % 8}" if i % 11 == 0 else None,
            f"n{i}", f"w{i % 12}", "EXACT",
        ) for i in range(count)
    )
    edges = tuple(
        StoredEdge(i, f"e{i}", f"p{i % 100}", f"f{i % 500}", "EVENT_WRITE",
                   i, "h", "process", "file", "process:p", "file:f", None)
        for i in range(count)
    )
    started = time.perf_counter()
    result = run_online_experiment(
        evidence, edges, scenario="06",
        config={"selection_fraction": 0.8, "projection_window_ns": 100, "unit_size": 64},
    )
    assert result["selection_ablations"]["S5"]["raw_event_count"] > 0
    assert time.perf_counter() - started < 5.0
