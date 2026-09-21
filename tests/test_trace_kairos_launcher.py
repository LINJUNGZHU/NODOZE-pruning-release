from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_orders_online_seal_before_orthrus_evaluation():
    text = (ROOT / "scripts/run_trace_e3_kairos_pipeline.sh").read_text()
    assert text.index("freeze_trace_kairos_pois.py") < text.index("run_trace_kairos_poi_experiment.py")
    assert "trap 'fail_pipeline" in text
    assert "process-status.json" in text
    assert "build_trace_e3_postgres.py" in text
    assert "trace-e3-from-tapas-2026-09-09_14-53-07.db" in text
    assert "download_resumable.py" not in text
    assert "drive.usercontent.google.com" not in text


def test_launcher_creates_unique_run_and_records_pid():
    text = (ROOT / "scripts/launch_trace_e3_kairos_pipeline.sh").read_text()
    assert "date +%Y%m%d-%H%M%S" in text
    assert "pipeline.pid" in text
    assert "nohup" in text
