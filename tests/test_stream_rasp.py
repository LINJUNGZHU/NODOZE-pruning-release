from scripts.run_stream_rasp import StreamRASP
from tc_pruning.models import EdgeRecord
from tc_pruning.history_archive import HistoryArchive


def edge(i):
    return EdgeRecord(str(i), str(i%3), str((i+1)%3), 'EVENT_WRITE', i)


def test_no_alert_is_pending_not_deleted_and_duplicates_ignored():
    s = StreamRASP(['4'], 10)
    s.ingest(edge(0)); assert not s.ingest(edge(0))
    report, rows = s.snapshot()
    assert rows[0]['retained'] is None
    assert report['seen_events'] == 1


def test_history_rarity_late_arrival_and_window_hard_cap():
    s = StreamRASP(['4'], 5)
    for i in range(8):
        s.ingest(edge(i))
        if i == 4: s.snapshot()
    report, rows = s.snapshot()
    assert len(rows) == 5 and report['retained_events'] <= 1
    assert rows[0]['rarity'] < 1
    assert next(r for r in rows if r['event_id']=='4')['retained']
    s.ingest(edge(0)); report, _ = s.snapshot()
    assert report['late_arrivals'] == 1


def test_history_recovers_expired_poi_without_inflating_budget(tmp_path):
    s=StreamRASP(['0'],5,archive=HistoryArchive(tmp_path))
    for i in range(10):s.ingest(edge(i))
    report,rows=s.snapshot()
    assert report['active_pois']==1
    assert report['budget_edges']==1
    assert report['active_events']==10
    assert next(r for r in rows if r['event_id']=='0')['retained']
