from tc_pruning.investigation.temporal_memory import LongShortTemporalMemory, RarePairHistoryKey


def test_log_time_retains_more_long_gap_signal_than_exponential():
    memory = LongShortTemporalMemory(base_unit_ns=1_000_000_000, short_window_ns=10_000_000_000)
    key = RarePairHistoryKey("process", "EVENT_CONNECT", "socket")
    memory.observe(key, 0, "old")
    score = memory.score(key, 7_200_000_000_000)
    assert score.log_time > score.exponential
    assert score.long_count == 1
    assert score.short_count == 0


def test_recent_and_long_history_are_reported_separately():
    second = 1_000_000_000
    memory = LongShortTemporalMemory(base_unit_ns=second, short_window_ns=10 * second)
    key = RarePairHistoryKey("p", "R", "f")
    memory.observe(key, 0, "old")
    memory.observe(key, 95 * second, "new")
    score = memory.score(key, 100 * second)
    assert (score.short_count, score.long_count) == (1, 1)
    assert score.gap_bucket == "1-10s"
