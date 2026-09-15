from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math


@dataclass(frozen=True, slots=True)
class RarePairHistoryKey:
    src_semantic_class: str
    relation: str
    dst_semantic_class: str


@dataclass(frozen=True, slots=True)
class TemporalMemoryScore:
    short_count: int
    long_count: int
    exponential: float
    log_time: float
    fused: float
    gap_bucket: str


class LongShortTemporalMemory:
    def __init__(self, *, base_unit_ns: int = 1_000_000_000,
                 short_window_ns: int = 600_000_000_000, short_weight: float = 0.5) -> None:
        if base_unit_ns < 1 or short_window_ns < 1 or not 0 <= short_weight <= 1:
            raise ValueError("invalid temporal memory configuration")
        self.base = base_unit_ns
        self.short_window = short_window_ns
        self.short_weight = short_weight
        self._history = defaultdict(list)

    def observe(self, key: RarePairHistoryKey, timestamp_ns: int, event_id: str) -> None:
        self._history[key].append((int(timestamp_ns), str(event_id)))
        self._history[key].sort()

    @staticmethod
    def _bucket(delta_ns: int) -> str:
        second = 1_000_000_000
        if delta_ns < second: return "<1s"
        if delta_ns < 10 * second: return "1-10s"
        if delta_ns < 60 * second: return "10-60s"
        if delta_ns < 600 * second: return "1-10m"
        if delta_ns < 3600 * second: return "10-60m"
        return ">1h"

    def score(self, key: RarePairHistoryKey, timestamp_ns: int) -> TemporalMemoryScore:
        history = [(time, event) for time, event in self._history.get(key, ()) if time < timestamp_ns]
        if not history:
            return TemporalMemoryScore(0, 0, 0.0, 0.0, 0.0, ">1h")
        delta = timestamp_ns - history[-1][0]
        short = sum(timestamp_ns - time <= self.short_window for time, _ in history)
        exponential = math.exp(-delta / self.base)
        log_time = 1.0 / (1.0 + math.log1p(delta / self.base))
        short_signal = min(1.0, short / 3.0)
        fused = self.short_weight * short_signal + (1 - self.short_weight) * log_time
        return TemporalMemoryScore(short, len(history), exponential, log_time, fused, self._bucket(delta))


__all__ = ["LongShortTemporalMemory", "RarePairHistoryKey", "TemporalMemoryScore"]
