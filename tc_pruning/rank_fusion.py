"""Tie-aware reciprocal-rank fusion (Cormack et al., SIGIR 2009).

Rank scores are selection priorities, not calibrated anomaly probabilities.
Zero evidence abstains. Average ranks avoid event-ID order deciding tied votes.
"""
import numpy as np


def reciprocal_rank_fusion(channels, eligible, k=60.):
    eligible = np.asarray(eligible, dtype=bool)
    if not np.isfinite(k) or k <= 0 or not channels:
        raise ValueError('positive k and at least one channel required')
    result = np.zeros(len(eligible))
    for channel in channels:
        values = np.asarray(channel, dtype=float)
        if values.shape != eligible.shape or not np.all(np.isfinite(values)) or np.any(values < 0):
            raise ValueError('finite nonnegative same-shape channels required')
        indices = np.flatnonzero(eligible & (values > 0))
        order = indices[np.argsort(-values[indices], kind='stable')]
        if not len(order): continue
        starts = np.r_[0, np.flatnonzero(np.diff(values[order]))+1]
        ends = np.r_[starts[1:], len(order)]
        ranks = np.repeat((starts+1+ends)/2, ends-starts)
        result[order] += 1/(k+ranks)
    return result
