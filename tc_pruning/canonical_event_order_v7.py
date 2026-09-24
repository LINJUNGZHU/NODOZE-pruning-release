"""Canonical event-index order for v7 retrieval, independent of ledger row order.

The frozen v4/v6 regression still consumes the original ledger order. This
adapter is applied only before new candidate, route and objective processing.
"""
import numpy as np


EVENT_FIELDS = ('src', 'dst', 'relation', 'timestamp', 'rarity', 'poi', 'old_score', 'tie')


def canonical_event_order(data, history_rarity):
    ids = data['ids']
    n = len(ids)
    if len(set(ids)) != n:
        raise ValueError('duplicate event IDs')
    if any(len(data[k]) != n for k in EVENT_FIELDS) or len(history_rarity) != n:
        raise ValueError('misaligned event arrays')
    order = np.argsort(np.asarray(ids, dtype=str), kind='stable')
    result = dict(data)
    result['ids'] = [ids[int(i)] for i in order]
    for key in EVENT_FIELDS:
        result[key] = np.asarray(data[key])[order]
    return result, np.asarray(history_rarity)[order]
