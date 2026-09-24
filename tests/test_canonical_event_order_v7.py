import numpy as np

from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.rasp import temporal_fork_routes, temporal_routes


def test_row_permutation_keeps_legacy_fork_event_ids_after_canonicalization():
    # Two parallel parents tie at equal depth and timestamp. Legacy RASP
    # otherwise picks whichever parent was serialized first.
    ids = ['poi', 'a', 'b', 'target']
    src = np.array([0, 1, 1, 2])
    dst = np.array([1, 2, 2, 3])
    timestamp = np.array([10, 11, 11, 12])
    poi = np.array([True, False, False, False])
    witnesses = []
    for order in (np.array([0, 1, 2, 3]), np.array([0, 2, 1, 3])):
        data = dict(ids=[ids[i] for i in order], src=src[order], dst=dst[order],
                    timestamp=timestamp[order], poi=poi[order],
                    relation=np.zeros(4, int), rarity=np.ones(4),
                    old_score=np.ones(4), tie=np.arange(4)[order].astype(np.uint64))
        canonical, history = canonical_event_order(data, np.arange(4)[order])
        assert canonical['ids'] == ['a', 'b', 'poi', 'target']
        assert history.tolist() == [1, 2, 0, 3]
        back = temporal_routes(canonical['src'], canonical['dst'], canonical['timestamp'], canonical['poi'])[0][0]
        parent, pivot, _, _ = temporal_fork_routes(canonical['src'], canonical['dst'], canonical['timestamp'], canonical['poi'], back)
        target = canonical['ids'].index('target')
        path = []
        j = target
        while j >= 0:
            path.append(canonical['ids'][j])
            j = int(parent[j])
        witnesses.append(tuple(path))
    assert witnesses[0] == witnesses[1]


def test_duplicate_ids_are_rejected():
    data = dict(ids=['x', 'x'], src=np.array([0, 1]), dst=np.array([1, 2]),
                relation=np.zeros(2, int), timestamp=np.array([1, 2]),
                rarity=np.ones(2), poi=np.array([True, False]),
                old_score=np.ones(2), tie=np.array([1, 2], np.uint64))
    try:
        canonical_event_order(data, np.ones(2))
    except ValueError as exc:
        assert 'duplicate' in str(exc)
    else:
        assert False, 'duplicate IDs accepted'
