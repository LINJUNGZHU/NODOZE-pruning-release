from types import SimpleNamespace

from tc_pruning.evaluation import _previous_kept_edge_ids


class CountedEventIds:
    def __init__(self, values):
        self.values = values
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return iter(self.values)


def test_prior_prefix_membership_is_materialized_only_once():
    graph = SimpleNamespace(edges=[
        SimpleNamespace(edge_id=1, event_id='a'),
        SimpleNamespace(edge_id=2, event_id='b'),
        SimpleNamespace(edge_id=3, event_id='a'),
    ])
    previous = CountedEventIds(['a'])
    assert _previous_kept_edge_ids(graph, previous) == {1, 3}
    assert previous.iterations == 1
    assert _previous_kept_edge_ids(graph, None) is None
