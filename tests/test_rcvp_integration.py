import json
from pathlib import Path

import pytest

from tc_pruning.config import load_experiment_config
from tc_pruning.diffusion import diffuse_importance
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.rcvp_config import preset


def test_rcvp_config_opts_in_without_changing_default(tmp_path):
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / 'configs/tc_pruning_poi_alert.json').read_text())
    document['scoring']['diffusion_mode'] = 'relation_time_contrastive'
    document['pruning']['mode'] = 'progressive'
    document['rcvp'] = preset('full')
    document['progressive'] = {'consistency_weight': .1, 'redundancy_weight': .02}
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(document))
    config = load_experiment_config(path)
    assert config.rcvp_config['max_root_candidates'] == 32
    assert config.progressive_config['redundancy_weight'] == .02
    assert load_experiment_config(root / 'configs/tc_pruning_poi_alert.json').diffusion_mode == 'time_respecting_bidir'


def test_cli_diffusion_preserves_execute_direction_and_has_all_edge_evidence():
    graph = Neighborhood({n: NodeRecord(n, 'process' if n != 'file' else 'file', n) for n in ['file', 'p', 'q', 'x']}, [
        StoredEdge(1, 'execute', 'p', 'file', 'EVENT_EXECUTE', 1, 'h', 'process', 'file'),
        StoredEdge(2, 'fork', 'p', 'q', 'EVENT_FORK', 2, 'h', 'process', 'process'),
        StoredEdge(3, 'poi', 'q', 'x', 'EVENT_SENDTO', 3, 'h', 'process', 'process')])
    result = diffuse_importance(graph, {'q'}, {1: 1., 2: 1., 3: 1.},
        mode='relation_time_contrastive', seed_edges=[graph.edges[-1]], rcvp_config=preset('full'))
    assert result.edge_evidence[1]['poi_backward_score'] > 0
    assert set(result.edge_evidence) == {1, 2, 3}
    assert result.edge_scores[3] == 1.
    assert result.rcvp_diagnostics['operator'] == 'exact_temporal_max_product'
    assert all(isinstance(row['relation_family'], str) for row in result.edge_evidence.values())


def test_rcvp_resolves_scoring_damping_unless_rcvp_explicitly_overrides():
    graph = Neighborhood({n: NodeRecord(n, 'process', n) for n in 'abc'}, [
        StoredEdge(1, 'before', 'a', 'b', 'EVENT_FORK', 1, 'h', 'process', 'process'),
        StoredEdge(2, 'poi', 'b', 'c', 'EVENT_FORK', 2, 'h', 'process', 'process')])
    inherited = diffuse_importance(graph, {'b'}, {1: 1., 2: 1.}, damping=.4,
        mode='relation_time_contrastive', seed_edges=[graph.edges[-1]], rcvp_config={})
    explicit = diffuse_importance(graph, {'b'}, {1: 1., 2: 1.}, damping=.4,
        mode='relation_time_contrastive', seed_edges=[graph.edges[-1]], rcvp_config={'damping': .7})
    assert inherited.rcvp_diagnostics['config']['damping'] == pytest.approx(.4)
    assert explicit.rcvp_diagnostics['config']['damping'] == pytest.approx(.7)


def test_loaded_rcvp_config_inherits_scoring_damping_only_when_omitted(tmp_path):
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / 'configs/tc_pruning_poi_alert.json').read_text())
    document['scoring']['diffusion_mode'] = 'relation_time_contrastive'
    document['scoring']['damping'] = .42
    document['rcvp'] = {'mixing': 'uniform'}
    path = tmp_path / 'inherited.json'; path.write_text(json.dumps(document))
    assert load_experiment_config(path).rcvp_config['damping'] == pytest.approx(.42)
    document['rcvp']['damping'] = .73
    path.write_text(json.dumps(document))
    assert load_experiment_config(path).rcvp_config['damping'] == pytest.approx(.73)


def test_online_scores_and_ledger_do_not_depend_on_groundtruth_file(tmp_path):
    from tc_pruning.causal import CausalSearchConfig
    from tc_pruning.evaluation import AttackAnnotations, run_experiment
    from tc_pruning.models import EdgeRecord
    from tc_pruning.store import ProvenanceStore
    from tc_pruning.score_ledger import verify_score_ledger
    import hashlib
    database = tmp_path / 'graph.db'
    online = AttackAnnotations(name='fixed-online', seed_uuids=set(), seed_event_ids={'poi'},
        seed_event_groups=[{'poi'}], seed_event_group_ids=['window'], seed_event_sequences=[('poi',)],
        investigation_windows={'window': (10, 40)}, attack_event_ids=set(), attack_node_uuids=set())
    hashes = []
    with ProvenanceStore(database) as store:
        store.ingest([NodeRecord(n, 'process', n, 'h') for n in 'abcdef'] + [
            EdgeRecord('history', 'e', 'f', 'EVENT_WRITE', 1, 'h'),
            EdgeRecord('root', 'a', 'b', 'EVENT_FORK', 10, 'h'),
            EdgeRecord('bridge', 'b', 'c', 'EVENT_FORK', 20, 'h'),
            EdgeRecord('poi', 'c', 'd', 'EVENT_SENDTO', 30, 'h'),
            EdgeRecord('noise', 'e', 'f', 'EVENT_WRITE', 40, 'h')])
        for i, labels in enumerate([['root', 'bridge'], ['noise']]):
            truth_file = tmp_path / f'truth-{i}.json'
            truth_file.write_text(json.dumps({'name': f'truth-{i}', 'seed_uuids': [],
                                            'attack_event_ids': labels, 'attack_node_uuids': []}))
            ledger = tmp_path / f'ledger-{i}'
            report = run_experiment(store, online, keep_ratios=(.5, .75),
                diffusion_mode='relation_time_contrastive', rcvp_config=preset('full'),
                pruning_mode='progressive', fusion_mode='rdp_guard', rarity_weight=.2,
                protect_alert_edges=True, connectivity_protection=True,
                causal_search_config=CausalSearchConfig(seed_strategy='window_context'),
                include_method_comparison=False, kmeans_restarts=2,
                groundtruth_annotations=lambda p=truth_file: AttackAnnotations.load(p, require_seeds=False),
                score_ledger_dir=ledger)
            assert verify_score_ledger(ledger)['valid']
            hashes.append(hashlib.sha256((ledger / 'edge-scores.jsonl.gz').read_bytes()).hexdigest())
            assert report['rcvp_diagnostics']['truth_used'] is False
        assert hashes[0] == hashes[1]


def test_rcvp_prefix_winner_evidence_tracks_immutable_local_scores():
    from tc_pruning.rdp_guard import PrefixScoreAccumulator, RDPGuardScores
    state = PrefixScoreAccumulator()
    state.add('a', RDPGuardScores({1: .8, 2: .2}, {1: {}, 2: {}}))
    state.add_rcvp_evidence('a', {1: {'diffusion_verified': .8}, 2: {'diffusion_verified': .2}}, {'config': {'a': 1}})
    first_digest = state.local_score_digests['a']
    state.add('b', RDPGuardScores({1: .3, 2: .9}, {1: {}, 2: {}}))
    state.add_rcvp_evidence('b', {1: {'diffusion_verified': .3}, 2: {'diffusion_verified': .9}}, {'config': {'a': 1}})
    assert state.winner_edge_evidence[1]['poi_event_id'] == 'a'
    assert state.winner_edge_evidence[2]['poi_event_id'] == 'b'
    assert state.local_score_digests['a'] == first_digest


def test_rcvp_group_winner_uses_truthful_poi_from_run_metadata():
    from tc_pruning.rdp_guard import PrefixScoreAccumulator, RDPGuardScores
    state = PrefixScoreAccumulator()
    state.add('group-7', RDPGuardScores({1: .8}, {1: {}}))
    state.add_rcvp_evidence(
        'group-7', {1: {'diffusion_verified': .8}},
        {'poi_event_ids': ['actual-poi'], 'config': {'schema_version': 1}},
    )
    assert state.winner_edge_evidence[1]['poi_event_id'] == 'actual-poi'
    assert 'group-7' not in state.winner_edge_evidence[1].values()


def test_rcvp_multi_poi_group_does_not_invent_winner_poi_identity():
    from tc_pruning.rdp_guard import PrefixScoreAccumulator, RDPGuardScores
    state = PrefixScoreAccumulator()
    state.add('group-8', RDPGuardScores({1: .8}, {1: {}}))
    state.add_rcvp_evidence(
        'group-8', {1: {'diffusion_verified': .8}},
        {'poi_event_ids': ['poi-a', 'poi-b'], 'config': {'schema_version': 1}},
    )
    assert 'poi_event_id' not in state.winner_edge_evidence[1]
    assert state.winner_edge_evidence[1]['poi_event_ids'] == ['poi-a', 'poi-b']


def test_real_two_poi_progressive_prefix_writes_verifiable_monotone_ledger(tmp_path):
    import gzip
    from tc_pruning.causal import CausalSearchConfig
    from tc_pruning.evaluation import AttackAnnotations, run_experiment
    from tc_pruning.models import EdgeRecord
    from tc_pruning.score_ledger import verify_score_ledger
    from tc_pruning.store import ProvenanceStore

    database = tmp_path / 'prefix.db'
    ledger = tmp_path / 'ledger'
    annotations = AttackAnnotations(
        name='two-poi-prefix', seed_uuids=set(),
        seed_event_ids={'poi-1', 'poi-2'},
        seed_event_groups=[{'poi-1'}, {'poi-2'}],
        seed_event_group_ids=['one', 'two'],
        seed_event_sequences=[('poi-1', 'poi-2')],
        investigation_windows={'prefix': (10, 50)},
        attack_event_ids=set(), attack_node_uuids=set(),
    )
    with ProvenanceStore(database) as store:
        store.ingest(
            [NodeRecord(node, 'process', node, 'h') for node in 'abcdef']
            + [
                EdgeRecord('root', 'a', 'b', 'EVENT_FORK', 10, 'h'),
                EdgeRecord('poi-1', 'b', 'c', 'EVENT_SENDTO', 20, 'h'),
                EdgeRecord('bridge', 'c', 'd', 'EVENT_FORK', 30, 'h'),
                EdgeRecord('poi-2', 'd', 'e', 'EVENT_SENDTO', 40, 'h'),
                EdgeRecord('noise', 'e', 'f', 'EVENT_WRITE', 50, 'h'),
            ]
        )
        report = run_experiment(
            store, annotations, keep_ratios=(.6, .8),
            diffusion_mode='relation_time_contrastive', rcvp_config=preset('full'),
            pruning_mode='progressive', fusion_mode='rdp_guard',
            poi_aggregation='noisy_or', rarity_weight=.2,
            protect_alert_edges=True, connectivity_protection=True,
            causal_search_config=CausalSearchConfig(seed_strategy='window_context'),
            include_method_comparison=False, kmeans_restarts=2,
            score_ledger_dir=ledger, include_internal_state=True,
        )

    assert verify_score_ledger(ledger)['valid'] is True
    accumulator = report['_online_state']['prefix_score_accumulator']
    assert set(accumulator.local_score_digests) == {'poi-1', 'poi-2'}
    with gzip.open(ledger / 'edge-scores.jsonl.gz', 'rt') as stream:
        aggregate = {row['edge_id']: row['score'] for row in map(json.loads, stream)}
    with gzip.open(ledger / 'poi-local-contributions.jsonl.gz', 'rt') as stream:
        local_rows = list(map(json.loads, stream))
    assert all(aggregate[row['edge_id']] + 1e-15 >= row['local_score'] for row in local_rows)
    assert all(row['churn_bound_satisfied'] for row in report['results'])
