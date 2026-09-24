"""Post-selection audit of group rank versus actual materialized positive closure."""
import argparse
import gzip
import json
from pathlib import Path

import numpy as np

from tc_pruning.candidate_views import rank_views
from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups
from tc_pruning.rasp import temporal_fork_routes, temporal_routes
from tc_pruning.temporal_diffusion import temporal_affinity
from scripts.history_channel_common import load_history, prepare_scores


def read(path):
    with gzip.open(path, 'rt') as f:
        return json.load(f)


def diagnose(case, input_dir):
    audit = json.loads(Path('docs/budget-evidence-v7/input_audit.json').read_text())
    info = audit['cases'][case]
    manifest = read(input_dir / f'case{case}' / 'manifest.json.gz')
    prior = read(info['inputs']['frozen_v6_decisions']['path'])
    data = load_ledger(Path(prior['ledger']))
    history, _ = load_history(case, prior['config'], data)
    if manifest.get('event_order') == 'lexicographic_event_id_for_E2_E3':
        data, history = canonical_event_order(data, history)
    window_ns = json.loads(Path('configs/budget_evidence_v7.json').read_text())['group_window_ns']
    channel_groups = interaction_groups(data['src'], data['dst'], data['timestamp'], window_ns)
    groups = GroupIndex.from_events(data['src'], data['dst'], data['relation'], data['timestamp'], data['tie'], window_ns)
    scores, _, _ = prepare_scores(data, prior['config'], history, channel_groups, ['history'])
    primary = scores['history_channel']
    back = temporal_routes(data['src'], data['dst'], data['timestamp'], data['poi'])[0][0]
    _, pivot, _, depth = temporal_fork_routes(data['src'], data['dst'], data['timestamp'], data['poi'], back)
    affinity = temporal_affinity(data['timestamp'], data['timestamp'][data['poi']], prior['config']['temporal_scale_ns'])
    temporal = affinity / (1 + np.minimum(depth, len(data['ids'])))
    temporal[pivot < 0] = 0
    scores_by_group = [groups.scores(view) for view in (primary, history, temporal)]
    ties = np.minimum.reduceat(data['tie'][groups.ordered_members], groups.offsets[:-1])
    reference = json.loads(Path('docs/sparse-five-local-critical-reference.json').read_text())['cases'][case]
    lookup = {eid: i for i, eid in enumerate(data['ids'])}
    positives = np.array([lookup[eid] for eid in reference['critical_event_ids']])
    positive_groups = np.unique(groups.group_of[positives])
    out = dict(scope='post-selection only; reference does not enter v7 retrieval', case_index=case,
               positive_events=len(positives), positive_groups=len(positive_groups), policies={})
    for policy in ('primary', 'rrf'):
        order = rank_views(*scores_by_group, ties, policy, 60)
        ranks = np.argsort(order)
        pool_entry = next(p for p in manifest['pools'] if p['pool_id'] == f'e2-c{case}-group-{policy}')
        visited = pool_entry['diagnostics']['n_group_refs']
        potentially_visited = positive_groups[ranks[positive_groups] < visited]
        pool = read(pool_entry['path'])
        out['policies'][policy] = dict(
            visited_descriptors=visited,
            positive_groups_potentially_visited=len(potentially_visited),
            positive_events_in_visited_groups=int(np.isin(groups.group_of[positives], potentially_visited).sum()),
            positive_events_in_actual_materialized_union=len(set(reference['critical_event_ids']) & set(pool['materialized_ids'])),
            positive_group_ranks_1based=(ranks[positive_groups] + 1).tolist(),
            largest_positive_group_size=int(max(np.bincount(groups.group_of[positives]))),
        )
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', type=int, required=True)
    p.add_argument('--input-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    with a.output.open('x') as f:
        json.dump(diagnose(a.case, a.input_dir), f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
