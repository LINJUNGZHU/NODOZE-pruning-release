"""Relation-aware contrastive verification on a strict temporal event DAG.

Like the existing temporal diffuser this uses maximum-transmission support,
not a stationary PageRank distribution. Evaluation is an exact timestamp sweep
in the log semiring. Relation-normalized channels are duplicate-invariant;
waiting is implicit and equal-time events never feed each other. This is
investigation relevance, not attack probability or an estimate of a true source.
"""
from __future__ import annotations

import math
import numpy as np

from .rcvp_config import validate_config, relation_families
from .causal import fanout_partition, fanout_priority_score


# Exact scalar timestamp-block evaluation avoids repeated tiny NumPy sorts.
SMALL_TIMESTAMP_BATCH = 4

def build_operator(src, dst, timestamp, relations, rarity, config=None, *, anchor_ns=None):
    cfg = validate_config(config)
    src, dst, timestamp, relations, rarity = map(np.asarray, (src, dst, timestamp, relations, rarity))
    n = len(src)
    if not n or any(v.ndim != 1 or len(v) != n for v in (src, dst, timestamp, relations, rarity)):
        raise ValueError('nonempty equally-sized one-dimensional event arrays required')
    if any(v.dtype.kind not in 'iu' for v in (src, dst, timestamp)) or np.any(src < 0) or np.any(dst < 0):
        raise ValueError('endpoints and nanosecond timestamps must be integers')
    if not np.all(np.isfinite(rarity)) or np.any((rarity < 0) | (rarity > 1)):
        raise ValueError('rarity must be finite in [0,1]')
    family = relation_families(relations, cfg)
    names, family_id = np.unique(family, return_inverse=True)
    # Deduplicate original normalized relation, not just its coarser family.
    _, relation_id = np.unique(relations, return_inverse=True)
    channels, inv = np.unique(np.column_stack((src, dst, relation_id)), axis=0, return_inverse=True)
    mass = np.zeros(len(channels))
    np.maximum.at(mass, inv, cfg['rarity_floor'] + (1 - cfg['rarity_floor']) * rarity)
    channel_family = np.zeros(len(channels), dtype=int)
    channel_family[inv] = family_id
    node_count = int(max(src.max(), dst.max())) + 1
    def weights(side):
        endpoint = channels[:, side]
        if cfg['mixing'] == 'legacy':
            total = np.bincount(endpoint, weights=mass, minlength=node_count)
            return (mass / total[endpoint])[inv]
        groups, group_id = np.unique(np.column_stack((endpoint, channel_family)), axis=0, return_inverse=True)
        total = np.bincount(group_id, weights=mass)
        omega = np.array([1. if cfg['mixing'] == 'uniform' else cfg['relation_weights'][names[r]] for r in groups[:, 1]])
        omega_total = np.bincount(groups[:, 0], weights=omega, minlength=node_count)
        return (mass / total[group_id] * omega[group_id] / omega_total[endpoint])[inv]
    partition_ns = max(1, int(cfg['high_frequency_partition_seconds'] * 1e9))
    def fanout(endpoint):
        # Same high-degree threshold, raw-neighbor count and POI-relative bin
        # rule as causal search; measured on the frozen candidate adjacency.
        degree = np.bincount(endpoint, minlength=node_count)
        buckets = fanout_partition(timestamp, int(timestamp.min()) if anchor_ns is None else anchor_ns, partition_ns)
        bins, bin_id, counts = np.unique(np.column_stack((endpoint, buckets)),
                                         axis=0, return_inverse=True, return_counts=True)
        local = np.where(degree[endpoint] >= cfg['high_frequency_degree'], counts[bin_id], degree[endpoint])
        counts_unique, count_index = np.unique(local, return_inverse=True)
        correction = np.array([fanout_priority_score(int(c)) ** cfg['fanout_gamma'] for c in counts_unique])
        return correction[count_index]
    taus = [cfg['temporal_tau_overrides'].get(str(r), cfg['temporal_tau_seconds']) for r in names]
    inverse = np.array([0. if t is None else 1. / t for t in taus])
    unique_tau, tau_ids = np.unique(inverse, return_inverse=True)
    order = np.lexsort((np.arange(n), relation_id, dst, src, timestamp))
    starts = np.r_[0, np.flatnonzero(np.diff(timestamp[order])) + 1, n]
    return dict(src=src, dst=dst, timestamp=timestamp, family=family, family_id=family_id,
                family_names=names, family_inverse_taus=inverse, channel_index=inv,
                channel_mass=mass, channel_family=channel_family, channels=channels,
                forward_weight=weights(0), reverse_weight=weights(1),
                forward_fanout=fanout(src), reverse_fanout=fanout(dst),
                inverse_taus=unique_tau, tau_index=tau_ids[family_id],
                order=order, starts=starts, node_count=node_count, config=cfg,
                unique_channels=len(channels))


def temporal_pass(operator, seeds, *, reverse=False, broadcast_nodes=None, inclusive=False):
    """Sparse timed seeds `(node, timestamp_ns, mass)`; -1 broadcasts to a mask.

    inclusive is only for a root's observed first departure event: the root is
    the source state immediately before that event, not an invented earlier
    timestamp. Every event-to-event step remains strictly ordered.
    """
    o = operator
    count, n = len(o['src']), o['node_count']
    invtau = o['family_inverse_taus']
    a, b = (o['dst'], o['src']) if reverse else (o['src'], o['dst'])
    fanout = o['reverse_fanout'] if reverse else o['forward_fanout']
    channel_nodes = o['channels'][:, 1 if reverse else 0]
    remaining = np.zeros((n, len(invtau)))
    remaining_count = np.zeros((n, len(invtau)), dtype=np.int64)
    np.add.at(remaining, (channel_nodes, o['channel_family']), o['channel_mass'])
    np.add.at(remaining_count, (channel_nodes, o['channel_family']), 1)
    # Retire a deduplicated channel only at its last eligible observation in
    # sweep direction. Every temporal state then sees the correct active
    # relation distribution without constructing O(E^2) event adjacencies.
    positions = np.empty(count, dtype=np.int64)
    positions[o['order']] = np.arange(count)
    last = np.full(len(o['channels']), count if reverse else -1, dtype=np.int64)
    (np.minimum.at if reverse else np.maximum.at)(last, o['channel_index'], positions)
    last_event = np.zeros(count, dtype=bool)
    last_event[o['order'][last]] = True
    omega = np.array([1. if o['config']['mixing'] == 'uniform' else o['config']['relation_weights'][r] for r in o['family_names']])
    logs = np.full(count, -np.inf)
    parent = np.full(count, -1, dtype=np.int64)
    origin = np.full(count, -1, dtype=np.int64)
    decay = np.zeros(count)
    transition = np.zeros(count)
    state = np.full((n, len(invtau)), -np.inf)
    state_event = np.full((n, len(invtau)), -1, dtype=np.int64)
    state_origin = np.full((n, len(invtau)), -1, dtype=np.int64)
    state_time = np.zeros((n, len(invtau)))
    state_norm = np.zeros((n, len(invtau)))
    sign = -1 if reverse else 1
    base = int(o['timestamp'].min())
    # Subtract integer epoch first; converting absolute ns to float loses
    # ordering information. Strict ordering itself is always integer based.
    seconds = (o['timestamp'] - base).astype(float) / 1e9 * sign
    seed_rows = sorted(enumerate(seeds), key=lambda item: (sign * int(item[1][1]), int(item[1][0]), item[0]))
    cursor = 0
    groups = range(len(o['starts']) - 1)
    if reverse:
        groups = reversed(range(len(o['starts']) - 1))
    logdamping = math.log(o['config']['damping']) if o['config']['damping'] else -np.inf
    event_mass = o['channel_mass'][o['channel_index']]
    logweight = np.log(event_mass * fanout) + logdamping
    def normalization(node):
        mass = remaining[node]
        if o['config']['mixing'] == 'legacy':
            total = mass.sum(axis=-1, keepdims=True)
            return np.divide(np.ones_like(mass), total, out=np.zeros_like(mass), where=total > 0)
        active = (remaining_count[node] > 0) * omega
        denominator = active.sum(axis=-1, keepdims=True) * mass
        return np.divide(active, denominator, out=np.zeros_like(mass), where=denominator > 0)
    def publish(node, x, value, event, seed_index):
        norm = normalization(node)
        lognorm = np.full_like(norm, -np.inf)
        np.log(norm, out=lognorm, where=norm > 0)
        values = value + x * invtau + lognorm
        improve = values > state[node]
        state[node] = np.where(improve, values, state[node])
        state_event[node] = np.where(improve, event, state_event[node])
        state_origin[node] = np.where(improve, seed_index, state_origin[node])
        state_time[node] = np.where(improve, x, state_time[node])
        state_norm[node] = np.where(improve, norm, state_norm[node])
    def retire(batch):
        ids = batch[last_event[batch]]
        channels = o['channel_index'][ids]
        nodes, families = a[ids], o['family_id'][ids]
        np.add.at(remaining, (nodes, families), -o['channel_mass'][channels])
        np.add.at(remaining_count, (nodes, families), -1)
        remaining[nodes, families] = np.where(remaining_count[nodes, families] > 0,
                                              remaining[nodes, families], 0.)
    def publish_scalar(node, x, value, event, seed_index):
        masses, counts = remaining[node], remaining_count[node]
        legacy = o['config']['mixing'] == 'legacy'
        total = sum(masses) if legacy else sum(omega[k] for k in range(len(invtau)) if counts[k] > 0)
        if total <= 0:
            return
        for k in range(len(invtau)):
            if counts[k] <= 0:
                continue
            norm = 1. / total if legacy else omega[k] / (total * masses[k])
            updated = value + x * invtau[k] + math.log(norm)
            if updated > state[node, k]:
                state[node, k] = updated
                state_event[node, k] = event
                state_origin[node, k] = seed_index
                state_time[node, k] = x
                state_norm[node, k] = norm
    for group in groups:
        batch = o['order'][o['starts'][group]:o['starts'][group + 1]]
        timestamp = int(o['timestamp'][batch[0]])
        while cursor < len(seed_rows):
            si, (node, stamp, mass) = seed_rows[cursor]
            if sign * int(stamp) > sign * timestamp or (not inclusive and int(stamp) == timestamp):
                break
            if not math.isfinite(mass) or mass <= 0 or mass > 1:
                raise ValueError('seed mass must be in (0,1]')
            if node != -1 and not 0 <= node < n:
                raise ValueError('seed node outside graph')
            x = (int(stamp) - base) / 1e9 * sign
            if node == -1:
                if broadcast_nodes is None:
                    raise ValueError('broadcast seed requires node mask')
                indices = np.flatnonzero(broadcast_nodes)
                publish(indices, x, math.log(mass), -1, si)
            else:
                publish(node, x, math.log(mass), -1, si)
            cursor += 1
        if len(batch) == 1:
            # Most high-resolution provenance timestamps contain one event.
            # Avoid allocating/sorting temporary arrays in that common case.
            i = int(batch[0])
            node, tau = int(a[i]), int(o['family_id'][i])
            value = state[node, tau] - seconds[i] * invtau[tau]
            if math.isfinite(value):
                logs[i] = value + logweight[i]
                parent[i] = state_event[node, tau]
                origin[i] = state_origin[node, tau]
                decay[i] = math.exp(-max(0., seconds[i] - state_time[node, tau]) * invtau[tau])
                transition[i] = event_mass[i] * state_norm[node, tau]
            if last_event[i]:
                remaining[node, tau] -= event_mass[i]
                remaining_count[node, tau] -= 1
                if remaining_count[node, tau] == 0:
                    remaining[node, tau] = 0.
            if math.isfinite(logs[i]):
                publish_scalar(int(b[i]), seconds[i], logs[i], i, origin[i])
            continue
        if len(batch) <= SMALL_TIMESTAMP_BATCH:
            # Equal-time events must all read the previous state before any
            # destination is published. Numeric event index breaks ties exactly
            # as the vector reference does, independently of endpoint order.
            ids = sorted(map(int, batch))
            for i in ids:
                node, tau = int(a[i]), int(o['family_id'][i])
                value = state[node, tau] - seconds[i] * invtau[tau]
                if math.isfinite(value):
                    logs[i] = value + logweight[i]
                    parent[i] = state_event[node, tau]
                    origin[i] = state_origin[node, tau]
                    decay[i] = math.exp(-max(0., seconds[i] - state_time[node, tau]) * invtau[tau])
                    transition[i] = event_mass[i] * state_norm[node, tau]
            for i in batch:
                if last_event[i]:
                    node, tau = int(a[i]), int(o['family_id'][i])
                    remaining[node, tau] -= event_mass[i]
                    remaining_count[node, tau] -= 1
                    if remaining_count[node, tau] == 0:
                        remaining[node, tau] = 0.
            for i in ids:
                if math.isfinite(logs[i]):
                    publish_scalar(int(b[i]), seconds[i], logs[i], i, origin[i])
            continue
        # Vector reads happen before any writes for this timestamp.
        nodes, ti = a[batch], o['family_id'][batch]
        values = state[nodes, ti] - seconds[batch] * invtau[ti]
        reachable = np.isfinite(values)
        ids = batch[reachable]
        logs[ids] = values[reachable] + logweight[ids]
        parent[ids] = state_event[nodes[reachable], ti[reachable]]
        origin[ids] = state_origin[nodes[reachable], ti[reachable]]
        decay[ids] = np.exp(-np.maximum(0., seconds[ids] - state_time[nodes[reachable], ti[reachable]]) * invtau[ti[reachable]])
        transition[ids] = event_mass[ids] * state_norm[nodes[reachable], ti[reachable]]
        retire(batch)
        # Publish per target using vectorized max reduction. Ties use first
        # canonical event, so witnesses remain immutable and reproducible.
        for tau in range(len(invtau)):
            norm = normalization(b[ids])[:, tau]
            lognorm = np.full(len(ids), -np.inf)
            np.log(norm, out=lognorm, where=norm > 0)
            vals = logs[ids] + seconds[ids] * invtau[tau] + lognorm
            if not len(ids):
                continue
            destinations = b[ids]
            sort = np.lexsort((ids, -vals, destinations))
            ordered_dest = destinations[sort]
            first = np.r_[True, ordered_dest[1:] != ordered_dest[:-1]]
            choices = sort[first]
            targets, events = destinations[choices], ids[choices]
            improve = vals[choices] > state[targets, tau]
            targets, events = targets[improve], events[improve]
            state[targets, tau] = vals[choices][improve]
            state_event[targets, tau] = events
            state_origin[targets, tau] = origin[events]
            state_time[targets, tau] = seconds[events]
            state_norm[targets, tau] = norm[choices][improve]
    return dict(log_support=logs, parent=parent, seed_index=origin, temporal_weight=decay,
                transition_weight=transition)


def contrast(poi_log, background_log, epsilon=1e-300):
    """log1p(max(exp(log_p-log_q)-1,0)), without exp overflow."""
    result = np.maximum(np.asarray(poi_log) - np.maximum(background_log, math.log(epsilon)), 0.)
    result[~np.isfinite(poi_log)] = 0.
    return result


def _normalize(values):
    maximum = float(np.max(values, initial=0.))
    return values / maximum if maximum else np.zeros_like(values), maximum


def propagate(src, dst, timestamp, relation_names, rarity, poi, process_nodes, config=None):
    poi = np.asarray(poi, dtype=bool)
    if poi.shape != np.asarray(src).shape or not poi.any():
        raise ValueError('POI mask must match graph; at least one POI required')
    o = build_operator(src, dst, timestamp, relation_names, rarity, config,
                       anchor_ns=int(np.min(np.asarray(timestamp)[poi])))
    cfg = o['config']
    poi = np.asarray(poi, dtype=bool)
    process_nodes = np.asarray(process_nodes, dtype=bool)
    if poi.shape != o['src'].shape or not poi.any() or process_nodes.shape != (o['node_count'],):
        raise ValueError('POI and process masks must match graph; at least one POI required')
    poi_ids = np.flatnonzero(poi)
    seeds = []
    for i in poi_ids:
        endpoints = sorted({int(o['src'][i]), int(o['dst'][i])})
        seeds.extend((node, int(o['timestamp'][i]), 1. / (len(poi_ids) * len(endpoints))) for node in endpoints)
    background_nodes = process_nodes if process_nodes.any() else np.ones(o['node_count'], dtype=bool)
    background_seeds = [(-1, int(o['timestamp'][i]), 1. / (len(poi_ids) * int(background_nodes.sum()))) for i in poi_ids]
    f = temporal_pass(o, seeds)
    b = temporal_pass(o, seeds, reverse=True)
    bf = temporal_pass(o, background_seeds, broadcast_nodes=background_nodes)
    bb = temporal_pass(o, background_seeds, reverse=True, broadcast_nodes=background_nodes)
    flift = contrast(f['log_support'], bf['log_support'], cfg['epsilon'])
    blift = contrast(b['log_support'], bb['log_support'], cfg['epsilon'])
    forward, forward_scale = _normalize(flift if cfg['background_contrast'] else np.exp(f['log_support']))
    backward, backward_scale = _normalize(blift if cfg['background_contrast'] else np.exp(b['log_support']))
    # Root eligibility uses observed backward support, independent of labels
    # and of whether background contrast hard-zeros a necessary ancestor.
    candidates = np.flatnonzero(np.isfinite(b['log_support']) & process_nodes[o['src']] & ~poi)
    best = {}
    for i in candidates:
        node = int(o['src'][i])
        old = best.get(node)
        if old is None or (b['log_support'][i], -int(o['timestamp'][i]), -int(i)) > (b['log_support'][old], -int(o['timestamp'][old]), -int(old)):
            best[node] = int(i)
    chosen = sorted(best.values(), key=lambda i: (-b['log_support'][i], int(o['src'][i]), int(o['timestamp'][i]), i))
    roots = []
    if chosen and cfg['backward_enabled']:
        peak = float(max(b['log_support'][i] for i in chosen))
        root_values = {i: math.exp(float(b['log_support'][i]) - peak) for i in chosen}
        cutoff = max(cfg['root_min_score'], float(np.quantile(list(root_values.values()), cfg['root_quantile'])))
        chosen = [i for i in chosen if root_values[i] > 0 and root_values[i] >= cutoff][:cfg['max_root_candidates']]
        total = sum(root_values[i] for i in chosen)
        for i in chosen:
            witness, j = [], i
            while j >= 0:
                witness.append(j)
                j = int(b['parent'][j])
            roots.append(dict(node=int(o['src'][i]), timestamp_ns=int(o['timestamp'][i]),
                              score=root_values[i], seed_weight=root_values[i] / total,
                              backward_log_support=float(b['log_support'][i]), witness=witness,
                              poi_seed_index=int(b['seed_index'][i])))
    root_seeds = [(r['node'], r['timestamp_ns'], r['seed_weight']) for r in roots]
    rf = temporal_pass(o, root_seeds, inclusive=True) if cfg['verification_enabled'] else dict(log_support=np.full(len(poi), -np.inf))
    root_forward, root_scale = _normalize(np.exp(rf['log_support']))
    # Normalize direct upstream support before harmonic verification. Contrast
    # still gates the backward channel; a root-forward channel can independently
    # explain a background-common upstream witness.
    upstream, upstream_scale = _normalize(np.exp(b['log_support']))
    denominator = upstream + root_forward
    roundtrip = np.divide(2 * upstream * root_forward, denominator,
                          out=np.zeros_like(upstream), where=denominator > 0)
    backward_channel = backward if cfg['backward_enabled'] else np.zeros_like(backward)
    channels = (backward_channel, forward, roundtrip)
    lambdas = cfg['channel_weights']
    verified = 1 - (1-lambdas['backward']*channels[0]) * (1-lambdas['forward']*channels[1]) * (1-lambdas['verification']*channels[2])
    relation_diffusion = 1 - (1-lambdas['backward']*backward_channel) * (1-lambdas['forward']*forward)
    legacy = np.zeros(len(poi))
    legacy_diag = None
    if cfg['include_legacy']:
        from .rasp import propagate as legacy_propagate
        _, legacy_relations = np.unique(relation_names, return_inverse=True)
        legacy, legacy_diag = legacy_propagate(o['src'], o['dst'], legacy_relations, rarity, poi, process_nodes,
            dict(rarity_floor=cfg['rarity_floor'], restart=cfg['legacy_restart'],
                 iterations=cfg['legacy_iterations'], tolerance=cfg['legacy_tolerance'], escape_floor=0.))
    verified[poi] = 1.
    relation_diffusion[poi] = 1.
    fields = dict(relation_family=o['family'], relation_transition_weight=f['transition_weight'],
        relation_backward_transition_weight=b['transition_weight'], temporal_weight=f['temporal_weight'],
        backward_temporal_weight=b['temporal_weight'], fanout_weight=o['forward_fanout'], backward_fanout_weight=o['reverse_fanout'],
        poi_forward_score=np.exp(f['log_support']), background_forward_score=np.exp(bf['log_support']), forward_lift=flift,
        poi_backward_score=np.exp(b['log_support']), background_backward_score=np.exp(bb['log_support']), backward_lift=blift,
        root_forward_score=np.exp(rf['log_support']), roundtrip_verification_score=roundtrip,
        forward_normalized=forward, backward_normalized=backward_channel, root_forward_normalized=root_forward,
        diffusion_legacy=legacy, diffusion_relation_aware=relation_diffusion, diffusion_verified=verified.copy())
    return verified, dict(version='rasp-rcvp-v1', operator='exact_temporal_max_product',
        config=cfg, edge_fields=fields, roots=roots, backward_parent=b['parent'],
        forward_parent=f['parent'], normalization=dict(forward=forward_scale, backward=backward_scale,
            root_forward=root_scale, upstream=upstream_scale), unique_channels=o['unique_channels'],
        iterations=1, converged=True, residual_l1=0.,
        legacy_converged=None if legacy_diag is None else bool(legacy_diag['background']['converged'] and all(x['converged'] for x in legacy_diag['personalized'])),
        truth_used=False, score_is_probability=False)
