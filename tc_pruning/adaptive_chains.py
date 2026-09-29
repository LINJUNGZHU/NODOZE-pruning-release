"""Budgeted selection of whole observed temporal witnesses, without attack labels.

Completeness here is relative to the candidate graph and the chosen witnesses.
No finite, sampled witness set establishes completeness of a real attack.
"""
from __future__ import annotations

from collections import Counter
from math import sqrt
from typing import Mapping, Sequence

import numpy as np

from .rasp import temporal_fork_routes, temporal_routes


def causal_endpoints(row: Mapping) -> tuple[str, str]:
    a, b = str(row['src']), str(row['dst'])
    return (b, a) if str(row['relation']).upper() == 'EVENT_EXECUTE' else (a, b)


def _inputs(rows, score):
    score = np.asarray(score, dtype=float)
    if score.shape != (len(rows),) or not np.all(np.isfinite(score)) or np.any(score < 0):
        raise ValueError('one finite nonnegative score is required per event')
    ids = [str(row['event_id']) for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError('event IDs must be unique')
    nodes = {}
    pairs = [causal_endpoints(row) for row in rows]
    src = np.asarray([nodes.setdefault(a, len(nodes)) for a, _ in pairs], dtype=np.int64)
    dst = np.asarray([nodes.setdefault(b, len(nodes)) for _, b in pairs], dtype=np.int64)
    times = [row['timestamp_ns'] for row in rows]
    if any(isinstance(t, (bool, np.bool_)) or not (isinstance(t, (int, np.integer)) or (isinstance(t, str) and t.lstrip('-').isdigit())) for t in times):
        raise ValueError('timestamp_ns must be an exact integer')
    timestamp = np.asarray([int(t) for t in times], dtype=np.int64)
    poi = np.asarray([bool(row.get('is_declared_poi', False)) for row in rows])
    return score, ids, src, dst, timestamp, poi


def _continuations(src, dst, timestamp, score, ids, reverse=False):
    """One deterministic maximum-discounted-evidence predecessor per event.

    Batch publication forbids equal-time chaining. Temporal states are acyclic,
    even when the entity graph has cycles. No reference labels enter this DP.
    """
    a, b = (dst, src) if reverse else (src, dst)
    order = sorted(range(len(src)), key=lambda i: ((-int(timestamp[i]) if reverse else int(timestamp[i])), ids[i]))
    parent = np.full(len(src), -1, dtype=np.int64)
    value = np.zeros(len(src))
    best = {}
    begin = 0
    while begin < len(order):
        end = begin+1
        while end < len(order) and timestamp[order[end]] == timestamp[order[begin]]:
            end += 1
        for i in order[begin:end]:
            j = best.get(int(a[i]), -1)
            parent[i] = j
            value[i] = .05 + float(score[i]) + (.9*value[j] if j >= 0 else 0.)
        for i in order[begin:end]:
            node = int(b[i]); j = best.get(node, -1)
            if j < 0 or value[i] > value[j] or (value[i] == value[j] and ids[i] < ids[j]):
                best[node] = i
        begin = end
    return parent


def _walk(index, links, cap):
    path = []
    while index >= 0 and len(path) < cap:
        path.append(int(index)); index = int(links[index])
    return path, index >= 0


def _family(row):
    # Program/relation/resource type diversity; resource UUID multiplicity must
    # not make a noisy application win every anchor slot.
    return (str(row.get('src_semantic', row['src'])), str(row['relation']),
            str(row.get('dst_type', 'unknown')))


def build_chain_bundles(rows: Sequence[Mapping], score, *, max_hops=64, max_anchors=4096):
    if not isinstance(max_hops, int) or max_hops < 1 or not isinstance(max_anchors, int) or max_anchors < 1:
        raise ValueError('positive integer witness limits required')
    score, ids, src, dst, timestamp, poi = _inputs(rows, score)
    if not len(rows):
        return [], {'eligible_event_ids': [], 'truncated_bundles': 0, 'anchor_limit_reached': False}
    # Stable event-ID order removes ingestion-order tie dependence in the
    # existing minimum-hop route operators.
    order = np.asarray(sorted(range(len(rows)), key=lambda i: ids[i]), dtype=int)
    inv = np.empty(len(order), dtype=int); inv[order] = np.arange(len(order))
    links, direction, reachable, _ = temporal_routes(src[order], dst[order], timestamp[order], poi[order])
    fp, pv, fork_reach, _ = temporal_fork_routes(src[order], dst[order], timestamp[order], poi[order], links[0])
    def original_indices(values):
        result = np.full(len(order), -1, dtype=int)
        valid = values >= 0
        result[order[valid]] = order[values[valid]]
        return result
    back, forward = [original_indices(x) for x in links]
    fork_parent, pivot = original_indices(fp), original_indices(pv)
    eligible = np.zeros(len(rows), dtype=bool); eligible[order] = fork_reach
    prev = _continuations(src, dst, timestamp, score, ids)
    nxt = _continuations(src, dst, timestamp, score, ids, reverse=True)
    family = [_family(row) for row in rows]
    counts = Counter(family[i] for i in np.flatnonzero(eligible))
    anchors = sorted(np.flatnonzero(eligible & ((score > 0) | poi)),
                     key=lambda i: (not poi[i], -score[i]/sqrt(counts[family[i]]), ids[i]))
    anchor_limit = len(anchors) > max(max_anchors, int(poi.sum()))
    anchors = anchors[:max(max_anchors, int(poi.sum()))]
    bundles, seen, truncations = [], set(), 0
    for anchor in anchors:
        # A causal fork is two individually valid directed paths, never a fake
        # single traversal which jumps backwards through the common ancestor.
        branch, cut = _walk(int(anchor), fork_parent, max_hops)
        branch.reverse()
        root = int(pivot[anchor])
        to_alert, cut2 = _walk(root, back, max_hops)
        # The legacy routes may meet either alert endpoint. Split at a
        # shared-endpoint turn: it is a real fork/join, not a directed step.
        raw_paths = []
        for route in (branch, to_alert):
            segment = []
            for edge in route:
                if segment and (dst[segment[-1]] != src[edge] or timestamp[segment[-1]] >= timestamp[edge]):
                    raw_paths.append(segment)
                    segment = []
                segment.append(edge)
            if segment:
                raw_paths.append(segment)
        paths, incomplete = [], cut or cut2
        for path in raw_paths:
            if not path:
                continue
            prefix, left_cut = _walk(int(prev[path[0]]), prev, max_hops)
            suffix, right_cut = _walk(int(nxt[path[-1]]), nxt, max_hops)
            full = list(reversed(prefix)) + path + suffix
            incomplete |= left_cut or right_cut or len(full) > max_hops
            # Preserve the alert connection even if extension exceeds the cap;
            # the result is explicitly incomplete and cannot certify a chain.
            if len(full) > max_hops:
                full = path
            if full not in paths:
                paths.append(full)
        # Suppress paths contained in a longer witness, but keep real branches.
        paths = [p for p in paths if not any(len(q)>len(p) and any(q[k:k+len(p)]==p for k in range(len(q)-len(p)+1)) for q in paths)]
        members = tuple(sorted({i for p in paths for i in p}, key=lambda i: ids[i]))
        if not members or members in seen:
            continue
        seen.add(members); truncations += int(incomplete)
        bundles.append({'id': f'bundle-{len(bundles)+1}', 'anchor_index': int(anchor),
                        'event_indices': list(members), 'paths': paths,
                        'complete_in_candidate': not incomplete,
                        'boundary_status': 'candidate_boundary_unverified',
                        'scope': 'selected_observed_witnesses_only'})
    return bundles, {'eligible_event_ids': [ids[i] for i in np.flatnonzero(eligible)],
                     'eligible_events': int(eligible.sum()), 'bundle_count': len(bundles),
                     'truncated_bundles': truncations, 'anchor_limit_reached': anchor_limit,
                     'max_hops': max_hops, 'max_anchors': max_anchors,
                     'global_attack_completeness': 'unknown',
                     'boundary_status': 'candidate_boundary_unverified'}


def select_chain_bundles(rows, score, bundles, budget):
    score, ids, _, _, _, poi = _inputs(rows, score)
    if isinstance(budget, bool) or not isinstance(budget, (int, np.integer)) or budget < int(poi.sum()) or budget < 1 or budget > len(rows):
        raise ValueError('raw event budget must fit declared alerts and not exceed candidate size')
    kept = poi.copy()
    families = [_family(row) for row in rows]
    poi_indices = set(np.flatnonzero(poi))
    ranked = []
    minimum_alert_cost = None
    for bundle in bundles:
        members = bundle['event_indices']
        if not bundle['complete_in_candidate']:
            continue
        quality = {}
        for i in members:
            quality[families[i]] = max(quality.get(families[i], 0.), float(score[i]))
        cost = len(set(members)-poi_indices)
        value = sum(quality.values()) / sqrt(max(1, cost))
        has_alert = any(poi[i] for i in members)
        if has_alert:
            minimum_alert_cost = min(minimum_alert_cost or len(members), len(members))
        ranked.append((not has_alert, -value, tuple(ids[i] for i in members), bundle))
    ranked.sort(key=lambda x:x[:3])
    blocked, selected, used = 0, [], int(kept.sum())
    for _, _, _, bundle in ranked:
        added = [i for i in bundle['event_indices'] if not kept[i]]
        if len(added) > budget-used:
            blocked += 1
            continue
        if added:
            kept[added] = True; used += len(added); selected.append(bundle['id'])
    complete = [b for b in bundles if b['complete_in_candidate'] and all(kept[i] for i in b['event_indices'])]
    completed_members = {i for b in complete for i in b['event_indices']}
    return kept, {'budget_edges': int(budget), 'retained_edges': int(kept.sum()),
                  'budget_feasible': True, 'budget_overflow_edges': 0,
                  'unused_budget': int(budget-kept.sum()), 'blocked_by_budget': blocked,
                  'selected_bundle_ids': selected,
                  'retained_complete_bundles': len(complete),
                  'minimum_alert_bundle_edges': minimum_alert_cost,
                  'alert_only_events': [ids[i] for i in np.flatnonzero(poi) if i not in completed_members],
                  'complete_attack_guarantee': False}


def run_adaptive(rows, score, *, budget, max_hops=64, max_anchors=4096):
    bundles, diagnostics = build_chain_bundles(rows, score, max_hops=max_hops, max_anchors=max_anchors)
    kept, selection = select_chain_bundles(rows, score, bundles, budget)
    return kept, {**diagnostics, **selection}


def select_adaptive_bundles(rows, score, bundles, budget):
    """Try complete continuations; retain the original witness if they cannot fit.

    Resource bounds limit completion attempts, never the original candidate
    coverage. Fallback witnesses remain explicitly partial. The returned mask
    always counts the original events of both completions and connectors.
    """
    import hashlib
    score, ids, src, dst, timestamp, poi = _inputs(rows, score)
    if isinstance(budget, bool) or not isinstance(budget, (int, np.integer)) or not int(poi.sum()) <= budget <= len(rows) or budget < 1:
        raise ValueError('invalid raw-event budget')
    # Use deterministic ingestion order for the established route operators.
    stable=np.asarray(sorted(range(len(rows)),key=lambda i:ids[i]),dtype=int)
    back=temporal_routes(src[stable],dst[stable],timestamp[stable],poi[stable])[0][0]
    parent,pivot,reachable,_=temporal_fork_routes(src[stable],dst[stable],timestamp[stable],poi[stable],back)
    inverse=np.empty(len(stable),dtype=int);inverse[stable]=np.arange(len(stable))
    by_anchor={b['anchor_index']:b for b in bundles}
    # Deduplication may give another event ownership of the same complete
    # witness; let every member request that same indivisible certificate.
    for b in bundles:
        if b['complete_in_candidate']:
            for i in b['event_indices']:by_anchor.setdefault(i,b)
    tie=lambda i:int.from_bytes(hashlib.sha256(ids[i].encode()).digest()[:8],'big')
    order=sorted(range(len(rows)),key=lambda i:(not poi[i],-score[i],tie(i)))
    kept=poi.copy();used=int(kept.sum());fallback=blocked=0;selected=[]
    for i in order:
        if used==budget:break
        b=by_anchor.get(i)
        if b and b['complete_in_candidate']:
            add=[j for j in b['event_indices'] if not kept[j]]
            if len(add)<=budget-used:
                if add:kept[add]=True;used+=len(add);selected.append(b['id'])
            else:blocked+=1
        if kept[i] or score[i]<=0 or not reachable[inverse[i]]:continue
        path=set();j=int(inverse[i])
        while j>=0:
            if not kept[stable[j]]:path.add(int(stable[j]))
            j=int(parent[j])
        j=int(pivot[inverse[i]])
        while j>=0:
            if not kept[stable[j]]:path.add(int(stable[j]))
            j=int(back[j])
        if len(path)<=budget-used:
            kept[list(path)]=True;used+=len(path);fallback+=1
    complete=[b for b in bundles if b['complete_in_candidate'] and all(kept[i] for i in b['event_indices'])]
    members={i for b in complete for i in b['event_indices']}
    return kept,{'budget_edges':int(budget),'retained_edges':int(kept.sum()),'budget_feasible':True,
                 'budget_overflow_edges':0,'unused_budget':int(budget-kept.sum()),'blocked_by_budget':blocked,
                 'fallback_witnesses':fallback,'selected_bundle_ids':selected,
                 'retained_complete_bundles':len(complete),'complete_attack_guarantee':False,
                 'alert_only_events':[ids[i] for i in np.flatnonzero(poi) if i not in members],
                 'fallback_policy':'original_temporal_fork_witness; not a complete-attack certificate'}
