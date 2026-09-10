"""Diminishing-return anchor selection with complete RASP causal-fork bundles.

The evidence score stays fixed. Selection priority is state-dependent and is
not an anomaly probability. No knapsack approximation ratio is claimed.
"""
from __future__ import annotations

import heapq
import math

import numpy as np


def event_families(src, dst, relation):
    """Directed endpoint/relation families, with no attack/name information."""
    src, dst, relation = map(np.asarray, (src, dst, relation))
    order = np.lexsort((relation, dst, src))
    group = np.empty(len(src), dtype=np.int64)
    if not len(src):
        return group
    boundaries = np.r_[True, (np.diff(src[order]) != 0) | (np.diff(dst[order]) != 0) | (np.diff(relation[order]) != 0)]
    group[order] = np.cumsum(boundaries)-1
    return group


def marginal(score, weight, selected_mass, quality_weight):
    """Marginal of q*sum(s)+(1-q)*sum_g w_g*log(1+mass_g/w_g)."""
    if score <= 0 or weight <= 0:
        return 0.
    return quality_weight*score+(1-quality_weight)*weight*math.log1p(score/(weight+selected_mass))


def select_diverse(score, poi, backward, parent, pivot, family, budget, tie_order, quality_weight=.05):
    score, poi, family = np.asarray(score), np.asarray(poi, dtype=bool), np.asarray(family)
    n = len(score)
    if not 0 <= quality_weight <= 1 or not int(poi.sum()) <= budget <= n:
        raise ValueError("invalid quality weight or edge budget")
    if not np.all(np.isfinite(score)) or np.any(score < 0):
        raise ValueError("importance scores must be finite and nonnegative")
    if any(len(a) != n for a in (poi, backward, parent, pivot, family, tie_order)):
        raise ValueError("array lengths differ")
    kept, anchors = poi.copy(), poi.copy()
    priority = np.full(n, np.nan)
    selected_step = np.full(n, -1, dtype=np.int64)
    selected_step[poi] = 0
    group_count = int(family.max())+1 if n else 0
    weights = np.zeros(group_count)
    np.maximum.at(weights, family, score)
    mass = np.bincount(family[kept], weights=score[kept], minlength=group_count)
    eligible = np.flatnonzero((score > 0) & (pivot >= 0) & ~poi)
    order = eligible[np.lexsort((tie_order[eligible], -score[eligible], family[eligible]))]
    # One queue head per family. Within a family the marginal is monotone in s.
    starts = np.r_[0, np.flatnonzero(np.diff(family[order]))+1, len(order)]
    cursor = np.full(group_count, -1, dtype=np.int64)
    end = np.zeros(group_count, dtype=np.int64)
    heap = []
    def push(group):
        pos = int(cursor[group])
        while pos < end[group] and kept[order[pos]]:
            pos += 1
        cursor[group] = pos
        if pos < end[group]:
            i = int(order[pos])
            gain = marginal(float(score[i]), weights[group], mass[group], quality_weight)
            heapq.heappush(heap, (-gain, int(tie_order[i]), i, int(group)))
    for lo, hi in zip(starts[:-1], starts[1:]):
        if lo == hi:
            continue
        group = int(family[order[lo]])
        cursor[group], end[group] = lo, hi
        push(group)
    used, step, recomputations, skipped = int(kept.sum()), 0, 0, 0
    while heap and used < budget:
        negative, tie, i, group = heapq.heappop(heap)
        if kept[i]:
            cursor[group] += 1
            push(group)
            continue
        gain = marginal(float(score[i]), weights[group], mass[group], quality_weight)
        # Group mass only increases, so old marginals are valid UPPER bounds.
        # Do not divide by marginal bundle cost: shared connectors can decrease
        # that cost and invalidate the lazy-heap upper-bound argument.
        if heap and (-gain, tie, i, group) > heap[0]:
            heapq.heappush(heap, (-gain, tie, i, group))
            recomputations += 1
            continue
        path, j = set(), int(i)
        while j >= 0:
            if not kept[j]:
                path.add(j)
            j = int(parent[j])
        j = int(pivot[i])
        while j >= 0:
            if not kept[j]:
                path.add(j)
            j = int(backward[j])
        if len(path) <= budget-used:
            chosen = np.fromiter(path, dtype=np.int64)
            kept[chosen] = True
            anchors[i] = True
            step += 1
            selected_step[chosen] = step
            priority[i] = gain
            np.add.at(mass, family[chosen], score[chosen])
            used += len(chosen)
        else:
            skipped += 1
        cursor[group] += 1
        push(group)
    return kept, anchors, {"selection_priority": priority, "selected_step": selected_step,
                           "lazy_recomputations": recomputations, "skipped_over_cap": skipped,
                           "selected_families": int(np.count_nonzero(np.bincount(family[kept], minlength=group_count))),
                           "total_families": group_count}
