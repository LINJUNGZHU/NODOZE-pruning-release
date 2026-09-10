"""Rarity-aware, duplicate-invariant, background-contrasted seeded propagation.

No labels, file names, original pruning scores or decisions enter this scorer.
Temporal routes use CDM information-flow endpoints supplied by the caller.
"""
from __future__ import annotations

import numpy as np


def interaction_graph(src, dst, relation, rarity):
    """One undirected channel per unique endpoint pair + event relation.

    Repeating an identical interaction does not increase its conductance.
    Max rarity within a channel is invariant under exact record replication.
    """
    src, dst, relation, rarity = map(np.asarray, (src, dst, relation, rarity))
    a, b = np.minimum(src, dst), np.maximum(src, dst)
    order = np.lexsort((relation, b, a))
    if not len(order):
        return a, b, rarity
    change = (np.diff(a[order]) != 0) | (np.diff(b[order]) != 0) | (np.diff(relation[order]) != 0)
    starts = np.r_[0, np.flatnonzero(change)+1]
    return a[order[starts]], b[order[starts]], np.maximum.reduceat(rarity[order], starts)


def personalized_pagerank(a, b, weight, teleport, restart=.15, iterations=100, tolerance=1e-10):
    n = len(teleport)
    degree = np.bincount(a, weights=weight, minlength=n) + np.bincount(b, weights=weight, minlength=n)
    p = np.asarray(teleport, dtype=float).copy()
    p /= p.sum()
    seed = p.copy()
    residual = float("inf")
    for iteration in range(iterations):
        scaled = np.divide(p, degree, out=np.zeros(n), where=degree > 0)
        propagated = np.bincount(b, weights=weight*scaled[a], minlength=n)
        propagated += np.bincount(a, weights=weight*scaled[b], minlength=n)
        propagated += p[degree == 0].sum()*seed
        nxt = restart*seed+(1-restart)*propagated
        residual = float(np.abs(nxt-p).sum())
        p = nxt
        if residual <= tolerance:
            break
    return p, {"iterations": iteration+1, "residual_l1": residual,
               "converged": residual <= tolerance}, degree


def propagate(src, dst, relation, rarity, poi, process_nodes, config):
    src, dst, rarity, poi = map(np.asarray, (src, dst, rarity, poi))
    if len(src) == 0 or not poi.any():
        raise ValueError("RASP requires candidate events and at least one POI")
    if not np.all(np.isfinite(rarity)) or np.any((rarity < 0) | (rarity > 1)):
        raise ValueError("rarity must be finite in [0,1]")
    n = int(max(src.max(), dst.max()))+1
    a, b, channel_rarity = interaction_graph(src, dst, relation, rarity)
    floor = config["rarity_floor"]
    weights = floor+(1-floor)*channel_rarity
    kwargs = {k: config[k] for k in ("restart", "iterations", "tolerance")}
    background = np.asarray(process_nodes, dtype=float)
    if not background.any():
        background = np.ones(n)
    background, background_diag, _ = personalized_pagerank(a, b, weights, background, **kwargs)
    score, diffusion = np.zeros(len(src)), np.zeros(len(src))
    uncontrasted = np.zeros(len(src))
    winner = np.full(len(src), -1, dtype=np.int64)
    diagnostics = []
    for seed_edge in np.flatnonzero(poi):
        seed = np.zeros(n)
        seed[src[seed_edge]] += .5
        seed[dst[seed_edge]] += .5
        p, diag, _ = personalized_pagerank(a, b, weights, seed, **kwargs)
        plain = np.sqrt(p[src]*p[dst])*(floor+(1-floor)*rarity)
        if plain.max() > 0:
            plain /= plain.max()
        uncontrasted = np.maximum(uncontrasted, plain)
        # Positive excess over background: suppress nodes that are important
        # merely because many ordinary processes naturally reach them.
        lift = np.log1p(np.maximum(p/np.maximum(background, 1e-300)-1., 0.))
        evidence = np.sqrt(lift[src]*lift[dst])
        local = evidence*(floor+(1-floor)*rarity)
        if local.max() > 0:
            local /= local.max()
        improve = local > score
        score[improve] = local[improve]
        diffusion[improve] = evidence[improve]
        winner[improve] = seed_edge
        diagnostics.append({"poi_index": int(seed_edge), **diag})
    score[poi] = 1.
    uncontrasted[poi] = 1.
    contrast_only = score.copy()
    # A background-common edge can still be an indispensable explanation.
    # Preserve a weak PPR escape channel rather than hard-zeroing such edges.
    escape = config.get("escape_floor", 0.)
    score = (score+escape*uncontrasted)/(1+escape)
    return score, {"diffusion": diffusion, "winner": winner,
                   "uncontrasted": uncontrasted,
                   "contrast_only": contrast_only,
                   "unique_channels": len(a), "background": background_diag,
                   "personalized": diagnostics}


def temporal_routes(src, dst, timestamp, poi):
    """Minimum-hop monotone routes to the endpoints of a declared POI event.

    POI events expose both endpoint states. Subsequent intermediate events must
    follow directed information flow. Equal-time events cannot feed each other.
    This is anchored investigative reachability, not an attack truth claim.
    """
    n = len(src)
    links, depths = [], []
    for reverse in (True, False):
        a, b = (src, dst) if reverse else (dst, src)
        order = np.argsort(-timestamp if reverse else timestamp, kind="stable")
        parent = np.full(n, -1, dtype=np.int64)
        depth = np.full(n, n+1, dtype=np.int64)
        best = {}
        start = 0
        while start < n:
            end = start+1
            while end < n and timestamp[order[start]] == timestamp[order[end]]:
                end += 1
            for i in order[start:end]:
                if poi[i]:
                    depth[i] = 0
                elif int(b[i]) in best:
                    parent[i] = best[int(b[i])]
                    depth[i] = depth[parent[i]]+1
            for i in order[start:end]:
                if depth[i] <= n:
                    endpoints = (int(a[i]), int(b[i])) if poi[i] else (int(a[i]),)
                    for node in endpoints:
                        previous = best.get(node)
                        if previous is None or depth[i] < depth[previous]:
                            best[node] = int(i)
            start = end
        links.append(parent)
        depths.append(depth)
    direction = (depths[1] < depths[0]).astype(np.int8)
    reachable = np.minimum(*depths) <= n
    return links, direction, reachable, np.minimum(*depths)


def select_bundles(score, poi, links, direction, reachable, budget, tie_order=None):
    """Greedy rooted path packing under a HARD edge cap, never append overflow.

    Rank anchor evidence once. Each anchor is admitted with its complete chosen
    route, charging only newly added edges. No global-optimality claim is made.
    """
    n = len(score)
    if budget < int(poi.sum()) or budget > n:
        raise ValueError("edge cap cannot accommodate POIs or exceeds candidate size")
    selected = np.asarray(poi, dtype=bool).copy()
    anchor = selected.copy()
    used = int(selected.sum())
    ties = np.arange(n) if tie_order is None else tie_order
    order = np.lexsort((ties, -score))
    for i in order:
        if used == budget:
            break
        if selected[i] or score[i] <= 0 or not reachable[i]:
            continue
        parent = links[direction[i]]
        path, j = [], int(i)
        while j >= 0:
            if not selected[j]:
                path.append(j)
            j = int(parent[j])
        if len(path) <= budget-used:
            selected[path] = True
            anchor[i] = True
            used += len(path)
    return selected, anchor


def temporal_fork_routes(src, dst, timestamp, poi, backward=None):
    """A common ancestor may cause both the alert and a sibling attack branch.

    A pivot has a strict backward-to-alert witness. Forward DP grows another
    directed branch after that pivot. Each branch is time-monotone separately;
    the union is an anchored causal fork, not one monotone event sequence.
    """
    n = len(src)
    if backward is None:
        backward = temporal_routes(src, dst, timestamp, poi)[0][0]
    back_depth = np.full(n, n+1, dtype=np.int64)
    back_depth[poi] = 0
    for i in np.argsort(-timestamp, kind="stable"):
        if backward[i] >= 0:
            back_depth[i] = back_depth[backward[i]]+1
    parent = np.full(n, -1, dtype=np.int64)
    pivot = np.full(n, -1, dtype=np.int64)
    depth = np.full(n, n+1, dtype=np.int64)
    best = {}
    order = np.argsort(timestamp, kind="stable")
    start = 0
    while start < n:
        end = start+1
        while end < n and timestamp[order[start]] == timestamp[order[end]]:
            end += 1
        for i in order[start:end]:
            if back_depth[i] <= n:
                depth[i], pivot[i] = back_depth[i], i
            previous = best.get(int(src[i]))
            if previous is not None and depth[previous]+1 < depth[i]:
                depth[i], parent[i], pivot[i] = depth[previous]+1, previous, pivot[previous]
        for i in order[start:end]:
            if pivot[i] >= 0:
                endpoints = (int(src[i]), int(dst[i])) if pivot[i] == i else (int(dst[i]),)
                for node in endpoints:
                    previous = best.get(node)
                    if previous is None or depth[i] < depth[previous]:
                        best[node] = int(i)
        start = end
    return parent, pivot, pivot >= 0, depth


def select_fork_bundles(score, poi, backward, parent, pivot, budget, tie_order=None):
    n = len(score)
    if budget < int(poi.sum()) or budget > n:
        raise ValueError("invalid edge cap")
    kept, anchor = poi.copy(), poi.copy()
    used = int(kept.sum())
    order = np.lexsort((np.arange(n) if tie_order is None else tie_order, -score))
    for i in order:
        if used == budget:
            break
        if kept[i] or score[i] <= 0 or pivot[i] < 0:
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
            kept[list(path)] = True
            anchor[i] = True
            used += len(path)
    return kept, anchor
