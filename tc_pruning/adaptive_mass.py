"""Stratified score-mass selection with strict temporal POI witnesses.

Experimental selector, not a calibrated attack probability or a full-chain
guarantee. No ground-truth inputs. Existing rarity/diffusion scores are reused.
"""
from __future__ import annotations

import numpy as np


def temporal_successors(src, dst, timestamp, poi, minimum_hops=False):
    """One strictly later successor toward a POI per reachable event.

    Equal-time batches never observe each other's updates. Reverse-time latest
    witnesses are deterministic for fixed input order. Returns -1 for terminals
    or unreachable events; the separate reachable mask distinguishes them.
    """
    n = len(src)
    successor = np.full(n, -1, dtype=np.int64)
    reachable = np.asarray(poi, dtype=bool).copy()
    future = {}
    depth = np.zeros(n, dtype=np.int64)
    order = np.argsort(-np.asarray(timestamp), kind="stable")
    start = 0
    while start < n:
        end = start + 1
        while end < n and timestamp[order[end]] == timestamp[order[start]]:
            end += 1
        for i in order[start:end]:
            if not poi[i] and int(dst[i]) in future:
                successor[i] = future[int(dst[i])]
                depth[i] = depth[successor[i]] + 1
                reachable[i] = True
        for i in order[start:end]:
            if reachable[i]:
                previous = future.get(int(src[i]))
                if not minimum_hops or previous is None or depth[i] < depth[previous]:
                    future[int(src[i])] = int(i)
        start = end
    return successor, reachable


def fit_score_mixture(scores, max_iter=60):
    """Unsupervised two-Gaussian mixture on log positive importance scores.

    High-component responsibilities are NOT malicious-event probabilities.
    BIC must favor two components over one; otherwise abstain (all zero).
    Zero scores are excluded from fitting and never become high-score evidence.
    """
    scores = np.asarray(scores, dtype=float)
    if not np.all(np.isfinite(scores)) or np.any(scores < 0):
        raise ValueError("scores must be finite and nonnegative")
    positive = scores > 0
    posterior = np.zeros(len(scores))
    x = np.log(scores[positive])
    if len(x) < 10 or float(np.std(x)) < 1e-8:
        return posterior, {"status": "abstained_insufficient_variation"}
    # Deterministic initialization and variance floor prevent singular fits.
    mu = np.quantile(x, [.25, .75])
    variance = np.full(2, max(float(x.var()), 1e-4))
    weights = np.array([.5, .5])
    last = -np.inf
    for iteration in range(max_iter):
        logp = np.stack([np.log(weights[k])-.5*(np.log(2*np.pi*variance[k])+(x-mu[k])**2/variance[k]) for k in range(2)], axis=1)
        norm = np.logaddexp(logp[:, 0], logp[:, 1])
        resp = np.exp(logp-norm[:, None])
        likelihood = float(norm.sum())
        if abs(likelihood-last) <= 1e-7*max(1., abs(likelihood)):
            break
        last = likelihood
        count = np.maximum(resp.sum(axis=0), 1e-8)
        weights = count/count.sum()
        mu = (resp*x[:, None]).sum(axis=0)/count
        variance = np.maximum((resp*(x[:, None]-mu)**2).sum(axis=0)/count, 1e-4)
    # Recompute likelihood/responsibilities at the final fitted parameters.
    logp = np.stack([np.log(weights[k])-.5*(np.log(2*np.pi*variance[k])+(x-mu[k])**2/variance[k]) for k in range(2)], axis=1)
    norm = np.logaddexp(logp[:, 0], logp[:, 1])
    resp = np.exp(logp-norm[:, None])
    null_ll = float((-.5*(np.log(2*np.pi*x.var())+(x-x.mean())**2/x.var())).sum())
    bic1, bic2 = 2*np.log(len(x))-2*null_ll, 5*np.log(len(x))-2*float(norm.sum())
    accepted = bool(bic2 < bic1)
    high = int(np.argmax(mu))
    # A posterior can rise again in a broad low-score tail. Require scores on
    # the high side of the fitted means' midpoint as well.
    if accepted:
        posterior[positive] = np.where(x >= float(mu.mean()), resp[:, high], 0.)
    return posterior, {"status": "fitted" if accepted else "abstained_bic",
                       "bic_one": float(bic1), "bic_two": float(bic2),
                       "log_means": mu.tolist(), "variances": variance.tolist(),
                       "weights": weights.tolist(), "iterations": iteration+1,
                       "semantics": "high-score mixture membership, not attack probability"}


def close_witnesses(selected, successor):
    """Linear amortized union of selected events and their witness suffixes."""
    closed = np.asarray(selected, dtype=bool).copy()
    visited = np.zeros(len(closed), dtype=bool)
    for origin in np.flatnonzero(closed):
        i = int(origin)
        while i >= 0 and not visited[i]:
            visited[i] = True
            closed[i] = True
            i = int(successor[i])
    return closed


def select_mass(scores, strata, protected, loss=0.1):
    """Minimum unprotected cardinality per disjoint stratum, before closure.

    Retain at least (1-loss) of each positive stratum's heuristic score mass.
    This is a score-mass guarantee only, not a bound on attack false negatives.
    """
    scores = np.asarray(scores, dtype=float)
    strata = np.asarray(strata)
    selected = np.asarray(protected, dtype=bool).copy()
    if not 0 <= loss < 1 or len(scores) != len(strata) or len(scores) != len(selected):
        raise ValueError("invalid loss or mismatched arrays")
    if not np.all(np.isfinite(scores)) or np.any(scores < 0):
        raise ValueError("scores must be finite and nonnegative")
    thresholds = []
    # Sort by stratum then decreasing score, stable input index tie breaker.
    order = np.lexsort((np.arange(len(scores)), -scores, strata))
    bounds = np.r_[0, np.flatnonzero(np.diff(strata[order])) + 1, len(order)]
    for lo, hi in zip(bounds[:-1], bounds[1:]):
        indices = order[lo:hi]
        if not len(indices):
            continue
        total = float(scores[indices].sum())
        needed = max(0., (1-loss)*total - float(scores[indices[selected[indices]]].sum()))
        candidates = indices[(~selected[indices]) & (scores[indices] > 0)]
        take = min(len(candidates), int(np.searchsorted(np.cumsum(scores[candidates]), needed)) + 1) if needed > 0 else 0
        selected[candidates[:take]] = True
        retained_mass = float(scores[indices[selected[indices]]].sum())
        thresholds.append({"stratum": int(strata[indices[0]]), "edges": len(indices),
                           "selected": int(selected[indices].sum()), "total_mass": total,
                           "retained_mass": retained_mass,
                           "threshold": float(scores[candidates[take-1]]) if take else None,
                           "constraint_met": retained_mass + 1e-10*max(1., total) >= (1-loss)*total})
    return selected, thresholds
