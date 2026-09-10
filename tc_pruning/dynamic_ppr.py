"""Signed residual PPR maintenance, inspired by Zhang et al., KDD 2016.

Invariant: r = alpha*s + (1-alpha)*P.T*p - p. Weighted row edits repair
this invariant before local relaxation. This is not their degree-error API.
Dangling rows self-loop; seed changes are explicitly repaired.
"""
from collections import defaultdict, deque
import math


class DynamicPPR:
    def __init__(self, restart=.15):
        if not 0 < restart < 1:
            raise ValueError('restart must be in (0,1)')
        self.alpha = restart
        self.adj = defaultdict(dict)
        self.p = defaultdict(float)
        self.r = defaultdict(float)
        self.seed = {}

    def row(self, u):
        total = sum(self.adj[u].values())
        return {v: w/total for v, w in self.adj[u].items()} if total else {u: 1.}

    def set_seed(self, weights):
        if not weights or any(not math.isfinite(v) or v < 0 for v in weights.values()) or sum(weights.values()) <= 0:
            raise ValueError('nonempty nonnegative seed required')
        total = sum(weights.values())
        seed = {k: v/total for k, v in weights.items()}
        for u in self.seed.keys() | seed.keys():
            self.r[u] += self.alpha*(seed.get(u, 0)-self.seed.get(u, 0))
        self.seed = seed

    def set_edge(self, u, v, weight):
        if not math.isfinite(weight) or weight < 0:
            raise ValueError('nonnegative finite weight required')
        for a, b in ((u, v),) if u == v else ((u, v), (v, u)):
            if self.adj[a].get(b, 0) == weight:
                continue
            old = self.row(a)
            if weight:
                self.adj[a][b] = weight
            else:
                self.adj[a].pop(b, None)
            new = self.row(a)
            for node in old.keys() | new.keys():
                self.r[node] += (1-self.alpha)*self.p[a]*(new.get(node, 0)-old.get(node, 0))

    def solve(self, tolerance=1e-7, max_pushes=1000000):
        if tolerance <= 0 or max_pushes < 1:
            raise ValueError('positive tolerance and work cap required')
        # Coordinate threshold implies global L1 error <= tolerance when done.
        nodes = set(self.adj) | set(self.r) | set(self.seed)
        threshold = self.alpha*tolerance/max(1, len(nodes))
        queue = deque(u for u in nodes if abs(self.r[u]) > threshold)
        queued = set(queue)
        pushes = 0
        while queue and pushes < max_pushes:
            u = queue.popleft(); queued.remove(u)
            delta = self.r[u]
            self.r[u] = 0.
            self.p[u] += delta
            pushes += 1
            for v, probability in self.row(u).items():
                self.r[v] += (1-self.alpha)*delta*probability
                if abs(self.r[v]) > threshold and v not in queued:
                    queue.append(v); queued.add(v)
        bound = sum(abs(v) for v in self.r.values())/self.alpha
        return {'pushes': pushes, 'error_l1_bound': bound,
                'converged': bound <= tolerance, 'nodes': len(nodes)}
