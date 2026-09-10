"""Microbatch CDM/normalized JSONL ingestion with reversible window pruning.

No prebuilt database. Snapshot scores use only observations already ingested.
The source logs remain the authoritative archive; this prototype is not a
durable tail/rotation consumer and does not guarantee cross-window recall.
"""
import argparse
from collections import Counter, defaultdict, deque
from dataclasses import asdict
import gzip
import json
import math
from pathlib import Path
import time

import numpy as np
from tc_pruning.cdm import normalize_cdm_record
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.dynamic_ppr import DynamicPPR
from tc_pruning.history_archive import HistoryArchive
from tc_pruning.rasp import temporal_routes, temporal_fork_routes, select_fork_bundles


class StreamRASP:
    def __init__(self, poi_ids, window=20000, budget=.2, archive=None):
        if window < 1 or not 0 < budget <= 1:
            raise ValueError('invalid window/budget')
        self.poi_ids = set(poi_ids)
        self.window, self.budget = window, budget
        self.events = deque(); self.active_ids = set()
        self.nodes = {}; self.types = {}
        self.counts = Counter(); self.total = 0
        self.ppr = DynamicPPR(); self.weights = {}
        self.late = 0; self.latest = -1
        self.archive = archive
        self.alert_endpoints = set()

    def ingest(self, event):
        if isinstance(event, NodeRecord):
            self.types[event.uuid] = event.node_type
            return False
        if event.event_id in self.active_ids:
            return False
        for node in (event.src, event.dst):
            if node not in self.nodes: self.nodes[node] = len(self.nodes)
        pattern = (self.types.get(event.src, 'unknown'), event.relation, self.types.get(event.dst, 'unknown'))
        # Prequential rarity: score before updating counts, never future counts.
        rarity = math.log((self.total+2)/(self.counts[pattern]+1))/math.log(self.total+2)
        self.counts[pattern] += 1; self.total += 1
        self.late += event.timestamp_ns < self.latest
        self.latest = max(self.latest, event.timestamp_ns)
        self.events.append((event, rarity)); self.active_ids.add(event.event_id)
        if self.archive:
            self.archive.append(dict(asdict(event), rarity=rarity))
        if event.event_id in self.poi_ids:
            self.alert_endpoints.update((event.src, event.dst))
        if len(self.events) > self.window:
            old, _ = self.events.popleft(); self.active_ids.remove(old.event_id)
        return True

    def snapshot(self):
        started = time.perf_counter()
        events = list(self.events)
        retrieval = {}
        if self.archive:
            self.archive.flush()
            if self.alert_endpoints:
                recovered, retrieval = self.archive.retrieve(self.alert_endpoints, self.latest, hops=2)
                combined = {e.event_id:(e,r) for e,r in events}
                for row in recovered:
                    e = EdgeRecord(**{k:row[k] for k in ('event_id','src','dst','relation','timestamp_ns')})
                    combined.setdefault(e.event_id,(e,row['rarity']))
                events = list(combined.values())
        n = len(events)
        channels = {}
        for e, rarity in events:
            a, b = sorted((self.nodes[e.src], self.nodes[e.dst]))
            key = (a, b, e.relation)
            channels[key] = max(channels.get(key, 0), .2+.8*rarity)
        weights = defaultdict(float)
        for (a, b, _), w in channels.items(): weights[a, b] += w
        for a, b in self.weights.keys() | weights.keys():
            self.ppr.set_edge(a, b, weights.get((a, b), 0))
        self.weights = weights
        src = np.array([self.nodes[e.dst if e.relation=='EVENT_EXECUTE' else e.src] for e, _ in events], dtype=int)
        dst = np.array([self.nodes[e.src if e.relation=='EVENT_EXECUTE' else e.dst] for e, _ in events], dtype=int)
        ts = np.array([e.timestamp_ns for e, _ in events], dtype=np.int64)
        poi = np.array([e.event_id in self.poi_ids for e, _ in events], dtype=bool)
        seed = Counter()
        for a, b in zip(src[poi], dst[poi]): seed[int(a)] += 1; seed[int(b)] += 1
        kept = np.zeros(n, dtype=bool); scores = np.zeros(n)
        diag = {'converged': False, 'status': 'waiting_for_poi'}
        cap = int(len(self.events)*self.budget)
        if seed:
            self.ppr.set_seed(seed); diag = self.ppr.solve()
            # Degree stationary reference, distinct from batch process-seeded PPR.
            degree = {u: sum(adj.values()) for u, adj in self.ppr.adj.items()}
            volume = sum(degree.values()) or 1.
            lift = {u: math.log1p(max(0., self.ppr.p[u]/max(degree.get(u, 0)/volume, 1e-15)-1)) for u in set(src)|set(dst)}
            scores = np.array([(.2+.8*r)*math.sqrt(lift[a]*lift[b]) for (e, r), a, b in zip(events, src, dst)])
            if scores.max() > 0: scores /= scores.max()
            scores[poi] = 1.
            if not diag['converged']:
                diag['status'] = 'provisional_nonconverged_no_pruning'
            elif poi.sum() > cap:
                diag['status'] = 'infeasible_poi_budget_no_pruning'
            else:
                back = temporal_routes(src, dst, ts, poi)[0][0]
                parent, pivot, reachable, _ = temporal_fork_routes(src, dst, ts, poi, back)
                kept, _ = select_fork_bundles(scores, poi, back, parent, pivot, cap)
                _, _, after, _ = temporal_fork_routes(src[kept], dst[kept], ts[kept], poi[kept])
                assert int((kept & reachable).sum()) == int(after.sum())
                diag['status'] = 'ready'
        report = {'seen_events': self.total, 'active_events': n, 'retained_events': int(kept.sum()),
                  'hot_window_events':len(self.events), 'history_retrieval':retrieval,
                  'budget_edges': cap, 'late_arrivals': self.late, 'active_pois': int(poi.sum()),
                  'history_nodes': len(self.nodes), 'snapshot_seconds': time.perf_counter()-started,
                  'propagation': diag, 'raw_log_deletion': False,
                  'scope': 'arrival-count window; no complete-attack guarantee'}
        rows = [dict(asdict(e), rarity=r, score=float(s), retained=bool(k) if diag['status']=='ready' else None,
                     decision_status=diag['status']) for (e, r), s, k in zip(events, scores, kept)]
        return report, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--poi', type=Path, required=True, help='JSON list of alert event IDs')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--window', type=int, default=20000)
    parser.add_argument('--batch', type=int, default=5000)
    parser.add_argument('--max-events', type=int, default=0)
    parser.add_argument('--history', action='store_true', help='retain indexed shards and recover two-hop alert history')
    args = parser.parse_args()
    if args.batch < 1: parser.error('batch must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    archive = HistoryArchive(args.output/'archive') if args.history else None
    engine = StreamRASP(json.loads(args.poi.read_text()), args.window, archive=archive)
    def publish():
        report, rows = engine.snapshot()
        version = engine.total
        with gzip.open(args.output/f'edges-{version}.jsonl.gz', 'wt') as out:
            for row in rows: out.write(json.dumps(row)+'\n')
        with (args.output/'progress.jsonl').open('a') as out: out.write(json.dumps(report)+'\n')
        print(json.dumps(report), flush=True)
    opener = gzip.open if args.input.suffix == '.gz' else open
    with opener(args.input, 'rt') as stream:
        for line in stream:
            raw = json.loads(line)
            observations = [EdgeRecord(**{k: raw[k] for k in ('event_id','src','dst','relation','timestamp_ns')})] if 'event_id' in raw else normalize_cdm_record(raw)
            for event in observations:
                if engine.ingest(event) and engine.total % args.batch == 0: publish()
            if args.max_events and engine.total >= args.max_events: break
    if engine.total % args.batch: publish()


if __name__ == '__main__': main()
