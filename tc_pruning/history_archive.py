"""Append-only event shards and exact endpoint-to-shard metadata.

No attack labels or pretrained database. Endpoint neighborhoods are retrieval
candidates, not causal certificates. Single writer; committed manifests only.
"""
import gzip
import hashlib
import json
from pathlib import Path


class HistoryArchive:
    def __init__(self, root, shard_size=5000):
        if shard_size < 1: raise ValueError('positive shard size required')
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root/'manifest.json'
        self.shards = json.loads(self.path.read_text()) if self.path.exists() else []
        self.pending = []; self.shard_size = shard_size

    def append(self, row):
        # Persist only normalized input and precomputed historical rarity.
        clean = {k: row[k] for k in ('event_id','src','dst','relation','timestamp_ns','rarity')}
        self.pending.append(clean)
        if len(self.pending) >= self.shard_size: self.flush()

    def flush(self):
        if not self.pending: return
        name = f'shard-{len(self.shards):08d}.jsonl.gz'
        target = self.root/name
        if target.exists(): raise ValueError('uncommitted shard exists; recovery required')
        temp = target.with_suffix('.tmp')
        with gzip.open(temp, 'wt') as stream:
            for row in self.pending: stream.write(json.dumps(row)+'\n')
        temp.replace(target)
        nodes = sorted({str(r[k]) for r in self.pending for k in ('src','dst')})
        times = [r['timestamp_ns'] for r in self.pending]
        self.shards.append({'file': name, 'nodes': nodes, 'min_time': min(times),
                            'max_time': max(times), 'events': len(times),
                            'sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(self.shards)); temp.replace(self.path)
        self.pending.clear()

    def retrieve(self, endpoints, before_ns, hops=2, after_ns=None):
        if hops < 0: raise ValueError('nonnegative hops required')
        if self.pending: raise ValueError('flush before query')
        frontier, visited, found = set(map(str, endpoints)), set(), {}
        reads = scanned = 0
        for _ in range(hops):
            if not frontier: break
            next_frontier = set()
            for shard in self.shards:
                if shard['min_time'] > before_ns or (after_ns is not None and shard['max_time'] < after_ns): continue
                if frontier.isdisjoint(shard['nodes']): continue
                path = self.root/shard['file']; reads += 1
                if hashlib.sha256(path.read_bytes()).hexdigest() != shard['sha256']:
                    raise ValueError('archive checksum mismatch')
                with gzip.open(path, 'rt') as stream:
                    for line in stream:
                        row = json.loads(line); scanned += 1
                        if row['timestamp_ns'] > before_ns or (after_ns is not None and row['timestamp_ns'] < after_ns): continue
                        if str(row['src']) not in frontier and str(row['dst']) not in frontier: continue
                        found[row['event_id']] = row
                        next_frontier.update((str(row['src']), str(row['dst'])))
            visited.update(frontier); frontier = next_frontier-visited
        return list(found.values()), {'shard_reads': reads, 'rows_scanned': scanned,
                                      'retrieved_events': len(found), 'hops': hops,
                                      'complete_component': not frontier}
