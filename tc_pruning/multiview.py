"""Paper-inspired, temporally calibrated multi-view process anomaly detector.

An adaptation of independent-view fusion, not a reproduction of PROVFUSION.
No labels, POI, pruning scores, PID or UUID embeddings enter the learned models.
"""
from collections import defaultdict
from itertools import groupby
from pathlib import Path
import hashlib
import json
import time

import numpy as np

from tc_pruning.deep_graph import RELATIONS, WINDOW_NS, snapshots, text_vector, neighbor_distances

VIEWS = ('attribute', 'structural', 'causal')
STRUCT_DIM = 2 * len(RELATIONS) + 5
CAUSAL_DIM = 32 + len(RELATIONS) + 5
DEFAULT_MODEL = Path(__file__).resolve().parents[1] / 'models/optc-multiview-v1'


def feature_sources():
    root = Path(__file__).resolve().parents[1]
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
            for name in ('tc_pruning/multiview.py', 'tc_pruning/deep_graph.py')}


def resolve_context(view, index):
    """Resolve shared minute context; causal scopes exclude equal-time peers."""
    scope = view.get('context_scope')
    if scope is None:
        return list(view['evidence_event_ids'])
    minute = str(scope['minute'])
    if minute not in index:
        raise ValueError('view context minute missing')
    cutoff = scope.get('before_ns')
    ids = [eid for eid, timestamp in index[minute] if cutoff is None or timestamp < cutoff]
    return sorted(set(ids) | set(view.get('target_event_ids', [])))


def structural_graphs(edges):
    graphs = snapshots(edges)
    by_minute = defaultdict(list)
    for edge in edges:
        by_minute[edge['timestamp_ns'] // WINDOW_NS].append(edge)
    for graph in graphs:
        graph['attribute'] = graph['x'][:, 28:].copy()
        x = graph['x'][:, :STRUCT_DIM].copy()
        counts = np.expm1(x[:, :2 * len(RELATIONS)])
        x[:, :2 * len(RELATIONS)] = counts / np.maximum(np.linalg.norm(counts, axis=1, keepdims=True), 1)
        graph['x'] = x
        index = {nid: i for i, nid in enumerate(graph['node_ids'])}
        arcs = set()
        for edge in by_minute[graph['minute']]:
            raw = edge['raw']
            if raw['object'] != 'PROCESS' or raw['actorID'] == raw['objectID']:
                continue
            a, b = index[raw['actorID']], index[raw['objectID']]
            rel = RELATIONS.index(edge['relation']) if edge['relation'] in RELATIONS else len(RELATIONS)-1
            arcs.update(((a, b, rel), (b, a, rel + len(RELATIONS))))
        triples = np.array(sorted(arcs), dtype=np.int64).reshape(-1, 3)
        graph['arcs'], graph['relations'] = triples[:, :2].T, triples[:, 2]
    return graphs


def causal_samples(edges):
    """Predict current relation from strictly earlier, minute-local actor history.

    All equal-time inputs are emitted before updating history. Metadata learned
    at a creation event cannot flow backwards into its predictor input.
    """
    xs, ys, ids, actors, times = [], [], [], [], []
    history, images, previous = {}, {}, {}
    ordered = sorted(edges, key=lambda e: (e['timestamp_ns'], e['id']))
    for timestamp, batch in groupby(ordered, key=lambda e: e['timestamp_ns']):
        batch = list(batch)
        for edge in batch:
            raw = edge['raw']; actor = raw['actorID']
            key = (timestamp // WINDOW_NS, actor)
            counts = history.get(key, np.zeros(len(RELATIONS), dtype=np.float32))
            obj = [float(raw['object'] == kind) for kind in ('PROCESS', 'FILE', 'FLOW')]
            gap = (timestamp - previous[key]) / 1e9 if key in previous else 0.
            x = np.concatenate((text_vector(images.get(key, '')), counts / max(float(counts.sum()), 1),
                                obj, [np.log1p(counts.sum()), np.log1p(gap)]))
            xs.append(x); ys.append(RELATIONS.index(edge['relation']) if edge['relation'] in RELATIONS else len(RELATIONS)-1)
            ids.append(edge['id']); actors.append(actor); times.append(timestamp)
        for edge in batch:
            raw = edge['raw']; props = raw.get('properties', {}); key = (timestamp // WINDOW_NS, raw['actorID'])
            counts = history.setdefault(key, np.zeros(len(RELATIONS), dtype=np.float32))
            counts[RELATIONS.index(edge['relation']) if edge['relation'] in RELATIONS else len(RELATIONS)-1] += 1
            previous[key] = timestamp
            if raw['object'] == 'PROCESS' and raw['action'] == 'CREATE':
                image = props.get('parent_image_path', '')
                images[(timestamp // WINDOW_NS, raw['objectID'])] = props.get('image_path', '').replace('/', '\\').split('\\')[-1]
            else:
                image = props.get('image_path', '')
            if image:
                images[key] = image.replace('/', '\\').split('\\')[-1]
    return dict(x=np.asarray(xs, dtype=np.float32).reshape(-1, CAUSAL_DIM), y=np.asarray(ys, dtype=np.int64),
                event_ids=ids, actors=actors, timestamps=times)


def make_models(hidden=48):
    import torch
    from torch import nn

    class RelationalMaskedEncoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.mask = nn.Parameter(torch.zeros(STRUCT_DIM))
            self.input = nn.Linear(STRUCT_DIM, hidden)
            self.relations = nn.Embedding(2 * len(RELATIONS), hidden)
            self.layers = nn.ModuleList([nn.Linear(2 * hidden, hidden) for _ in range(2)])
            self.decoder = nn.Sequential(nn.Linear(hidden, hidden), nn.GELU(), nn.Linear(hidden, STRUCT_DIM))

        def encode(self, x, arcs, relations):
            h = torch.nn.functional.gelu(self.input(x))
            for layer in self.layers:
                agg = torch.zeros_like(h); degree = torch.zeros((len(h), 1), device=h.device)
                if arcs.shape[1]:
                    message = h[arcs[0]] * torch.sigmoid(self.relations(relations))
                    agg.index_add_(0, arcs[1], message)
                    degree.index_add_(0, arcs[1], torch.ones((arcs.shape[1], 1), device=h.device))
                h = torch.nn.functional.gelu(layer(torch.cat((h, agg / degree.clamp_min(1)), dim=1)))
            return h

        def forward(self, x, arcs, relations, mask):
            return self.decoder(self.encode(torch.where(mask[:, None], self.mask, x), arcs, relations))

    predictor = nn.Sequential(nn.Linear(CAUSAL_DIM, hidden), nn.GELU(), nn.Linear(hidden, len(RELATIONS)))
    return RelationalMaskedEncoder(), predictor


def dimensions(percentiles):
    p = np.asarray(percentiles, dtype=float)
    ranked = np.sort(p, axis=-1)
    def weighted(values):
        w = np.exp(5 * (values - values.max(axis=-1, keepdims=True)))
        return (w * values).sum(axis=-1) / w.sum(axis=-1)
    return np.stack((p[..., 0], p[..., 1], p[..., 2], ranked[..., -2:].sum(-1),
                     weighted(ranked[..., -2:]), p.sum(-1), weighted(p)), axis=-1)


def percentiles(scores, reference):
    scores = np.asarray(scores, dtype=float)
    if scores.shape[-1] != 3 or not np.isfinite(scores).all():
        raise ValueError('Expected three finite view scores')
    return np.stack([(np.searchsorted(r, scores[..., i], side='left') +
                      np.searchsorted(r, scores[..., i], side='right')) / (2 * len(r))
                     for i, r in enumerate(reference)], axis=-1)


def calibrate_fusion(scores):
    scores = np.asarray(scores, dtype=float)
    if scores.ndim != 2 or scores.shape[1] != 3 or len(scores) < 2 or not np.isfinite(scores).all():
        raise ValueError('Need at least two finite calibration processes')
    reference = [sorted(scores[:, i].tolist()) for i in range(3)]
    d = dimensions(percentiles(scores, reference))
    return dict(reference=reference, thresholds=np.quantile(d, .99, axis=0).tolist(),
                active=(np.ptp(d, axis=0) > 1e-12).tolist(), required_votes=4,
                quantile=.99, comparison='strict >', protocol='Midrank ECDF, seven dimensions, constant dimensions abstain; empirical calibration, not FPR control')


def fusion_decision(scores, calibration):
    p = percentiles(scores, calibration['reference']); d = dimensions(p)
    flags = (d > np.asarray(calibration['thresholds'])) & np.asarray(calibration['active'])
    return dict(percentiles=p.tolist(), dimensions=d.tolist(), flags=flags.tolist(), votes=int(flags.sum()),
                predicted=bool(flags.sum() >= calibration['required_votes']))


def _tensor_graph(graph, mean, scale):
    import torch
    return (torch.tensor(np.clip((graph['x'] - mean) / scale, -12, 12), dtype=torch.float32),
            torch.tensor(graph['arcs']), torch.tensor(graph['relations']))


def _view_scores(edges, graphs, encoder, predictor, bundle):
    import torch
    mean, scale = bundle['mean'].numpy(), bundle['scale'].numpy()
    rows = {}
    with torch.no_grad():
        for graph in graphs:
            z = encoder.encode(*_tensor_graph(graph, mean, scale)).numpy()
            z = (z - bundle['embedding_mean'].numpy()) / bundle['embedding_scale'].numpy()
            struct = neighbor_distances(z, bundle['reference_structure'].numpy())
            attr = neighbor_distances(graph['attribute'], bundle['reference_attribute'].numpy())
            for i, nid in enumerate(graph['node_ids']):
                row = rows.setdefault(nid, dict(raw=np.zeros(3), evidence=[[], [], []], scopes=[None,None,None]))
                for j, value in enumerate((attr[i], struct[i])):
                    if value >= row['raw'][j]:
                        row['raw'][j] = float(value)
                        row['evidence'][j] = graph['evidence'][nid]
                        if j == 1:
                            row['scopes'][j] = dict(minute=graph['minute'])
        samples = causal_samples(edges)
        for start in range(0, len(samples['x']), 4096):
            logits = predictor(torch.tensor(samples['x'][start:start+4096]))
            losses = torch.nn.functional.cross_entropy(logits, torch.tensor(samples['y'][start:start+4096]), reduction='none').numpy()
            for i, value in enumerate(losses, start):
                row = rows[samples['actors'][i]]
                if value >= row['raw'][2]:
                    row['raw'][2] = float(value); row['evidence'][2] = [samples['event_ids'][i]]
    by_id = {e['id']: e for e in edges}
    for row in rows.values():
        row['causal_target_event_ids'] = list(row['evidence'][2])
        if row['evidence'][2]:
            target = by_id[row['evidence'][2][0]]
            row['scopes'][2] = dict(minute=target['timestamp_ns']//WINDOW_NS, before_ns=target['timestamp_ns'])
    return rows


def fit_model(train, validation, calibration, directory, epochs=60, seed=913):
    import torch
    started = time.monotonic(); torch.set_num_threads(4); torch.manual_seed(seed)
    splits = (train, validation, calibration)
    if any(not s for s in splits):
        raise ValueError('Empty temporal split')
    if not (max(e['timestamp_ns'] for e in train) < min(e['timestamp_ns'] for e in validation) and
            max(e['timestamp_ns'] for e in validation) < min(e['timestamp_ns'] for e in calibration)):
        raise ValueError('Temporal split overlap')
    graphs = [structural_graphs(s) for s in splits]
    x = np.concatenate([g['x'] for g in graphs[0]])
    mean, scale = x.mean(0), np.maximum(x.std(0), .1)
    encoder, predictor = make_models()
    optimizer = torch.optim.AdamW(encoder.parameters(), lr=.003, weight_decay=.0001)
    inputs = [_tensor_graph(g, mean, scale) for g in graphs[0]]
    history = []; best = float('inf'); best_state = None
    for epoch in range(epochs):
        encoder.train(); total = 0.
        for gx, arcs, relations in inputs:
            mask = torch.rand(len(gx)) < .5
            if not mask.any(): mask[0] = True
            optimizer.zero_grad()
            loss = (encoder(gx, arcs, relations, mask)[mask] - gx[mask]).square().mean()
            loss.backward(); torch.nn.utils.clip_grad_norm_(encoder.parameters(), 5); optimizer.step(); total += float(loss.detach())
        encoder.eval()
        with torch.no_grad():
            val = []
            for g in graphs[1]:
                gx, arcs, rel = _tensor_graph(g, mean, scale)
                for fold in range(4):
                    mask = torch.arange(len(gx)) % 4 == fold
                    if mask.any(): val.extend((encoder(gx, arcs, rel, mask)[mask] - gx[mask]).square().mean(1).tolist())
            value = float(np.mean(val))
        history.append(dict(epoch=epoch+1, loss=total/len(inputs), validation=value))
        if value < best:
            best = value; best_state = {k: v.detach().clone() for k, v in encoder.state_dict().items()}
    encoder.load_state_dict(best_state); encoder.eval()
    samples, vs = causal_samples(train), causal_samples(validation)
    tx, ty = torch.tensor(samples['x']), torch.tensor(samples['y'])
    optimizer = torch.optim.AdamW(predictor.parameters(), lr=.003, weight_decay=.0001)
    counts = torch.bincount(ty, minlength=len(RELATIONS)).float()
    weights = (counts.sum() / counts.clamp_min(1)).sqrt().clamp(max=10); weights /= weights.mean()
    causal_history = []; best = float('inf'); state = None
    for epoch in range(epochs):
        order = torch.randperm(len(tx)); total = 0.
        for batch in order.split(4096):
            optimizer.zero_grad(); loss = torch.nn.functional.cross_entropy(predictor(tx[batch]), ty[batch], weight=weights)
            loss.backward(); optimizer.step(); total += float(loss.detach())
        with torch.no_grad():
            value = float(torch.nn.functional.cross_entropy(predictor(torch.tensor(vs['x'])), torch.tensor(vs['y']), weight=weights))
        causal_history.append(dict(epoch=epoch+1, validation=value))
        if value < best:
            best = value; state = {k: v.detach().clone() for k, v in predictor.state_dict().items()}
    predictor.load_state_dict(state); predictor.eval()
    with torch.no_grad():
        z = torch.cat([encoder.encode(*g) for g in inputs]).numpy()
    em, es = z.mean(0), np.maximum(z.std(0), .1)
    bundle = dict(encoder=encoder.state_dict(), predictor=predictor.state_dict(), mean=torch.tensor(mean), scale=torch.tensor(scale),
                  embedding_mean=torch.tensor(em), embedding_scale=torch.tensor(es),
                  reference_structure=torch.tensor((z-em)/es),
                  reference_attribute=torch.tensor(np.concatenate([g['attribute'] for g in graphs[0]])))
    rows = _view_scores(calibration, graphs[2], encoder, predictor, bundle)
    fusion = calibrate_fusion([r['raw'] for r in rows.values()])
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    torch.save(bundle, directory/'weights.pt')
    manifest = dict(model_id='optc-multiview-v1', seed=seed, epochs=epochs, fusion=fusion,
        architecture='Attribute trigram KNN + masked relational process encoder KNN + causal-history MLP',
        labels_used=False, rules_used=False, calibration_end_ns=max(e['timestamp_ns'] for e in calibration)+1,
        weights_sha256=hashlib.sha256((directory/'weights.pt').read_bytes()).hexdigest(),
        feature_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        feature_sources=feature_sources(),
        splits={name:dict(events=len(s), start_ns=min(e['timestamp_ns'] for e in s), end_ns=max(e['timestamp_ns'] for e in s),
            event_ids_sha256=hashlib.sha256('\n'.join(sorted(e['id'] for e in s)).encode()).hexdigest())
            for name, s in zip(('train','validation','calibration'), splits)},
        training_seconds=time.monotonic()-started, calibration_processes=len(rows),
        limitation='Adaptation, not a paper reproduction; process maximum over variable windows is not an FPR guarantee; pre-campaign normality assumed')
    (directory/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return dict(manifest=manifest, structural_training=history, causal_training=causal_history)


def available_model(directory=None):
    folder = Path(directory or DEFAULT_MODEL)
    return folder/'manifest.json' if (folder/'manifest.json').is_file() and (folder/'weights.pt').is_file() else None


def score_nodes(edges, directory=None):
    import torch
    torch.set_num_threads(4); folder = Path(directory or DEFAULT_MODEL)
    if available_model(folder) is None:
        raise ValueError('Multi-view model is not trained; run train_multiview.py')
    manifest = json.loads((folder/'manifest.json').read_text())
    if manifest.get('feature_sources') != feature_sources():
        raise ValueError('Multi-view feature code differs from trained artifact; retrain model')
    if hashlib.sha256((folder/'weights.pt').read_bytes()).hexdigest() != manifest['weights_sha256']:
        raise ValueError('Multi-view model checksum mismatch')
    if edges and min(e['timestamp_ns'] for e in edges) < manifest['calibration_end_ns']:
        raise ValueError('Candidate window overlaps multi-view training/calibration')
    bundle = torch.load(folder/'weights.pt', map_location='cpu', weights_only=True)
    encoder, predictor = make_models(); encoder.load_state_dict(bundle['encoder']); predictor.load_state_dict(bundle['predictor'])
    encoder.eval(); predictor.eval()
    scores = _view_scores(edges, structural_graphs(edges), encoder, predictor, bundle)
    nodes = {}
    for nid, row in scores.items():
        decision = fusion_decision(row['raw'], manifest['fusion'])
        nodes[nid] = dict(score=float(decision['votes']), predicted=decision['predicted'], **{k:v for k,v in decision.items() if k!='predicted'},
            views={name:dict(score=float(row['raw'][i]), percentile=decision['percentiles'][i],
                            evidence_event_ids=row['evidence'][i],
                            context_scope=row['scopes'][i],
                            target_event_ids=row['causal_target_event_ids'] if name=='causal' else [],
                            evidence_role='Representative observations; full scoring context resolved through context_scope and shared context_index; not proof of maliciousness') for i,name in enumerate(VIEWS)},
            evidence_event_ids=sorted(set(eid for evidence in row['evidence'] for eid in evidence)))
    context_index = defaultdict(list)
    for edge in sorted(edges,key=lambda e:(e['timestamp_ns'],e['id'])):
        context_index[str(edge['timestamp_ns']//WINDOW_NS)].append([edge['id'],edge['timestamp_ns']])
    return dict(model_id=manifest['model_id'], nodes=nodes, threshold=4, fusion=manifest['fusion'],
                context_index=dict(context_index),
                weights_sha256=manifest['weights_sha256'], training=manifest['splits'],
                calibration='Three independent views; seven dimensions, at least four votes; thresholds frozen on earlier data',
                score_meaning='Number of empirical anomaly votes, not attack probability', limitation=manifest['limitation'])
