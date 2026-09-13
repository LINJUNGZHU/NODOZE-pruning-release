"""Stored-event adapter; identity and CDM orientation stay with the project."""
import numpy as np

from .diffusion import DiffusionResult, _causal_endpoints
from .rcvp import propagate


def diffuse_graph(graph, rarity, poi_edges, config=None):
    if not graph.edges:
        return DiffusionResult({}, {}, 0, True, [], {}, 'relation_time_contrastive')
    edges = sorted(graph.edges, key=lambda e: (e.timestamp_ns, e.event_id, e.edge_id))
    nodes = sorted({n for e in edges for n in (e.src, e.dst)})
    index = {node: i for i, node in enumerate(nodes)}
    endpoints = [_causal_endpoints(e) for e in edges]
    src = np.array([index[a] for a, _ in endpoints])
    dst = np.array([index[b] for _, b in endpoints])
    poi_ids = {e.edge_id for e in poi_edges}
    poi = np.array([e.edge_id in poi_ids for e in edges])
    process = np.array([node in graph.nodes and graph.nodes[node].node_type == 'process' for node in nodes])
    scores, diag = propagate(src, dst, np.array([e.timestamp_ns for e in edges], dtype=np.int64),
        np.array([e.relation for e in edges]), np.array([rarity.get(e.edge_id, 0.) for e in edges]),
        poi, process, config)
    evidence = {e.edge_id: {key: values[i].item() for key, values in diag['edge_fields'].items()} for i, e in enumerate(edges)}
    for e in edges:
        evidence[e.edge_id]['redundancy_key'] = f'{e.src}|{e.dst}|{e.relation}'
    metadata = {k: v for k, v in diag.items() if k not in ('edge_fields', 'backward_parent', 'forward_parent', 'roots')}
    seed_events = [e.event_id for e in edges if e.edge_id in poi_ids
                   for _ in range(len(set(_causal_endpoints(e))))]
    metadata['roots'] = [dict(r, node_uuid=nodes[r['node']],
        poi_event_id=seed_events[r['poi_seed_index']],
        witness_event_ids=[edges[j].event_id for j in r['witness']]) for r in diag['roots']]
    metadata['poi_event_ids'] = [e.event_id for e in edges if e.edge_id in poi_ids]
    node_scores = np.zeros(len(nodes))
    np.maximum.at(node_scores, src, scores)
    np.maximum.at(node_scores, dst, scores)
    predecessors = {nodes[int(src[i])]: edges[int(j)].edge_id for i, j in enumerate(diag['backward_parent']) if j >= 0}
    return DiffusionResult(dict(zip(nodes, node_scores.tolist())), predecessors, 1, True,
        [{'iteration': 1, 'l1_delta': 0., 'nonzero_edges': int(np.count_nonzero(scores))}],
        dict(zip((e.edge_id for e in edges), scores.tolist())), 'relation_time_contrastive', evidence, metadata)
