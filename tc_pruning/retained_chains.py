"""Exact retained-event exports, independent of reference labels and attacks.

The disjoint greedy path cover describes observed events, not complete attacks.
All event indices in paths and bundles refer to the stable serialized events
array, sorted by exact integer timestamp and original event ID.
"""
from __future__ import annotations

from collections import defaultdict
import csv
import hashlib
import heapq
import io
import json
from pathlib import Path
import re
from typing import Mapping, Sequence
import xml.etree.ElementTree as ET

import numpy as np

SCHEMA = 'retained-chain-export-v1'
GRAPHML_NS = 'http://graphml.graphdrawing.org/xmlns'


def _timestamp(value):
    if isinstance(value, (bool, np.bool_)) or not (
        isinstance(value, (int, np.integer)) or isinstance(value, str) and re.fullmatch(r'-?\d+', value)
    ):
        raise ValueError('timestamp_ns must be an exact integer or decimal integer string')
    return int(value)


def _identity(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{field} must be a nonempty string')
    return value


def _causal(row):
    a, b = row['src'], row['dst']
    return (b, a) if row['relation'].upper() == 'EVENT_EXECUTE' else (a, b)


def _strict_path(indices, events):
    return all(
        events[a].get('host', '') == events[b].get('host', '')
        and _causal(events[a])[1] == _causal(events[b])[0]
        and _timestamp(events[a]['timestamp_ns']) < _timestamp(events[b]['timestamp_ns'])
        for a, b in zip(indices, indices[1:])
    )


def _path_cover(events):
    paths, available = [], defaultdict(list)
    begin = 0
    while begin < len(events):
        end = begin + 1
        timestamp = int(events[begin]['timestamp_ns'])
        while end < len(events) and int(events[end]['timestamp_ns']) == timestamp:
            end += 1
        pending = []
        for index in range(begin, end):
            event = events[index]
            key = (event['host'], event['causal_src'])
            if available[key]:
                _, _, path_index = heapq.heappop(available[key])
                paths[path_index].append(index)
            else:
                path_index = len(paths)
                paths.append([index])
            pending.append((path_index, event))
        # A path consumed in this batch is unavailable to other same-time
        # events. Publish its new endpoint only after the entire batch.
        for path_index, event in pending:
            key = (event['host'], event['causal_dst'])
            first_id = events[paths[path_index][0]]['event_id']
            heapq.heappush(available[key], (-timestamp, first_id, path_index))
        begin = end
    return [
        {'id': f'path-{index + 1}', 'event_indices': path,
         'event_ids': [events[i]['event_id'] for i in path],
         'start_ns': events[path[0]]['timestamp_ns'], 'end_ns': events[path[-1]]['timestamp_ns'],
         'singleton': len(path) == 1}
        for index, path in enumerate(paths)
    ]


def build_retained_artifact(
    rows: Sequence[Mapping], selected, scores=None, *, case_id, method,
    budget_edges, bundles=(),
):
    """Export exactly a boolean selection, including every isolated event.

    Optional bundle indices refer to the input rows and are remapped to export
    indices. Only fully retained bundles are included. Their original candidate
    completeness declaration remains separate from attack completeness.
    """
    rows = list(rows)
    n = len(rows)
    mask = np.asarray(selected)
    if n == 0 and mask.shape == (0,):
        mask = mask.astype(bool)
    if mask.shape != (n,) or mask.dtype != np.bool_:
        raise ValueError('selection mask must contain exactly one boolean per candidate event')
    if (isinstance(budget_edges, (bool, np.bool_)) or not isinstance(budget_edges, (int, np.integer))
            or not int(mask.sum()) <= budget_edges <= n):
        raise ValueError('budget must fit the exact selection and not exceed candidate count')
    _identity(case_id, 'case_id'); _identity(method, 'method')
    score = None if scores is None else np.asarray(scores)
    if score is not None and (score.shape != (n,) or score.dtype.kind not in 'fiu'
                              or not np.isfinite(score).all() or np.any(score < 0)):
        raise ValueError('scores must be aligned finite nonnegative numeric values')
    ids, timestamps = [], []
    for row in rows:
        ids.append(_identity(row['event_id'], 'event_id'))
        _identity(row['src'], 'src'); _identity(row['dst'], 'dst'); _identity(row['relation'], 'relation')
        timestamps.append(_timestamp(row['timestamp_ns']))
        if not isinstance(row.get('host', ''), str):
            raise ValueError('host must be a string')
    if len(set(ids)) != n:
        raise ValueError('duplicate candidate event IDs')
    order = sorted(np.flatnonzero(mask).tolist(), key=lambda i: (timestamps[i], ids[i]))
    remap = {original: export for export, original in enumerate(order)}
    events = []
    for export, original in enumerate(order):
        row = rows[original]
        a, b = _causal(row)
        event = {
            'event_index': export, 'event_id': ids[original],
            'src': row['src'], 'dst': row['dst'], 'relation': row['relation'],
            'host': row.get('host', ''), 'timestamp_ns': str(timestamps[original]),
            'src_type': str(row.get('src_type', 'unknown')), 'dst_type': str(row.get('dst_type', 'unknown')),
            'src_semantic': str(row.get('src_semantic', row['src'])),
            'dst_semantic': str(row.get('dst_semantic', row['dst'])),
            'is_declared_poi': bool(row.get('is_declared_poi', False)),
            'score': None if score is None else float(score[original]),
            'causal_src': a, 'causal_dst': b,
            'causal_direction': 'dst_to_src' if row['relation'].upper() == 'EVENT_EXECUTE' else 'src_to_dst',
        }
        if row.get('edge_id') is not None:
            event['edge_id'] = int(row['edge_id'])
        if row.get('data_size') is not None:
            event['data_size'] = int(row['data_size'])
        events.append(event)
    entities = defaultdict(lambda: {'types': set(), 'labels': set()})
    for event in events:
        for side in ('src', 'dst'):
            details = entities[(event['host'], event[side])]
            details['types'].add(event[side + '_type'])
            details['labels'].add(event[side + '_semantic'])
    node_indices = {key: index for index, key in enumerate(sorted(entities))}
    nodes = []
    for (host, uuid), index in node_indices.items():
        details = entities[(host, uuid)]
        nodes.append({'node_index': index, 'uuid': uuid, 'host': host,
                      'node_type': next(iter(details['types'])) if len(details['types']) == 1 else 'mixed',
                      'label': min(details['labels'])})
    for event in events:
        for side in ('src', 'dst', 'causal_src', 'causal_dst'):
            event[side + '_node_index'] = node_indices[(event['host'], event[side])]
    observed = []
    seen_bundles = set()
    for bundle in bundles:
        bundle_id = _identity(bundle.get('id'), 'bundle id')
        if bundle_id in seen_bundles:
            raise ValueError('duplicate bundle id')
        seen_bundles.add(bundle_id)
        members = bundle.get('event_indices')
        if (not isinstance(members, (list, tuple)) or not members
                or any(type(i) is not int or not 0 <= i < n for i in members)
                or len(members) != len(set(members))):
            raise ValueError('invalid bundle event indices')
        paths = bundle.get('paths')
        if not isinstance(paths, (list, tuple)) or not paths:
            raise ValueError('bundle must supply separately directed witness paths')
        for path in paths:
            if (not isinstance(path, (list, tuple)) or not path
                    or any(type(i) is not int or i not in members for i in path)
                    or not _strict_path(path, rows)):
                raise ValueError('invalid bundle temporal path')
        if {i for path in paths for i in path} != set(members):
            raise ValueError('bundle paths must cover all declared members')
        if not all(mask[i] for i in members):
            continue
        indices = sorted(remap[i] for i in members)
        observed.append({
            'id': bundle_id, 'event_indices': indices, 'event_ids': [events[i]['event_id'] for i in indices],
            'paths': [[remap[i] for i in path] for path in paths],
            'complete_in_candidate': bundle.get('complete_in_candidate') is True,
            'boundary_status': str(bundle.get('boundary_status', 'candidate_boundary_unverified')),
            'scope': 'observed_witness_only_not_complete_attack',
        })
    observed.sort(key=lambda bundle: bundle['id'])
    paths = _path_cover(events)
    return {
        'schema_version': SCHEMA, 'case_id': case_id, 'method': method,
        'scope': 'retained_graph_only_not_complete_attack',
        'reference_labels_used': False, 'complete_attack_guarantee': False,
        'candidate_edges': n, 'retained_edges': len(events), 'budget_edges': int(budget_edges),
        'actual_compression': 1 - len(events) / n if n else None,
        'path_policy': 'deterministic edge-disjoint strict-time cover; singletons included; not exhaustive path enumeration',
        'counts': {'candidate_events': n, 'retained_events': len(events), 'nodes': len(nodes),
                   'paths': len(paths), 'singleton_paths': sum(p['singleton'] for p in paths),
                   'observed_bundles': len(observed)},
        'events': events, 'nodes': nodes, 'paths': paths, 'observed_bundles': observed,
    }


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def _csv_bytes(events):
    fields = ['event_index', 'event_id', 'timestamp_ns', 'host', 'relation', 'src', 'dst',
              'src_type', 'dst_type', 'src_semantic', 'dst_semantic', 'is_declared_poi', 'score',
              'causal_src', 'causal_dst', 'causal_direction', 'src_node_index', 'dst_node_index',
              'causal_src_node_index', 'causal_dst_node_index', 'edge_id', 'data_size']
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader(); writer.writerows(events)
    return stream.getvalue().encode('utf-8')


def _graphml_bytes(artifact):
    ET.register_namespace('', GRAPHML_NS)
    q = lambda name: '{' + GRAPHML_NS + '}' + name
    root = ET.Element(q('graphml'))
    node_fields = ['uuid', 'host', 'node_type', 'label']
    edge_fields = ['event_id', 'timestamp_ns', 'relation', 'host', 'src', 'dst', 'src_semantic',
                   'dst_semantic', 'causal_src', 'causal_dst', 'causal_direction', 'is_declared_poi', 'score']
    for scope, fields in [('node', node_fields), ('edge', edge_fields)]:
        for field in fields:
            ET.SubElement(root, q('key'), {'id': scope + '_' + field, 'for': scope,
                                          'attr.name': field, 'attr.type': 'string'})
    graph = ET.SubElement(root, q('graph'), {'id': 'retained-events', 'edgedefault': 'directed'})
    for node in artifact['nodes']:
        element = ET.SubElement(graph, q('node'), {'id': 'n' + str(node['node_index'])})
        for field in node_fields:
            ET.SubElement(element, q('data'), {'key': 'node_' + field}).text = str(node[field])
    for event in artifact['events']:
        element = ET.SubElement(graph, q('edge'), {
            'id': 'e' + str(event['event_index']), 'source': 'n' + str(event['causal_src_node_index']),
            'target': 'n' + str(event['causal_dst_node_index'])})
        for field in edge_fields:
            value = event.get(field)
            ET.SubElement(element, q('data'), {'key': 'edge_' + field}).text = '' if value is None else str(value)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def write_retained_export(directory, artifact):
    """Write three formats and their hashes to a new local directory only."""
    directory = Path(directory)
    if directory.exists() or directory.is_symlink():
        raise FileExistsError(f'retained export destination already exists: {directory}')
    if artifact.get('schema_version') != SCHEMA:
        raise ValueError('unsupported retained export schema')
    events = artifact['events']
    covered = [i for path in artifact['paths'] for i in path['event_indices']]
    if (sorted(covered) != list(range(len(events)))
            or artifact['retained_edges'] != len(events)
            or len(events) > artifact['budget_edges']
            or any(not _strict_path(path['event_indices'], events) for path in artifact['paths'])):
        raise ValueError('invalid retained event union, temporal cover, or budget')
    payloads = {'retained-graph.json': _json_bytes(artifact),
                'retained-events.csv': _csv_bytes(events),
                'retained-graph.graphml': _graphml_bytes(artifact)}
    manifest = {'schema_version': SCHEMA, 'case_id': artifact['case_id'], 'method': artifact['method'],
                'scope': artifact['scope'], 'counts': artifact['counts'],
                'budget_edges': artifact['budget_edges'], 'reference_labels_used': False,
                'artifacts': {name: hashlib.sha256(content).hexdigest() for name, content in payloads.items()}}
    if 'frozen_source' in artifact:
        manifest['frozen_source'] = artifact['frozen_source']
    directory.mkdir(parents=True, exist_ok=False)
    for name, content in payloads.items():
        (directory / name).write_bytes(content)
    (directory / 'manifest.json').write_bytes(_json_bytes(manifest))
    return manifest


__all__ = ['build_retained_artifact', 'write_retained_export']
