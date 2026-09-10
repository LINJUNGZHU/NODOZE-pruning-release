"""Enrich visualization labels from original CDM entity declarations only.

Never modifies the graph, scores, truth labels, or experiment database.
"""
import argparse
import json
import subprocess
from pathlib import Path
from tc_pruning.cdm import normalize_cdm_record
from tc_pruning.models import NodeRecord


def enrich(document, paths):
    missing = {n['id'] for n in document['nodes'] if n['label'] == n['id']}
    resolved = {}
    for path in paths:
        if not missing:
            break
        process = subprocess.Popen(
            ['rg', '-n', r'"com.bbn.tc.schema.avro.cdm\d+\.(FileObject|Subject|NetFlowObject|MemoryObject|UnnamedPipeObject)"', str(path)],
            stdout=subprocess.PIPE, text=True,
        )
        for line in process.stdout:
            lineno, content = line.split(':', 1)
            raw = json.loads(content)
            body = next(iter(raw.get('datum', {}).values()), {})
            if body.get('uuid') not in missing:
                continue
            for node in normalize_cdm_record(raw):
                if isinstance(node, NodeRecord) and node.uuid in missing and node.label != node.uuid:
                    resolved[node.uuid] = {'label': node.semantic_key, 'type': node.node_type,
                                          'evidence': {'file': path.name, 'line': int(lineno)}}
                    missing.remove(node.uuid)
        if process.wait() not in (0, 1):
            raise RuntimeError(f'Could not read entity records in {path}')
    for node in document['nodes']:
        if node['id'] in resolved:
            node.update(resolved[node['id']])
    lookup = {n['id']: n for n in document['nodes']}
    for edge in document['edges']:
        for side in ('source', 'target'):
            node = lookup[edge[side]]
            edge[side+'_label'] = node['label']
            edge[side+'_type'] = node['type']
            if 'evidence' in node:
                edge[side+'_label_evidence'] = node['evidence']
    document['entity_resolution'] = {'resolved': len(resolved), 'unresolved': len(missing),
                                     'policy': 'exact UUID match to raw CDM entity records'}
    return document


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    args = parser.parse_args()
    data = enrich(json.loads(args.cache.read_text()), sorted(args.source_dir.glob('*.json')))
    tmp = args.cache.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(args.cache)
    print(data['entity_resolution'])
