#!/usr/bin/env python3
"""Audit a DARPA node-label ZIP against explicit read-only DB and saved-ledger inputs.

Usage: python evaluate_uploaded_groundtruth.py --archive labels.zip --config inputs.json
       --output-dir results --local-label-root /path/to/darpa

Config: {"cases": {"E3-CADETS/node_example.csv": {"database": "/x.db",
 "annotation": "/annotations.json", "ledger": "/edge-scores.jsonl.gz",
 "comparison": "/comparison.json", "decisions": "/diverse-decisions.jsonl.gz"}}}.
Only database is required for a mapped case. Annotations supply an optional protocol
window, never node truth. Comparison and decisions add its recorded primary method.
Node UUIDs are case-insensitive; Orthrus index_id is never used as a local DB key.
This measures retained graph coverage of positive entity labels, not classification.
"""
from __future__ import annotations

import argparse
import ast
import collections
import csv
import gzip
import hashlib
import io
import json
import sqlite3
import sys
import zipfile
from pathlib import Path


def canonical(value):
    return str(value).strip().upper()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def provenance(path, full_hash=True):
    path = Path(path).resolve()
    stat = path.stat()
    return {'path': str(path), 'bytes': stat.st_size, 'mtime_ns': stat.st_mtime_ns,
            'sha256': sha256(path) if full_hash else None}


def json_lines(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def read_archive(path, local_label_root):
    files, readmes = [], []
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if name.lower().endswith('readme.md'):
                readmes.append({'member': name, 'text': archive.read(name).decode('utf-8-sig')})
            if not name.endswith('.csv'):
                continue
            data = archive.read(name)
            rows = list(csv.reader(io.StringIO(data.decode('utf-8-sig'))))
            labels, attribute_types = set(), collections.Counter()
            uppercase_rows = 0
            for number, row in enumerate(rows, 1):
                if len(row) != 3 or not row[0].strip():
                    raise ValueError(f'{name}:{number}: expected UUID, attributes, index_id')
                attributes = ast.literal_eval(row[1])
                if not isinstance(attributes, dict):
                    raise ValueError(f'{name}:{number}: attributes must be a dictionary')
                int(row[2])  # Validate, but never join on the Orthrus-local integer.
                labels.add(canonical(row[0]))
                uppercase_rows += row[0] == canonical(row[0])
                attribute_types.update(attributes.keys())
            relative = str(Path(name).relative_to(Path(name).parents[1]))
            item = {'member': name, 'case_key': relative,
                    'dataset': Path(name).parent.name, 'filename': Path(name).name,
                    'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                    'row_count': len(rows), 'unique_node_count': len(labels),
                    'duplicate_rows_after_case_normalization': len(rows) - len(labels),
                    'uppercase_uuid_rows': uppercase_rows,
                    'attribute_key_counts': dict(attribute_types),
                    'node_uuids': sorted(labels)}
            if local_label_root:
                local = Path(local_label_root) / relative
                item['existing_local_copy'] = {'path': str(local), 'exists': local.is_file(),
                    'byte_identical': local.read_bytes() == data if local.is_file() else None}
            files.append(item)
    return {'source': provenance(path), 'readmes': readmes, 'files': files,
            'datasets': sorted({x['dataset'] for x in files}),
            'total_csv_files': len(files), 'total_label_rows': sum(x['row_count'] for x in files),
            'unique_dataset_node_pairs': len({(x['dataset'], n) for x in files for n in x['node_uuids']})}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def evaluate_case(item, config):
    if not config or not config.get('database'):
        return {'status': 'no_matching_local_database', 'database': None, 'retention': None}
    path = Path(config['database']).resolve()
    labels = set(item['node_uuids'])
    annotations = json.loads(Path(config['annotation']).read_text()) if config.get('annotation') else {}
    metadata = annotations.get('metadata', {})
    start, end = metadata.get('attack_window_start_ns'), metadata.get('attack_window_end_ns')
    if (start is None) != (end is None):
        raise ValueError('annotation window must specify both start and end')
    source_hash = metadata.get('groundtruth_source_sha256')
    if source_hash and source_hash != item['sha256']:
        raise ValueError(f'{path}: annotation label source hash differs from uploaded CSV')
    result = {'status': 'database_available_no_completed_prediction', 'retention': None}
    before = provenance(path, False)
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
        conn.execute('PRAGMA query_only=ON')
        # One scan covers arbitrary UUID casing without assuming uppercase DB storage.
        matches = {uuid: kind for uuid, kind in conn.execute('SELECT uuid,node_type FROM nodes')
                   if canonical(uuid) in labels}
        matched = {canonical(uuid) for uuid in matches}
        static, protocol = set(), set()
        if matches:
            placeholders = ','.join('?' for _ in matches)
            for source in matches:
                query = f'SELECT event_id,timestamp_ns FROM edges WHERE src=? AND dst IN ({placeholders})'
                for event, timestamp in conn.execute(query, [source, *matches]):
                    static.add(canonical(event))
                    if start is None or start <= timestamp <= end:
                        protocol.add(canonical(event))
        result['database'] = {**before, 'open_mode': 'ro',
            'sha256_policy': 'large DB not hashed; byte size/mtime and deterministic matched-label/internal-event digest recorded',
            'matched_node_count': len(matched), 'csv_node_count': len(labels),
            'node_coverage': ratio(len(matched), len(labels)),
            'matched_node_uuids': sorted(matched), 'missing_node_uuids': sorted(labels - matched),
            'matched_node_types': dict(collections.Counter(matches.values())),
            'casefolded_db_collisions': len(matches) - len(matched),
            'matched_content_sha256': hashlib.sha256(json.dumps({'nodes':sorted(matches.items()),
                'static_internal_events': sorted(static), 'protocol_internal_events':sorted(protocol)},
                separators=(',', ':')).encode()).hexdigest()}
    if provenance(path, False) != before:
        raise RuntimeError(f'Database changed during read: {path}')
    prior = {canonical(x) for x in annotations.get('attack_event_ids', [])}
    result['derived_events'] = {'static_internal_count': len(static), 'protocol_internal_count': len(protocol),
        'rule': 'both endpoints are CSV-labeled entities; optional annotation window inclusive',
        'manually_labeled_events': False, 'protocol_window_ns': [start,end] if start is not None else None,
        'protocol_scope': 'annotation_window' if start is not None else 'all_events_in_selected_local_database',
        'annotation_event_count': len(prior) if annotations else None,
        'agrees_with_saved_annotation_event_set': prior == protocol if annotations else None,
        'static_internal_event_ids_sha256': hashlib.sha256('\n'.join(sorted(static)).encode()).hexdigest(),
        'protocol_internal_event_ids_sha256': hashlib.sha256('\n'.join(sorted(protocol)).encode()).hexdigest()}
    result['annotation'] = provenance(config['annotation']) if config.get('annotation') else None
    ledger = config.get('ledger')
    if not ledger:
        return result
    result['status'] = 'evaluated_saved_retention'
    result['ledger'] = provenance(ledger)
    methods, selected = {'saved_pruning@0.2': None}, {}
    if config.get('comparison'):
        comparison = json.loads(Path(config['comparison']).read_text())
        primary = comparison['primary_method']
        methods[primary] = set()
        result['comparison'] = {**provenance(config['comparison']),
            'primary_method': primary, 'algorithm': comparison.get('algorithm'),
            'parameter_policy': comparison.get('config', {}).get('parameter_policy'),
            'evaluation_scope': comparison.get('evaluation_scope'),
            'candidate_source_matches': Path(comparison['candidate_source']).resolve() == Path(ledger).resolve()}
        if not result['comparison']['candidate_source_matches']:
            raise ValueError('comparison candidate source does not match supplied ledger')
        for row in json_lines(config['decisions']):
            if row['decisions'].get(primary) is True:
                methods[primary].add(canonical(row['event_id']))
        result['decisions'] = provenance(config['decisions'])
    for method in methods:
        selected[method] = {'nodes': set(), 'events': 0, 'protocol': set(), 'static': set(), 'seen_selected': set()}
    candidate_nodes, candidate_protocol, candidate_static = set(), set(), set()
    candidate_count = 0
    for row in json_lines(ledger):
        event = canonical(row['event_id'])
        endpoints = {canonical(row['src']), canonical(row['dst'])}
        candidate_count += 1
        candidate_nodes.update(endpoints & labels)
        if event in protocol:
            candidate_protocol.add(event)
        if event in static:
            candidate_static.add(event)
        decisions = row.get('decisions', [])
        keep = any(str(d.get('budget_key')) == '0.2' and d.get('kept') is True for d in decisions)
        for method, identifiers in methods.items():
            if (keep if identifiers is None else event in identifiers):
                state = selected[method]
                state['events'] += 1
                state['nodes'].update(endpoints & labels)
                if identifiers is not None:
                    state['seen_selected'].add(event)
                if event in protocol:
                    state['protocol'].add(event)
                if event in static:
                    state['static'].add(event)
    result['candidate'] = {'events':candidate_count, 'labeled_nodes':len(candidate_nodes),
        'protocol_internal_events':len(candidate_protocol), 'static_internal_events':len(candidate_static),
        'node_recall_csv':ratio(len(candidate_nodes),len(labels)),
        'event_recall_protocol':ratio(len(candidate_protocol),len(protocol))}
    result['retention'] = {}
    for method, state in selected.items():
        if methods[method] is not None and methods[method] != state['seen_selected']:
            raise ValueError('selected decision IDs absent from candidate ledger')
        result['retention'][method] = {'retained_events':state['events'],
            'keep_ratio':ratio(state['events'],candidate_count),
            'retained_labeled_nodes':len(state['nodes']), 'retained_labeled_node_uuids':sorted(state['nodes']),
            'missed_csv_node_uuids':sorted(labels-state['nodes']),
            'node_recall_csv':ratio(len(state['nodes']),len(labels)),
            'node_recall_db_matched':ratio(len(state['nodes'] & matched),len(matched)),
            'retained_protocol_internal_events':len(state['protocol']),
            'event_recall_protocol':ratio(len(state['protocol']),len(protocol)),
            'event_recall_given_candidate':ratio(len(state['protocol']),len(candidate_protocol)),
            'retained_static_internal_events':len(state['static']),
            'event_recall_static':ratio(len(state['static']),len(static)),
            'classification_accuracy':None, 'precision':None, 'false_positive_rate':None,
            'reason_classification_unavailable':'retained graph membership is not an attack decision; unlisted entities have no verified negative labels'}
    return result


def write_report(result, destination):
    rows = ['# Uploaded DARPA archive audit', '',
        f"Archive SHA-256: `{result['archive']['source']['sha256']}`.", '',
        'The ZIP provides static positive entity UUID labels and attributes, with an Orthrus-local index_id. '
        'It provides no event labels, timestamps, malicious paths, or verified negative labels. '
        'All UUID comparisons ignore case; index_id is never used for database matching.', '',
        '| Dataset / CSV | Rows | DB matched | Method | Retained labeled nodes | Derived events retained |',
        '|---|---:|---:|---|---:|---:|']
    for item in result['archive']['files']:
        evaluation = item['evaluation']
        db = evaluation.get('database')
        node_db = f"{db['matched_node_count']}/{item['unique_node_count']}" if db else 'unavailable'
        for method, values in (evaluation.get('retention') or {'unavailable':None}).items():
            n = f"{values['retained_labeled_nodes']}/{item['unique_node_count']}" if values else 'N/A'
            e = f"{values['retained_protocol_internal_events']}/{evaluation['derived_events']['protocol_internal_count']}" if values else 'N/A'
            rows.append(f"| {item['case_key']} | {item['row_count']} | {node_db} | {method} | {n} | {e} |")
    rows += ['', 'These are retrospective graph-retention measurements, not classifier accuracy. '
        'Static node membership across all entity types does not establish a malicious causal path. '
        'Derived events merely connect two labeled entities; CADETS uses saved annotation windows, '
        'whereas THEIA uses all events in the explicitly selected database. These denominators are not interchangeable.', '',
        'The RASP-D primary setting was selected post hoc using development-case recall. '
        'Existing POIs/candidates may use analyst or ground-truth-derived information. '
        'The uploaded labels are byte-identical to the existing labels wherever reported, so this is not an independent held-out test.', '',
        'Absent datasets and incomplete runs have N/A retention, never fabricated zero or perfect results. '
        'No OPTC or TRACE CSV is present. CLEARSCOPE and E5 lack matching local databases in this input configuration. '
        'SQLite connections are read-only. Large database identity uses size/mtime and matched-content digests; '
        'the archive, every CSV, annotation, comparison, and saved ledger has a full SHA-256.', '']
    destination.write_text('\n'.join(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--local-label-root', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    result = {'schema_version':1, 'evaluator':provenance(__file__), 'config':provenance(args.config),
        'archive':read_archive(args.archive,args.local_label_root),
        'metric_semantics':'positive-node coverage and derived-event retention; no classification accuracy'}
    for item in result['archive']['files']:
        print('Evaluating ' + item['case_key'], file=sys.stderr, flush=True)
        item['evaluation'] = evaluate_case(item,config.get('cases',{}).get(item['case_key'],{}))
    result['coverage'] = {'csv_files':len(result['archive']['files']),
        'with_database':sum(x['evaluation']['database'] is not None for x in result['archive']['files']),
        'with_completed_retention':sum(x['evaluation']['retention'] is not None for x in result['archive']['files'])}
    args.output_dir.mkdir(parents=True,exist_ok=True)
    (args.output_dir/'evaluation.json').write_text(json.dumps(result,indent=2)+'\n')
    write_report(result,args.output_dir/'report.md')
    print(json.dumps(result['coverage']))


if __name__ == '__main__':
    main()
