"""Non-destructive CADETS E3 SQLite -> PostgreSQL identity transport.

No labels or investigation annotations are inputs. All raw records are retained;
PIDSMaker views expose its model vocabulary with explicit audited aliases.
"""
import argparse
import hashlib
import io
import os
import importlib.util
import json
import re
import sqlite3
import subprocess
from pathlib import Path

SCHEMA_VERSION = 1
FROZEN_SHA256 = '719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf'
NODE_TYPES = {'process': 'subject', 'socket': 'netflow', 'file': 'file',
              'pipe': 'file', 'srcsink': 'file', 'principal': None}
RELATIONS = {name: name for name in ('EVENT_CONNECT', 'EVENT_EXECUTE', 'EVENT_OPEN',
    'EVENT_READ', 'EVENT_RECVFROM', 'EVENT_RECVMSG', 'EVENT_SENDMSG', 'EVENT_SENDTO',
    'EVENT_WRITE', 'EVENT_CLONE')}
RELATIONS['EVENT_FORK'] = 'EVENT_CLONE'
NODE_COLUMNS = ('index_id', 'node_uuid', 'raw_type', 'model_type', 'label', 'host',
                'semantic_key', 'properties_json')
EVENT_COLUMNS = ('source_row_id', 'event_uuid', 'original_event_id', 'src_uuid',
                 'dst_uuid', 'src_index_id', 'dst_index_id', 'raw_relation',
                 'model_operation', 'timestamp_rec', 'identity_collision', 'host', 'data_size')


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_source(path, expected):
    actual = file_sha256(path)
    if actual != expected:
        raise ValueError('Source hash mismatch')
    return actual


def validate_target(name, source_sha):
    if not re.fullmatch(r'cadets_e3_identity_v1_' + source_sha[:12], name):
        raise ValueError('Unsafe or incompatible target database')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def seal_manifest(manifest):
    result = {k: v for k, v in manifest.items() if k != 'manifest_sha256'}
    result['manifest_sha256'] = hashlib.sha256(canonical(result).encode()).hexdigest()
    return result


def validate_manifest(manifest):
    if manifest.get('status') != 'COMPLETED':
        raise ValueError('Identity database is NOT_COMPLETED')
    if seal_manifest(manifest)['manifest_sha256'] != manifest.get('manifest_sha256'):
        raise ValueError('Identity manifest digest mismatch')
    if not manifest.get('reconciliation', {}).get('exact'):
        raise ValueError('Identity database lacks full reconciliation')
    return manifest


def _connection(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)


def _identity(value, kind):
    if not isinstance(value, str) or not value.strip() or value.startswith('legacy-row-'):
        raise ValueError('Missing or synthetic ' + kind + ' identity')
    return value


def iter_nodes(path, after=0):
    with _connection(path) as db:
        for index, uuid, typ, label, host, semantic, props in db.execute(
                'SELECT rowid,uuid,node_type,label,host,semantic_key,properties_json '
                'FROM nodes WHERE rowid>? ORDER BY rowid', (after,)):
            _identity(uuid, 'node')
            if typ not in NODE_TYPES:
                raise ValueError('Unaudited node type: ' + typ)
            json.loads(props)
            yield (index, uuid, typ, NODE_TYPES[typ], label, host, semantic, props)


def iter_events(path, after=0):
    with _connection(path) as db:
        query = '''SELECT e.id,e.event_id,e.original_event_id,e.src,e.dst,
                   s.rowid,d.rowid,e.relation,e.timestamp_ns,e.host,e.data_size
                   FROM edges e LEFT JOIN nodes s ON s.uuid=e.src
                   LEFT JOIN nodes d ON d.uuid=e.dst WHERE e.id>? ORDER BY e.id'''
        for idx, event, original, src, dst, si, di, relation, ts, host, size in db.execute(query, (after,)):
            for value, kind in ((event, 'event'), (original, 'original event'), (src, 'source'), (dst, 'destination')):
                _identity(value, kind)
            if si is None or di is None:
                raise ValueError('Missing endpoint node identity for ' + event)
            yield (idx, event, original, src, dst, si, di, relation,
                   RELATIONS.get(relation), ts, event != original, host, size)


DDL = '''
CREATE TABLE IF NOT EXISTS identity_state(key text PRIMARY KEY, value jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS identity_nodes(
 index_id bigint PRIMARY KEY, node_uuid text UNIQUE NOT NULL, raw_type text NOT NULL,
 model_type text, label text NOT NULL, host text NOT NULL, semantic_key text NOT NULL,
 properties_json text NOT NULL);
CREATE TABLE IF NOT EXISTS identity_events(
 source_row_id bigint PRIMARY KEY, event_uuid text UNIQUE NOT NULL,
 original_event_id text NOT NULL, src_uuid text NOT NULL, dst_uuid text NOT NULL,
 src_index_id bigint NOT NULL, dst_index_id bigint NOT NULL, raw_relation text NOT NULL,
 model_operation text, timestamp_rec bigint NOT NULL, identity_collision boolean NOT NULL,
 host text NOT NULL, data_size bigint);
'''

VIEWS = '''
CREATE INDEX IF NOT EXISTS identity_events_time_idx ON identity_events(timestamp_rec,event_uuid);
CREATE OR REPLACE VIEW file_node_table AS SELECT node_uuid,node_uuid AS hash_id,
 COALESCE(NULLIF(properties_json::jsonb->>'path',''),label) AS path,index_id
 FROM identity_nodes WHERE model_type='file';
CREATE OR REPLACE VIEW subject_node_table AS SELECT node_uuid,node_uuid AS hash_id,
 COALESCE(NULLIF(properties_json::jsonb->>'exec',''),label) AS exec,
 COALESCE(NULLIF(properties_json::jsonb->>'exec',''),label) AS path,
 COALESCE(properties_json::jsonb->>'cmdLine','') AS cmd,index_id
 FROM identity_nodes WHERE model_type='subject';
CREATE OR REPLACE VIEW netflow_node_table AS SELECT node_uuid,node_uuid AS hash_id,
 COALESCE(properties_json::jsonb->>'localAddress','') AS src_addr,
 COALESCE(properties_json::jsonb->>'localPort','') AS src_port,
 COALESCE(properties_json::jsonb->>'remoteAddress',label) AS dst_addr,
 COALESCE(properties_json::jsonb->>'remotePort','') AS dst_port,index_id
 FROM identity_nodes WHERE model_type='netflow';
CREATE OR REPLACE VIEW event_table AS SELECT e.src_uuid AS src_node,
 e.src_index_id::text AS src_index_id,e.model_operation AS operation,e.dst_uuid AS dst_node,
 e.dst_index_id::text AS dst_index_id,e.event_uuid,e.timestamp_rec,e.source_row_id AS _id,
 e.original_event_id,e.src_uuid,e.dst_uuid,e.raw_relation,e.identity_collision,
 CASE WHEN e.original_event_id LIKE 'LINEAGE:%' THEN 'DERIVED_NO_RAW_EVENT'
 WHEN e.original_event_id ~ '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$'
 THEN 'RAW_TC_EVENT' ELSE 'OTHER_STORED_ID' END AS identity_origin
 FROM identity_events e JOIN identity_nodes s ON s.index_id=e.src_index_id
 JOIN identity_nodes d ON d.index_id=e.dst_index_id
 WHERE e.model_operation IS NOT NULL AND s.model_type IS NOT NULL AND d.model_type IS NOT NULL;
'''


def _write_manifest(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    temp = Path(str(path) + '.tmp')
    with temp.open('w') as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)
    directory = os.open(str(Path(path).parent), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _checkpoint(conn, manifest, path):
    # DB is the authoritative transaction log. A crash between commit and file
    # publication is repaired from this exact checkpoint on the next invocation.
    with conn.cursor() as cur:
        cur.execute("UPDATE identity_state SET value=%s WHERE key='manifest'", (json.dumps(manifest),))
    conn.commit()
    _write_manifest(path, manifest)


def _copy_batch(cur, table, columns, rows):
    stream = io.StringIO()
    # Force quote all strings so SQL NULL is distinguishable from empty text.
    for row in rows:
        pieces = []
        for value in row:
            if value is None:
                pieces.append('')
            elif isinstance(value, str):
                pieces.append('"' + value.replace('"', '""') + '"')
            else:
                pieces.append(str(value))
        stream.write(','.join(pieces) + '\n')
    stream.seek(0)
    cur.copy_expert('COPY ' + table + '(' + ','.join(columns) + ') FROM STDIN WITH CSV', stream)


def _digest(rows):
    digest = hashlib.sha256()
    count = 0
    samples = []
    for row in rows:
        digest.update((canonical(list(row)) + '\n').encode())
        count += 1
        if count <= 5:
            samples.append(list(row))
    return {'count': count, 'sha256': digest.hexdigest(), 'samples': samples}


def build_database(source, target, manifest_path, expected_sha=FROZEN_SHA256, batch_size=50000, *, test_only=False):
    """Commit bounded COPY batches; resume only the same source and schema.

    PostgreSQL credentials use libpq's environment/password-file handling.
    The legacy database is never opened. SQL targets are fixed except for a
    tightly validated newly versioned database name.
    """
    if expected_sha != FROZEN_SHA256 and not test_only:
        raise ValueError('Production CADETS_E3 requires the frozen source hash')
    import psycopg2
    from psycopg2 import sql
    validate_target(target, expected_sha)
    verify_source(source, expected_sha)
    manifest = {'status': 'NOT_COMPLETED', 'schema_version': SCHEMA_VERSION,
                'test_only': bool(test_only), 'production_admissible': False,
                'source_path': str(Path(source).resolve()), 'source_sha256': expected_sha,
                'target_database': target, 'node_type_mapping': NODE_TYPES,
                'relation_mapping': RELATIONS,
                'loader_sha256': file_sha256(__file__),
                'model_views_sha256': hashlib.sha256(VIEWS.encode()).hexdigest(),
                'code_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'progress': {}}
    admin = psycopg2.connect(dbname='postgres')
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute('SELECT 1 FROM pg_database WHERE datname=%s', (target,))
        if cur.fetchone() is None:
            cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(target)))
    admin.close()
    conn = psycopg2.connect(dbname=target)
    try:
        with conn.cursor() as cur:
            cur.execute(DDL)
            cur.execute("SELECT value FROM identity_state WHERE key='source'")
            saved = cur.fetchone()
            binding = {'sha256': expected_sha, 'schema_version': SCHEMA_VERSION}
            if saved and saved[0] != binding:
                raise ValueError('Incompatible database resume binding')
            cur.execute("SELECT value FROM identity_state WHERE key='manifest'")
            prior = cur.fetchone()
            if prior:
                previous = prior[0]
                if previous.get('source_sha256') != expected_sha or previous.get('test_only', False) != bool(test_only):
                    raise ValueError('Incompatible checkpoint binding')
                manifest['progress'] = previous.get('progress', {})
            cur.execute("INSERT INTO identity_state VALUES('source',%s) ON CONFLICT DO NOTHING", (json.dumps(binding),))
            cur.execute("INSERT INTO identity_state VALUES('manifest',%s) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(manifest),))
        conn.commit()
        _write_manifest(manifest_path, manifest)
        for table, columns, iterator in (('identity_nodes', NODE_COLUMNS, iter_nodes), ('identity_events', EVENT_COLUMNS, iter_events)):
            with conn.cursor() as cur:
                cur.execute('SELECT COALESCE(MAX(' + columns[0] + '),0),COUNT(*) FROM ' + table)
                after, count = cur.fetchone()
            checkpoint = manifest['progress'].get(table)
            if checkpoint is not None and (checkpoint['rows'] != count or checkpoint['last_id'] != after):
                raise ValueError('Committed rows differ from authoritative checkpoint')
            batch = []
            last_id = after
            for row in iterator(source, after):
                last_id = row[0]
                batch.append(row)
                if len(batch) >= batch_size:
                    with conn.cursor() as cur:
                        _copy_batch(cur, table, columns, batch)
                    count += len(batch)
                    manifest['progress'][table] = {'rows': count, 'last_id': batch[-1][0]}
                    _checkpoint(conn, manifest, manifest_path)
                    print(json.dumps({'stage': table, 'rows': count}), flush=True)
                    batch.clear()
            if batch:
                with conn.cursor() as cur:
                    _copy_batch(cur, table, columns, batch)
                count += len(batch)
            manifest['progress'][table] = {'rows': count, 'last_id': last_id}
            _checkpoint(conn, manifest, manifest_path)
        with conn.cursor() as cur:
            cur.execute(VIEWS)
        conn.commit()
        manifest['reconciliation'] = {'exact': True}
        for table, columns, iterator in (('identity_nodes', NODE_COLUMNS, iter_nodes), ('identity_events', EVENT_COLUMNS, iter_events)):
            print(json.dumps({'stage': 'reconcile', 'table': table}), flush=True)
            source_digest = _digest(iterator(source))
            with conn.cursor(name='reconcile_' + table) as cur:
                cur.itersize = batch_size
                cur.execute('SELECT ' + ','.join(columns) + ' FROM ' + table + ' ORDER BY ' + columns[0])
                target_digest = _digest(cur)
            if source_digest != target_digest:
                raise ValueError('Full reconciliation mismatch: ' + table)
            manifest['reconciliation'][table] = source_digest
            _write_manifest(manifest_path, manifest)
        with conn.cursor() as cur:
            cur.execute('SELECT raw_type,model_type,count(*) FROM identity_nodes GROUP BY 1,2 ORDER BY 1')
            manifest['node_type_counts'] = cur.fetchall()
            cur.execute('SELECT raw_relation,model_operation,count(*) FROM identity_events GROUP BY 1,2 ORDER BY 1')
            manifest['relation_counts'] = cur.fetchall()
            cur.execute('SELECT count(*),count(*) FILTER(WHERE identity_collision) FROM event_table')
            manifest['inference_eligible_events'], manifest['eligible_collision_events'] = cur.fetchone()
            cur.execute('SELECT count(*) FROM identity_events e LEFT JOIN identity_nodes s ON s.index_id=e.src_index_id LEFT JOIN identity_nodes d ON d.index_id=e.dst_index_id WHERE s.node_uuid IS DISTINCT FROM e.src_uuid OR d.node_uuid IS DISTINCT FROM e.dst_uuid')
            missing = cur.fetchone()[0]
            if missing:
                raise ValueError('Endpoint reconciliation failed')
            manifest['identity_audit'] = {'missing': 0, 'duplicate_stored_ids': 0,
                                          'ambiguous_node_indices': 0, 'endpoint_mismatches': missing}
        verify_source(source, expected_sha)
        manifest['source_hash_verified_before_and_after'] = True
        manifest['status'] = 'COMPLETED'
        manifest = seal_manifest(manifest)
        with conn.cursor() as cur:
            cur.execute("UPDATE identity_state SET value=%s WHERE key='manifest'", (json.dumps(manifest),))
        conn.commit()
        _write_manifest(manifest_path, manifest)
        return manifest
    except BaseException as exc:
        conn.rollback()
        manifest['status'] = 'NOT_COMPLETED'
        manifest['failure'] = type(exc).__name__ + ': ' + str(exc)
        _checkpoint(conn, manifest, manifest_path)
        raise
    finally:
        conn.close()


def finalize_model_views(source, target, manifest_path):
    """Upgrade only derived model views after a successful raw reconciliation.

    This supports a long-running v1 COPY begun before the compatibility-view
    correction. It does not insert, update, or delete any raw node/event row.
    The predecessor reconciliation digest remains explicit in the new manifest.
    """
    import psycopg2
    with open(manifest_path) as stream:
        previous = validate_manifest(json.load(stream))
    validate_target(target, previous['source_sha256'])
    if previous['source_sha256'] != FROZEN_SHA256 and not previous.get('test_only'):
        raise ValueError('Production CADETS_E3 requires the frozen source hash')
    if previous['target_database'] != target:
        raise ValueError('Manifest target mismatch')
    verify_source(source, previous['source_sha256'])
    with psycopg2.connect(dbname=target) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM identity_state WHERE key='manifest'")
            saved = cur.fetchone()
            if saved is None or saved[0] != previous:
                raise ValueError('Database and file manifests disagree')
            # Exclude concurrent raw-table writes while rechecking every record.
            cur.execute('LOCK TABLE identity_nodes,identity_events IN SHARE MODE')
            for name, columns in (('identity_nodes', NODE_COLUMNS), ('identity_events', EVENT_COLUMNS)):
                with conn.cursor(name='finalize_' + name) as scan:
                    scan.itersize = 50000
                    scan.execute('SELECT ' + ','.join(columns) + ' FROM ' + name + ' ORDER BY ' + columns[0])
                    actual_digest = _digest(scan)
                if actual_digest != previous['reconciliation'][name]:
                    invalid = dict(previous, status='NOT_COMPLETED', failure='Finalization reconciliation mismatch')
                    cur.execute("UPDATE identity_state SET value=%s WHERE key='manifest'", (json.dumps(invalid),))
                    conn.commit()
                    _write_manifest(manifest_path, invalid)
                    raise ValueError('Finalization reconciliation mismatch: ' + name)
            for name in ('subject_node_table', 'netflow_node_table'):
                cur.execute('SELECT definition FROM pg_views WHERE schemaname=%s AND viewname=%s', ('public', name))
                row = cur.fetchone()
                if row is None or 'identity_nodes' not in row[0]:
                    raise ValueError('Refusing to replace an unowned model view')
            cur.execute('DROP VIEW subject_node_table; DROP VIEW netflow_node_table;')
            cur.execute(VIEWS)
            manifest = dict(previous)
            manifest['progress'] = {}
            for name, columns in (('identity_nodes', NODE_COLUMNS), ('identity_events', EVENT_COLUMNS)):
                cur.execute('SELECT max(' + columns[0] + ') FROM ' + name)
                manifest['progress'][name] = {'rows': previous['reconciliation'][name]['count'], 'last_id': cur.fetchone()[0]}
            manifest['raw_reconciliation_manifest_sha256'] = previous['manifest_sha256']
            manifest['loader_sha256'] = file_sha256(__file__)
            manifest['model_views_sha256'] = hashlib.sha256(VIEWS.encode()).hexdigest()
            manifest['view_code_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            nested_repo = Path(__file__).resolve().parents[2] / 'webapp/runtime/research/PIDSMaker'
            if nested_repo.is_dir():
                manifest['pidsmaker_code_commit'] = subprocess.check_output(['git', '-C', str(nested_repo), 'rev-parse', 'HEAD'], text=True).strip()
                spec = importlib.util.spec_from_file_location('identity_runtime_contract', nested_repo / 'pidsmaker/identity_contract.py')
                contract = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(contract)
                manifest['pidsmaker_runtime_seal'] = contract.runtime_seal()
            origin_sql = "CASE WHEN original_event_id LIKE 'LINEAGE:%' THEN 'DERIVED_NO_RAW_EVENT' WHEN original_event_id ~ '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$' THEN 'RAW_TC_EVENT' ELSE 'OTHER_STORED_ID' END"
            cur.execute('SELECT ' + origin_sql + ',count(*) FROM identity_events GROUP BY 1')
            manifest['identity_origin_counts'] = dict(cur.fetchall())
            cur.execute('SELECT identity_origin,count(*) FROM event_table GROUP BY 1')
            manifest['model_eligible_identity_origin_counts'] = dict(cur.fetchall())
            cur.execute("SELECT raw_type,model_type,CASE WHEN model_type IS NULL THEN 'excluded' WHEN raw_type=model_type THEN 'included' ELSE 'remapped' END,count(*) FROM identity_nodes GROUP BY 1,2,3 ORDER BY 1")
            node_audit = cur.fetchall()
            cur.execute("""SELECT e.raw_relation,e.model_operation,
                CASE WHEN e.model_operation IS NULL THEN 'excluded_unsupported_relation'
                     WHEN s.index_id IS NULL OR d.index_id IS NULL THEN 'rejected_missing_endpoint'
                     WHEN s.model_type IS NULL OR d.model_type IS NULL THEN 'excluded_endpoint_type'
                     WHEN e.raw_relation=e.model_operation THEN 'included' ELSE 'remapped' END,count(*)
                FROM identity_events e LEFT JOIN identity_nodes s ON s.index_id=e.src_index_id
                LEFT JOIN identity_nodes d ON d.index_id=e.dst_index_id
                GROUP BY 1,2,3 ORDER BY 1,2,3""")
            event_audit = cur.fetchall()
            manifest['node_disposition_audit'] = node_audit
            manifest['event_disposition_audit'] = event_audit
            manifest['conservation'] = {}
            for name, rows in (('nodes', node_audit), ('events', event_audit)):
                counts = {'raw': previous['reconciliation']['identity_' + name]['count'], 'included': 0, 'remapped': 0, 'excluded': 0}
                for raw, model, reason, count in rows:
                    if reason.startswith('rejected'):
                        raise ValueError('Unresolved identity category: ' + reason)
                    category = 'excluded' if reason.startswith('excluded') else reason
                    if category not in ('included', 'remapped', 'excluded'):
                        raise ValueError('Unclassified identity disposition')
                    counts[category] += count
                if counts['raw'] != counts['included'] + counts['remapped'] + counts['excluded']:
                    raise ValueError('Raw/model conservation failed')
                manifest['conservation'][name] = counts
            manifest['identity_mapping_convention'] = {
                'local_stored_identity_exact': 'all reconciled stored events',
                'raw_TC_event_identity_exact': 'RAW_TC_EVENT only; LINEAGE rows are DERIVED_NO_RAW_EVENT',
                'subject_lineage_provenance': 'src_uuid=parent subject; dst_uuid=child subject'}
            manifest['test_only'] = previous.get('test_only', False)
            manifest['production_admissible'] = not manifest['test_only'] and previous['source_sha256'] == FROZEN_SHA256
            manifest = seal_manifest(manifest)
            cur.execute("UPDATE identity_state SET value=%s WHERE key='manifest'", (json.dumps(manifest),))
    _write_manifest(manifest_path, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--source-sha256', default=FROZEN_SHA256)
    parser.add_argument('--finalize-model-views', action='store_true')
    parser.add_argument('--test-only', action='store_true', help='Fixture sources; seals cannot be used for production')
    args = parser.parse_args()
    result = (finalize_model_views(args.source, args.target, args.manifest) if args.finalize_model_views
              else build_database(args.source, args.target, args.manifest, args.source_sha256, test_only=args.test_only))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
