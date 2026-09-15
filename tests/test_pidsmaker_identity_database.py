import hashlib
import os
import sqlite3

import pytest

from tc_pruning.detectors import identity_database as identity


def fixture_db(path):
    db = sqlite3.connect(path)
    db.executescript('''
      CREATE TABLE nodes(uuid TEXT PRIMARY KEY, node_type TEXT, label TEXT, host TEXT,
                         semantic_key TEXT, properties_json TEXT);
      CREATE TABLE edges(id INTEGER PRIMARY KEY, event_id TEXT UNIQUE, original_event_id TEXT,
                         src TEXT, dst TEXT, relation TEXT, timestamp_ns INTEGER,
                         host TEXT, data_size INTEGER);
      INSERT INTO nodes VALUES('p1','process','same','h','same','{}');
      INSERT INTO nodes VALUES('p2','process','same','h','same','{}');
      INSERT INTO nodes VALUES('f1','pipe','pipe','h','pipe','{}');
      INSERT INTO edges VALUES(1,'e1','e1','p1','p2','EVENT_FORK',10,'h',NULL);
      INSERT INTO edges VALUES(2,'e1#2','e1','p2','f1','EVENT_WRITE',11,'h',3);
      INSERT INTO edges VALUES(3,'e3','e3','p1','f1','EVENT_CLOSE',12,'h',NULL);
    ''')
    db.close()
    return path


def test_semantically_equal_nodes_remain_distinct(tmp_path):
    source = fixture_db(tmp_path / 'source.db')
    nodes = list(identity.iter_nodes(source))
    assert [(n[0], n[1]) for n in nodes[:2]] == [(1, 'p1'), (2, 'p2')]
    assert nodes[2][3] == 'file'


def test_events_keep_raw_fork_collision_and_exact_endpoints(tmp_path):
    source = fixture_db(tmp_path / 'source.db')
    rows = list(identity.iter_events(source))
    assert rows[0][:10] == (1, 'e1', 'e1', 'p1', 'p2', 1, 2, 'EVENT_FORK', 'EVENT_CLONE', 10)
    assert rows[1][10] is True
    assert rows[2][8] is None


@pytest.mark.parametrize('mutation', [
    "UPDATE edges SET event_id='legacy-row-1' WHERE id=1",
    "UPDATE edges SET original_event_id='' WHERE id=1",
    "UPDATE edges SET src='absent' WHERE id=1",
    "UPDATE nodes SET uuid='' WHERE uuid='p1'",
])
def test_missing_synthetic_or_unresolvable_identity_aborts(tmp_path, mutation):
    source = fixture_db(tmp_path / 'source.db')
    with sqlite3.connect(source) as db:
        db.execute(mutation)
    with pytest.raises(ValueError):
        list(identity.iter_nodes(source))
        list(identity.iter_events(source))


def test_hash_mismatch_and_legacy_target_are_rejected(tmp_path):
    source = fixture_db(tmp_path / 'source.db')
    with pytest.raises(ValueError, match='hash'):
        identity.verify_source(source, '0' * 64)
    with pytest.raises(ValueError, match='target'):
        identity.validate_target('cadets_e3', 'a' * 64)
    assert identity.verify_source(source, hashlib.sha256(source.read_bytes()).hexdigest())


def test_incomplete_or_tampered_manifest_is_not_consumable():
    with pytest.raises(ValueError):
        identity.validate_manifest({'status': 'NOT_COMPLETED'})
    with pytest.raises(ValueError):
        identity.validate_manifest({'status': 'COMPLETED', 'manifest_sha256': 'bad'})


@pytest.mark.skipif(os.environ.get('IDENTITY_PG_TEST') != '1', reason='explicit PostgreSQL integration run')
def test_real_copy_resume_and_tamper_reconciliation(tmp_path):
    import psycopg2
    source = fixture_db(tmp_path / 'source.db')
    # Separate fixture namespace per invocation, within the content-bound naming rule.
    with sqlite3.connect(source) as db:
        db.execute('UPDATE nodes SET host=?', (str(tmp_path),))
    sha = identity.file_sha256(source)
    target = 'cadets_e3_identity_v1_' + sha[:12]
    manifest_path = tmp_path / 'manifest.json'
    first = identity.build_database(source, target, manifest_path, sha, batch_size=1)
    assert first['inference_eligible_events'] == 2
    assert first['eligible_collision_events'] == 1
    assert first['reconciliation']['identity_events']['count'] == 3
    assert identity.validate_manifest(first)['status'] == 'COMPLETED'
    resumed = identity.build_database(source, target, manifest_path, sha, batch_size=1)
    assert resumed['reconciliation'] == first['reconciliation']
    upgraded = identity.finalize_model_views(source, target, manifest_path)
    assert upgraded['raw_reconciliation_manifest_sha256'] == resumed['manifest_sha256']
    assert upgraded['identity_origin_counts'] == {'OTHER_STORED_ID': 3}
    with psycopg2.connect(dbname=target) as db:
        with db.cursor() as cur:
            cur.execute('SELECT node_uuid,hash_id,exec,path,cmd,index_id FROM subject_node_table ORDER BY index_id')
            assert [row[0] for row in cur.fetchall()] == ['p1', 'p2']
            cur.execute('SELECT src_addr,src_port,dst_addr,dst_port FROM netflow_node_table')
            cur.execute('SELECT event_uuid,original_event_id,raw_relation,operation FROM event_table ORDER BY _id')
            assert cur.fetchall() == [('e1', 'e1', 'EVENT_FORK', 'EVENT_CLONE'), ('e1#2', 'e1', 'EVENT_WRITE', 'EVENT_WRITE')]
            cur.execute("UPDATE identity_events SET src_uuid='tampered' WHERE source_row_id=1")
    with pytest.raises(ValueError, match='reconciliation'):
        identity.build_database(source, target, manifest_path, sha, batch_size=1)
