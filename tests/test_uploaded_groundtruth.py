"""Evaluation contracts: node UUID identity, honest denominators, missing outputs."""
import importlib.util
import json
import sqlite3
import zipfile
from pathlib import Path

MODULE = Path(__file__).parents[1] / 'webapp/scripts/evaluate_uploaded_groundtruth.py'


def load_module():
    spec = importlib.util.spec_from_file_location('archive_evaluator', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_archive_case_normalization_and_deduplication(tmp_path):
    archive = tmp_path / 'truth.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('truth/README.md', 'UUID, attributes, index_id')
        z.writestr('truth/darpa/E3-X/nodes.csv', "a,{'subject': 'x'},7\nA,{'subject': 'x'},8\nb,{'file': 'f'},9\n")
    result = load_module().read_archive(archive, None)
    item = result['files'][0]
    assert item['row_count'] == 3
    assert item['unique_node_count'] == 2
    assert item['node_uuids'] == ['A', 'B']


def test_retention_is_not_classification_and_absent_nodes_stay_in_denominator(tmp_path):
    module = load_module()
    db = tmp_path / 'events.db'
    with sqlite3.connect(db) as c:
        c.executescript('CREATE TABLE nodes(uuid TEXT PRIMARY KEY,node_type TEXT); CREATE TABLE edges(event_id TEXT,src TEXT,dst TEXT,timestamp_ns INTEGER); CREATE INDEX idx_edges_src ON edges(src);')
        c.executemany('INSERT INTO nodes VALUES (?,?)', [('a','process'),('b','file'),('u','file')])
        c.executemany('INSERT INTO edges VALUES (?,?,?,?)', [('e1','a','b',10),('e2','a','b',30),('e3','a','u',15)])
    ledger = tmp_path / 'ledger.jsonl'
    ledger.write_text('\n'.join(json.dumps(x) for x in [
        {'event_id':'e1','src':'a','dst':'b','decisions':[{'budget_key':'0.2','kept':False}]},
        {'event_id':'e3','src':'a','dst':'u','decisions':[{'budget_key':'0.2','kept':True}]},
    ]))
    annotations = tmp_path / 'annotations.json'
    annotations.write_text(json.dumps({'metadata': {'attack_window_start_ns':0,'attack_window_end_ns':20}, 'attack_event_ids':['e1']}))
    item = {'node_uuids':['A','B','C'], 'sha256':'unused'}
    result = module.evaluate_case(item, {'database':str(db),'ledger':str(ledger),'annotation':str(annotations)})
    assert result['database']['matched_node_count'] == 2
    assert result['database']['missing_node_uuids'] == ['C']
    assert result['derived_events']['static_internal_count'] == 2
    assert result['derived_events']['protocol_internal_count'] == 1
    measured = result['retention']['saved_pruning@0.2']
    assert measured['retained_labeled_nodes'] == 1
    assert measured['node_recall_csv'] == 1 / 3
    assert measured['retained_protocol_internal_events'] == 0
    assert measured['event_recall_protocol'] == 0
    assert measured['classification_accuracy'] is None


def test_no_prediction_has_no_fabricated_zero_recall(tmp_path):
    module = load_module()
    db = tmp_path / 'events.db'
    with sqlite3.connect(db) as c:
        c.executescript('CREATE TABLE nodes(uuid TEXT PRIMARY KEY,node_type TEXT); CREATE TABLE edges(event_id TEXT,src TEXT,dst TEXT,timestamp_ns INTEGER);')
        c.execute('INSERT INTO nodes VALUES (?,?)', ('A','process'))
    result = module.evaluate_case({'node_uuids':['A'],'sha256':'unused'}, {'database':str(db)})
    assert result['retention'] is None
    assert result['status'] == 'database_available_no_completed_prediction'
