"""Subgraph evaluation must remain bound to the already frozen experiment."""
import json

import pytest

from test_evaluate_chain_workbench import frozen, change_registration
from tc_pruning.chain_workbench import write_json


def api():
    from scripts import evaluate_reference_subgraphs
    return evaluate_reference_subgraphs


@pytest.fixture
def base_report(frozen, tmp_path):
    from scripts.evaluate_chain_workbench import evaluate_run
    path = tmp_path/'base-report.json'
    write_json(path, evaluate_run(frozen['run']))
    return path


def test_fixed_subgraphs_and_source_gaps_are_distinct(frozen, base_report):
    report = api().evaluate_run(frozen['run'], base_report)
    assert report['schema_version'] == 'chain-subgraph-report-v1'
    case = report['cases'][0]
    assert case['source_missing_positive_events'] == 2
    assert case['reference_summaries']['native']['reference_subgraph_count'] == 1
    assert case['reference_summaries']['native']['reference_events'] == 3
    variant = next(v for v in case['variants'] if v['poi_policy']=='single')
    small = next(p for p in variant['rows'] if p['method']=='rarity_only' and p['budget']==2)
    large = next(p for p in variant['rows'] if p['method']=='rarity_only' and p['budget']==5)
    assert small['scopes']['native']['complete_subgraphs'] == 0
    assert small['scopes']['native']['retained_reference_events'] == 2
    assert large['scopes']['native']['complete_subgraphs'] == 1
    assert large['scopes']['native']['subgraph_retention'] == 1
    assert sum(small['scopes']['native']['first_loss_counts'].values()) == 1
    assert 'SECRET' not in json.dumps(report)
    assert str(frozen['root']) not in json.dumps(report)


def test_frozen_tamper_prevents_reference_access(frozen, base_report, monkeypatch):
    from scripts import evaluate_chain_workbench as existing
    (frozen['folder']/'base/adaptive/decisions.npz').write_bytes(b'tamper')
    monkeypatch.setattr(existing, '_load_reference', lambda *_: pytest.fail('labels read too early'))
    with pytest.raises(ValueError, match='hash'):
        api().evaluate_run(frozen['run'], base_report)


def test_old_report_from_different_reference_is_rejected(frozen, base_report):
    content=json.loads(frozen['reference'].read_text())
    content['attack_event_ids'].pop()
    write_json(frozen['reference'], content)
    with pytest.raises(ValueError, match='reference'):
        api().evaluate_run(frozen['run'], base_report)


def test_report_point_and_case_mismatch_are_rejected(frozen, base_report):
    content=json.loads(base_report.read_text())
    content['cases'][0]['variants'][0]['rows'][0]['retained_events'] += 1
    write_json(base_report, content)
    with pytest.raises(ValueError, match='base report'):
        api().evaluate_run(frozen['run'], base_report)


def test_unavailable_reference_remains_null(frozen, tmp_path):
    from scripts.evaluate_chain_workbench import evaluate_run
    change_registration(frozen, lambda r:r['case'].update(reference={'kind':'unavailable'}))
    path=tmp_path/'unavailable.json';write_json(path,evaluate_run(frozen['run']))
    report=api().evaluate_run(frozen['run'],path)
    case=report['cases'][0]
    assert case['reference_summaries']['native']['reference_subgraph_count'] is None
    point=case['variants'][0]['rows'][0]['scopes']['native']
    assert point['complete_subgraphs'] is None and point['subgraph_retention'] is None


def test_mutation_during_reference_loading_prevents_publication(frozen, base_report, monkeypatch, tmp_path):
    from scripts import evaluate_chain_workbench as existing
    original=existing._load_reference
    def mutate(registration):
        result=original(registration)
        path=frozen['folder']/'base/single/manifest.json'
        path.write_bytes(path.read_bytes()+b' ')
        return result
    monkeypatch.setattr(existing,'_load_reference',mutate)
    with pytest.raises(ValueError,match='changed'):
        api().evaluate_run(frozen['run'],base_report)


def test_cli_writes_two_scopes_per_point_and_refuses_overwrite(frozen, base_report, tmp_path):
    import csv
    output=tmp_path/'subgraphs.json'
    argv=['--input',str(frozen['run']),'--base-report',str(base_report),'--output',str(output)]
    api().main(argv)
    report=json.loads(output.read_text())
    with output.with_suffix('.csv').open() as stream:rows=list(csv.DictReader(stream))
    assert len(rows)==2*sum(len(v['rows']) for c in report['cases'] for v in c['variants'])
    assert {r['scope'] for r in rows}=={'native','augmented'}
    with pytest.raises(FileExistsError):api().main(argv)


@pytest.fixture
def exported_catalog(frozen, tmp_path):
    from scripts.export_chain_workbench import export_frozen
    frontend=tmp_path/'frontend';target=frontend/'retained-chain-data/sample'
    export_frozen(frozen['folder']/'base/single','rarity_only',2,target)
    artifact=json.loads((target/'retained-graph.json').read_text())
    entry={k:artifact[k] for k in ('case_id','track','poi_policy','method','budget_edges')}
    entry.update(id='sample',study_version='chain-workbench-v2',
                 artifact_url='/assets/retained-chain-data/sample/retained-graph.json')
    catalog=frontend/'retained-chain-catalog.json';write_json(catalog,{'entries':[entry]})
    return catalog,target/'retained-graph.json'


def test_private_inspection_is_exact_and_bound(frozen, base_report, exported_catalog, tmp_path):
    catalog,_=exported_catalog;destination=tmp_path/'private'
    report=api().evaluate_run(frozen['run'],base_report,catalog=catalog,local_output=destination)
    detail=json.loads((destination/'sample.json').read_text())
    assert detail['schema_version']=='chain-subgraph-audit-v1'
    assert detail['base_report_sha256']==report['base_report_sha256']
    assert detail['budget_edges']==2 and detail['selection_recomputed'] is False
    assert detail['source_missing_positive_events']==2
    scope=detail['scopes']['native']
    assert scope['stages']['retained']['complete_subgraphs']==0
    assert {r['event_id'] for r in scope['events'] if r['retained']}=={'SECRET_EVENT_A','SECRET_EVENT_B'}
    assert all(isinstance(r['timestamp_ns'],str) for r in scope['events'])
    assert 'SECRET' not in json.dumps(report)


def test_foreign_export_events_rejected_without_private_output(frozen, base_report, exported_catalog, tmp_path):
    catalog,artifact_path=exported_catalog;artifact=json.loads(artifact_path.read_text())
    artifact['events'][0]['event_id']='SECRET_EVENT_C';write_json(artifact_path,artifact)
    destination=tmp_path/'private'
    with pytest.raises(ValueError,match='exact frozen mask'):
        api().evaluate_run(frozen['run'],base_report,catalog=catalog,local_output=destination)
    assert not destination.exists()


def test_catalog_cannot_escape_assets(frozen, base_report, exported_catalog, tmp_path):
    catalog,_=exported_catalog;data=json.loads(catalog.read_text())
    data['entries'][0]['artifact_url']='/assets/retained-chain-data/../../outside.json';write_json(catalog,data)
    with pytest.raises(ValueError,match='escapes'):
        api().evaluate_run(frozen['run'],base_report,catalog=catalog,local_output=tmp_path/'private')


def test_public_schema_drops_future_private_core_fields(frozen, base_report, monkeypatch):
    addon=api();derive=addon.derive_reference_subgraphs;evaluate=addon.evaluate_subgraphs
    def private_model(*args,**kwargs):
        model=derive(*args,**kwargs)
        model['summary']['private_event_ids']=['SECRET_CANARY']
        return model
    def private_metrics(*args,**kwargs):
        result=evaluate(*args,**kwargs)
        for stage in result['stages'].values():stage['private_event_ids']=['SECRET_CANARY']
        return result
    monkeypatch.setattr(addon,'derive_reference_subgraphs',private_model)
    monkeypatch.setattr(addon,'evaluate_subgraphs',private_metrics)
    report=addon.evaluate_run(frozen['run'],base_report)
    assert 'SECRET_CANARY' not in json.dumps(report)


@pytest.mark.parametrize('field,value', [('src','WRONG'),('relation','EVENT_READ'),
    ('timestamp_ns','999'),('host','FOREIGN'),('causal_dst','WRONG')])
def test_export_semantics_must_match_frozen_events(frozen, base_report, exported_catalog, tmp_path, field, value):
    catalog,path=exported_catalog;artifact=json.loads(path.read_text())
    artifact['events'][0][field]=value;write_json(path,artifact)
    with pytest.raises(ValueError,match='event structure'):
        api().evaluate_run(frozen['run'],base_report,catalog=catalog,local_output=tmp_path/'private')


def test_source_reference_ids_cannot_represent_changed_candidate_structure(frozen, tmp_path):
    import sqlite3
    from scripts.evaluate_chain_workbench import evaluate_run
    database=frozen['registration']['data_root']+'/source.db'
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE edges SET src='P5' WHERE event_id='SECRET_EVENT_B'")
    report=tmp_path/'changed-source-report.json';write_json(report,evaluate_run(frozen['run']))
    with pytest.raises(ValueError,match='source and candidate event structure'):
        api().evaluate_run(frozen['run'],report)


def test_catalog_may_link_into_this_frozen_runs_exports(frozen, base_report, exported_catalog, tmp_path):
    catalog,artifact=exported_catalog
    physical=frozen['run']/'exports/sample';physical.parent.mkdir()
    artifact.parent.rename(physical)
    artifact.parent.symlink_to(physical,target_is_directory=True)
    destination=tmp_path/'private'
    api().evaluate_run(frozen['run'],base_report,catalog=catalog,local_output=destination)
    assert (destination/'sample.json').is_file()
