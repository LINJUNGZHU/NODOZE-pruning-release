"""Offline aggregation must follow global artifact validation and preserve denominators."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from tc_pruning.chain_workbench import (METHODS, canonical, digest, freeze_variant, prepare_evidence,
                                      run_variant, validate_variant, write_json)
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def api():
    from scripts import evaluate_chain_workbench
    return evaluate_chain_workbench


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    root = tmp_path / 'code'; root.mkdir()
    (root / 'configs').mkdir()
    source = tmp_path / 'data'; source.mkdir()
    ledger = source / 'ledger.gz'; ledger.write_bytes(b'frozen original ledger fixture')
    database = source / 'source.db'
    events = ['SECRET_EVENT_A', 'SECRET_EVENT_B', 'SECRET_EVENT_C', 'LINEAGE_SECRET_EVENT', 'SECRET_NOISE']
    rows = [{'event_id':event, 'src':f'P{i}', 'dst':f'P{i+1}', 'relation':'EVENT_WRITE',
             'timestamp_ns':100+i, 'host':'SECRET_HOST', 'src_type':'process', 'dst_type':'process',
             'src_semantic':'process:/SECRET_BINARY', 'dst_semantic':'process:/SECRET_BINARY',
             'is_declared_poi':i in (0,2), 'rarity':.8} for i,event in enumerate(events)]
    with ProvenanceStore(database) as store:
        store.ingest([NodeRecord(f'P{i}', 'process', 'SECRET_LABEL', 'SECRET_HOST', 'process:/SECRET_BINARY') for i in range(6)]
                     + [EdgeRecord(row['event_id'],row['src'],row['dst'],row['relation'],row['timestamp_ns'],row['host'])
                        for row in rows if 'LINEAGE' not in row['event_id']])
    reference = root / 'reference.json'
    write_json(reference, {'attack_event_ids':events[:4]+['SECRET_MISSING'],
                          'metadata':{'groundtruth_family':'CAPTAIN/human_readable_gt','scenario':'06'}})
    spec = {'id':'cadets06','label':'SECRET_FREE_LABEL','provider':'CADETS','ledger':'ledger.gz',
            'database':'source.db','expand_window':False,'reference':{'kind':'captain_events','path':'reference.json'}}
    config = {'poi_policies':['single','declared','adaptive'],'max_pois':2}
    write_json(root/'configs/chain_workbench_v2.json', {'cases':[spec], 'data_readiness':[
        {'dataset':'E5','provider':'local annotation folders','status':'annotation_only','reason':'No matching local raw data.'}]})
    run = tmp_path/'run'; folder = run/'cadets06'; folder.mkdir(parents=True)
    registration = {'schema_version':'chain-workbench-case-registration-v2','case':spec,'config':config,
                    'ledger_sha256':digest(ledger),'data_root':str(source),'history':{},'labels_opened':False}
    write_json(folder/'registration.json', registration)
    prepared = prepare_evidence(rows, [], 99)
    variants = []
    import hashlib
    for policy in config['poi_policies']:
        online = run_variant(rows, prepared, policy, [2,5], max_anchors=16, max_pois=2)
        directory = folder/'base'/policy
        freeze_variant(directory, rows, prepared, online, case_id='cadets06', track='base', provenance={
            'ledger_sha256':digest(ledger),'config_sha256':hashlib.sha256(canonical(config)).hexdigest(),
            'initial_candidate_events':len(rows),'fixed_scope_events':len(rows),
            'original_declared_event_ids':[events[0],events[2]], 'source_note':'SECRET_SOURCE_PATH'})
        variants.append({'track':'base','poi_policy':policy,'path':f'base/{policy}',
                         'manifest_sha256':digest(directory/'manifest.json'),**validate_variant(directory)})
    case = {'schema_version':'chain-workbench-case-v2','id':'cadets06','label':spec['label'],'provider':'CADETS',
            'split':'development','labels_used':False,'variants':variants,'source_scope_events':len(rows),
            'registration_sha256':digest(folder/'registration.json')}
    write_json(folder/'case.json',case)
    monkeypatch.setattr(api(),'ROOT',root)
    return {'run':run,'folder':folder,'root':root,'reference':reference,'registration':registration,'case':case}


def test_aggregate_denominators_are_fixed_and_no_private_details_escape(frozen):
    report = api().evaluate_run(frozen['run'])
    assert report['schema_version']=='chain-workbench-v2-report'
    assert set(report['methods'])==set(METHODS)
    case=report['cases'][0]
    assert case['label']=='CADETS06' and case['split']=='development'
    assert case['annotation_status']=='captain_event_pattern_reference'
    for variant in case['variants']:
        assert variant['source_scope_events']==5
        for point in variant['rows']:
            assert point['positive_count']==5
            assert point['incremental_positive_count']==3
            assert point['source_positive_events']==3
            assert point['source_missing_positive_events']==2
            assert point['synthetic_lineage_positive_count']==1
            assert point['verified_attack_chain_retention'] is None
            assert point['compression']==1-point['retained_events']/5
            assert point['fixed_scope_compression']==point['compression']
            assert sum(point['event_first_loss_counts'].values())==5
    text=json.dumps(report)
    assert 'SECRET' not in text and str(frozen['root']) not in text
    assert 'false_positive' not in text and 'precision' not in text


def test_every_variant_is_validated_before_any_reference_is_opened(frozen, monkeypatch):
    broken=frozen['folder']/'base/adaptive/decisions.npz'
    broken.write_bytes(broken.read_bytes()+b'tampered')
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('reference read before global validation'))
    with pytest.raises(ValueError,match='hash'):
        api().evaluate_run(frozen['run'])


def test_registration_hash_tampering_precedes_label_loading(frozen, monkeypatch):
    path=frozen['folder']/'registration.json';path.write_bytes(path.read_bytes()+b' ')
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('reference read before registration validation'))
    with pytest.raises(ValueError,match='registration'):
        api().evaluate_run(frozen['run'])


def test_manifest_hash_tampering_precedes_label_loading(frozen, monkeypatch):
    path=frozen['folder']/'base/single/manifest.json';path.write_bytes(path.read_bytes()+b' ')
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('reference read before manifest validation'))
    with pytest.raises(ValueError,match='manifest'):
        api().evaluate_run(frozen['run'])


def change_registration(frozen, change):
    registration=deepcopy(frozen['registration']);change(registration)
    write_json(frozen['folder']/'registration.json',registration)
    case=deepcopy(frozen['case']);case['registration_sha256']=digest(frozen['folder']/'registration.json')
    write_json(frozen['folder']/'case.json',case)


def test_unavailable_reference_yields_null_not_fake_perfect_retention(frozen):
    change_registration(frozen,lambda r:r['case'].update(reference={'kind':'unavailable'}))
    frozen['reference'].unlink()
    case=api().evaluate_run(frozen['run'])['cases'][0]
    assert case['annotation_status']=='unavailable'
    for variant in case['variants']:
        for point in variant['rows']:
            assert point['reference_chain_retention'] is None
            assert point['positive_retention'] is None
            assert point['reference_chain_count'] is None
            assert point['positive_count'] is None
            assert point['retained_events']>=1


def test_empty_available_reference_has_zero_counts_and_null_ratios(frozen):
    value=json.loads(frozen['reference'].read_text());value['attack_event_ids']=[]
    write_json(frozen['reference'],value)
    point=api().evaluate_run(frozen['run'])['cases'][0]['variants'][0]['rows'][0]
    assert point['positive_count']==0 and point['positive_retention'] is None
    assert point['reference_chain_count']==0 and point['reference_chain_retention'] is None


def test_captain_family_and_scenario_must_match(frozen):
    value=json.loads(frozen['reference'].read_text());value['metadata']['scenario']='13'
    write_json(frozen['reference'],value)
    with pytest.raises(ValueError,match='CAPTAIN'):
        api().evaluate_run(frozen['run'])


def test_local_subset_requires_matching_ledger_hash(frozen):
    write_json(frozen['reference'],{'protocol':'sparse-local-critical-edge-reference-v1','cases':[
        {'critical_event_ids':['SECRET_EVENT_A'],'ledger_sha256':'0'*64}]})
    change_registration(frozen,lambda r:r['case'].update(reference={'kind':'local_critical_subset','path':'reference.json','case_index':0}))
    with pytest.raises(ValueError,match='ledger'):
        api().evaluate_run(frozen['run'])


def test_variant_path_cannot_escape_case(frozen, monkeypatch):
    case=deepcopy(frozen['case']);case['variants'][0]['path']='../outside'
    write_json(frozen['folder']/'case.json',case)
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('unsafe path reached labels'))
    with pytest.raises(ValueError,match='path'):
        api().evaluate_run(frozen['run'])


def test_reference_derivation_happens_once_per_case(frozen, monkeypatch):
    original=api().derive_reference_chains;calls=[]
    def traced(*args,**kwargs):
        calls.append(1);return original(*args,**kwargs)
    monkeypatch.setattr(api(),'derive_reference_chains',traced)
    api().evaluate_run(frozen['run'])
    assert calls==[1]


def test_cli_writes_report_and_flat_csv(frozen, tmp_path):
    output=tmp_path/'aggregate.json'
    api().main(['--input',str(frozen['run']),'--output',str(output)])
    assert json.loads(output.read_text())['cases'][0]['id']=='cadets06'
    assert output.with_suffix('.csv').is_file()
    assert 'SECRET' not in output.with_suffix('.csv').read_text()


def test_plot_exports_publication_artifacts_without_filling_na(frozen, tmp_path):
    from scripts import plot_chain_workbench
    report=api().evaluate_run(frozen['run'])
    output=tmp_path/'plots'
    files=plot_chain_workbench.plot_report(report,output)
    assert len(files)==12  # One case's three faceted figures + one overview, in three formats.
    assert {p.suffix for p in files}=={'.png','.svg','.pdf'}
    assert all(p.stat().st_size>100 for p in files)
    assert any('reference-chain' in p.name for p in files)
    assert any('equal-budget' in p.name for p in files)


def resign_variant(frozen, policy, change):
    directory=frozen['folder']/'base'/policy
    manifest=json.loads((directory/'manifest.json').read_text())
    change(directory, manifest)
    write_json(directory/'manifest.json',manifest)
    case=json.loads((frozen['folder']/'case.json').read_text())
    next(v for v in case['variants'] if v['poi_policy']==policy)['manifest_sha256']=digest(directory/'manifest.json')
    write_json(frozen['folder']/'case.json',case)


def test_resigned_candidate_structure_cannot_differ_between_poi_policies(frozen, monkeypatch):
    from tc_pruning.chain_workbench import read_gzip, write_gzip
    def change(directory,manifest):
        candidates=read_gzip(directory/'candidates.json.gz')
        candidates[-1]['dst_semantic']='process:/CHANGED_STRUCTURE'
        write_gzip(directory/'candidates.json.gz',candidates)
        manifest['artifacts']['candidates.json.gz']=digest(directory/'candidates.json.gz')
    resign_variant(frozen,'adaptive',change)
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('structural mismatch reached labels'))
    with pytest.raises(ValueError,match='candidate|context'):
        api().evaluate_run(frozen['run'])


def test_shared_history_cutoff_cannot_change_between_poi_policies(frozen, monkeypatch):
    resign_variant(frozen,'adaptive',lambda directory,manifest:manifest.update(cutoff_ns='98'))
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('history mismatch reached labels'))
    with pytest.raises(ValueError,match='history'):
        api().evaluate_run(frozen['run'])


def test_expansion_comparison_keeps_reference_denominator_and_fixed_scope(frozen):
    from tc_pruning.chain_workbench import read_gzip
    import hashlib
    registration=deepcopy(frozen['registration']);registration['case']['expand_window']=True
    write_json(frozen['folder']/'registration.json',registration)
    case=json.loads((frozen['folder']/'case.json').read_text())
    case['registration_sha256']=digest(frozen['folder']/'registration.json')
    case['source_scope_events']=6
    originals={'SECRET_EVENT_A','SECRET_EVENT_C'}
    rows=read_gzip(frozen['folder']/'base/declared/candidates.json.gz')
    for row in rows:
        row['timestamp_ns']=int(row['timestamp_ns']);row['is_declared_poi']=row['event_id'] in originals
    extra=dict(rows[-1],event_id='SECRET_ADDED_EVENT',src='P5',dst='P6',timestamp_ns=105,is_declared_poi=False)
    rows.append(extra)
    prepared=prepare_evidence(rows,[],99)
    for variant in case['variants']:
        directory=frozen['folder']/variant['path'];manifest=json.loads((directory/'manifest.json').read_text())
        manifest['provenance']['fixed_scope_events']=6
        write_json(directory/'manifest.json',manifest);variant['manifest_sha256']=digest(directory/'manifest.json')
    for policy in registration['config']['poi_policies']:
        online=run_variant(rows,prepared,policy,[2,5],max_anchors=16,max_pois=2)
        directory=frozen['folder']/'expanded'/policy
        freeze_variant(directory,rows,prepared,online,case_id='cadets06',track='expanded',provenance={
            'ledger_sha256':registration['ledger_sha256'],
            'config_sha256':hashlib.sha256(canonical(registration['config'])).hexdigest(),
            'initial_candidate_events':5,'fixed_scope_events':6,'original_declared_event_ids':sorted(originals)})
        case['variants'].append({'track':'expanded','poi_policy':policy,'path':f'expanded/{policy}',
                                 'manifest_sha256':digest(directory/'manifest.json'),**validate_variant(directory)})
    write_json(frozen['folder']/'case.json',case)
    result=api().evaluate_run(frozen['run'])['cases'][0]
    chain_counts={point['reference_chain_count'] for variant in result['variants'] for point in variant['rows']}
    assert chain_counts=={1}
    for variant in result['variants']:
        assert variant['source_scope_events']==6
        for point in variant['rows']:
            assert point['fixed_scope_compression']==1-point['retained_events']/6
            assert point['compression']==1-point['retained_events']/variant['candidate_events']
            assert point['incremental_positive_count']==3


def test_unavailable_plot_has_no_numeric_retention_lines(frozen):
    from scripts.plot_chain_workbench import _case_figure
    import matplotlib.pyplot as plt
    change_registration(frozen,lambda r:r['case'].update(reference={'kind':'unavailable'}))
    case=api().evaluate_run(frozen['run'])['cases'][0]
    figure=_case_figure(case,metric='reference_chain_retention',xfield='compression')
    assert all(not axis.lines for axis in figure.axes)
    assert all(any('N/A' in text.get_text() for text in axis.texts) for axis in figure.axes)
    plt.close(figure)


def test_started_but_unfinished_case_blocks_all_reference_reads(frozen, monkeypatch):
    unfinished=frozen['run']/'cadets12';unfinished.mkdir()
    write_json(unfinished/'registration.json',{'labels_opened':False})
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('unfinished run reached labels'))
    with pytest.raises(ValueError,match='unfinished|incomplete'):
        api().evaluate_run(frozen['run'])


def test_missing_registered_cases_require_explicit_partial_mode(frozen, monkeypatch):
    path=frozen['root']/'configs/chain_workbench_v2.json';config=json.loads(path.read_text())
    config['cases'].append({'id':'cadets12','provider':'CADETS'})
    write_json(path,config)
    with monkeypatch.context() as patch:
        patch.setattr(api(),'_load_reference',lambda *_:pytest.fail('partial run reached labels without opt-in'))
        with pytest.raises(ValueError,match='missing|incomplete'):
            api().evaluate_run(frozen['run'])
    report=api().evaluate_run(frozen['run'],allow_partial=True)
    assert report['registered_cases']==2 and report['completed_cases']==1
    assert report['missing_case_ids']==['cadets12'] and report['partial_evaluation'] is True


def test_partial_mode_never_accepts_unfinished_registration(frozen, monkeypatch):
    directory=frozen['run']/'cadets12';directory.mkdir()
    write_json(directory/'registration.json',{'labels_opened':False})
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('unfinished partial run reached labels'))
    with pytest.raises(ValueError,match='unfinished|incomplete'):
        api().evaluate_run(frozen['run'],allow_partial=True)


def test_reference_hash_tracks_changed_labels_without_changing_source_snapshot(frozen):
    first=api().evaluate_run(frozen['run'])
    assert first['registered_cases']==first['completed_cases']==1
    assert first['missing_case_ids']==[] and first['partial_evaluation'] is False
    case=first['cases'][0]
    assert case['reference_sha256']==digest(frozen['reference'])
    assert len(case['source_positive_snapshot_sha256'])==64
    assert case['source_positive_snapshot_sha256']==case['source_positive_graph_sha256']
    assert first['evaluation_provenance']['evaluator_sha256']==digest(api().__file__)
    value=json.loads(frozen['reference'].read_text());value['attack_event_ids'].append('SECRET_ADDITIONAL_MISSING')
    write_json(frozen['reference'],value)
    second=api().evaluate_run(frozen['run'])['cases'][0]
    assert second['reference_sha256']!=case['reference_sha256']
    assert second['source_positive_snapshot_sha256']==case['source_positive_snapshot_sha256']


def test_source_positive_snapshot_hash_changes_if_source_event_changes(frozen):
    import sqlite3
    first=api().evaluate_run(frozen['run'])['cases'][0]
    database=Path(frozen['registration']['data_root'])/'source.db'
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE edges SET relation='EVENT_READ' WHERE event_id='SECRET_EVENT_B'")
    second=api().evaluate_run(frozen['run'])['cases'][0]
    assert second['source_positive_snapshot_sha256']!=first['source_positive_snapshot_sha256']
    assert second['reference_sha256']==first['reference_sha256']


def test_fixed_reference_summary_counts_overlap_singletons_and_lineage(frozen):
    import sqlite3
    database=Path(frozen['registration']['data_root'])/'source.db'
    with sqlite3.connect(database) as conn:
        # The existing noise event becomes a labelled singleton. The LINEAGE
        # positive now exists in the source and continues the first path.
        conn.execute("UPDATE edges SET src='P0',dst='P0' WHERE event_id='SECRET_NOISE'")
        conn.execute("INSERT INTO edges(event_id,src,dst,relation,timestamp_ns,host) VALUES(?,?,?,?,?,?)",
                     ('LINEAGE_SECRET_EVENT','P3','P4','EVENT_WRITE',103,'SECRET_HOST'))
    value=json.loads(frozen['reference'].read_text());value['attack_event_ids'].append('SECRET_NOISE')
    write_json(frozen['reference'],value)
    summary=api().evaluate_run(frozen['run'])['cases'][0]['fixed_reference_summary']
    assert summary=={'chain_count':1,'covered_positive_events':4,'singleton_positive_events':1,
                     'min_chain_events':4,'max_chain_events':4,'paths_are_exhaustive':False,
                     'paths_containing_synthetic_lineage':1,'independent_attack_count':None}


def test_resource_metrics_are_allowlisted_and_missing_values_stay_null(frozen):
    path=frozen['folder']/'case.json';case=json.loads(path.read_text())
    case.update(elapsed_seconds=42.25,peak_rss_mib=512.5)
    write_json(path,case)
    resign_variant(frozen,'single',lambda directory,manifest:manifest['diagnostics']['rarity_only@2'].update(
        selected_bundle_ids=['SECRET_BUNDLE_ID'],private_note='SECRET_PRIVATE_DIAGNOSTIC'))
    report=api().evaluate_run(frozen['run']);case=report['cases'][0]
    assert case['elapsed_seconds']==42.25 and case['peak_rss_mib']==512.5
    for variant in case['variants']:
        manifest=json.loads((frozen['folder']/variant['track']/variant['poi_policy']/'manifest.json').read_text())
        assert variant['online_seconds']==manifest['online_seconds']
        for point in variant['rows']:
            diagnostic=manifest['diagnostics'][f"{point['method']}@{point['budget']}"]
            for field in ('unused_budget','anchor_limit_reached','truncated_bundles','retained_complete_bundles','fallback_witnesses'):
                assert point[field]==diagnostic.get(field)
    assert 'SECRET' not in json.dumps(report)


@pytest.mark.parametrize('field,value',[('elapsed_seconds',-1),('elapsed_seconds',True),
                                       ('peak_rss_mib',float('nan')),('peak_rss_mib','512')])
def test_invalid_case_resource_values_are_rejected_before_labels(frozen,monkeypatch,field,value):
    path=frozen['folder']/'case.json';case=json.loads(path.read_text());case[field]=value
    path.write_text(json.dumps(case))
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('bad resource value reached labels'))
    with pytest.raises(ValueError,match='resource|elapsed|rss'):
        api().evaluate_run(frozen['run'])


@pytest.mark.parametrize('field,value',[('fallback_witnesses',-1),('fallback_witnesses',True),
                                       ('truncated_bundles',1.5),('anchor_limit_reached',1)])
def test_invalid_optional_point_diagnostics_are_rejected_before_labels(frozen,monkeypatch,field,value):
    resign_variant(frozen,'single',lambda directory,manifest:manifest['diagnostics']['rarity_only@2'].update({field:value}))
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('bad point resource value reached labels'))
    with pytest.raises(ValueError,match='resource|witness|bundle|anchor'):
        api().evaluate_run(frozen['run'])


def test_unavailable_reference_hashes_and_path_summary_are_null(frozen):
    change_registration(frozen,lambda r:r['case'].update(reference={'kind':'unavailable'}))
    case=api().evaluate_run(frozen['run'])['cases'][0]
    assert case['reference_sha256'] is None and case['source_positive_snapshot_sha256'] is None
    assert case['fixed_reference_summary']['chain_count'] is None
    assert case['fixed_reference_summary']['covered_positive_events'] is None


def test_plot_discloses_reference_coverage_and_synthetic_path_dependence(frozen):
    from scripts.plot_chain_workbench import _case_figure
    import matplotlib.pyplot as plt
    case=api().evaluate_run(frozen['run'])['cases'][0]
    case['fixed_reference_summary'].update(chain_count=3,covered_positive_events=4,
        singleton_positive_events=27,paths_containing_synthetic_lineage=3)
    figure=_case_figure(case,metric='reference_chain_retention',xfield='compression')
    text=' '.join(item.get_text() for item in figure.texts)
    assert '4 covered positives' in text and '27 singleton positives' in text
    assert 'All reference paths depend on synthetic LINEAGE' in text
    plt.close(figure)


def test_overview_uses_only_base_declared_without_averaging(frozen):
    from scripts.plot_chain_workbench import _overview_figure
    import matplotlib.pyplot as plt
    report=api().evaluate_run(frozen['run'])
    for variant in report['cases'][0]['variants']:
        for point in variant['rows']:
            point['reference_chain_retention']=.73 if (variant['track'],variant['poi_policy'])==('base','declared') else .04
    figure=_overview_figure(report)
    assert len(figure.axes[0].lines)==len(METHODS)
    assert all(set(line.get_ydata())=={.73} for line in figure.axes[0].lines)
    assert any('Same base candidates and declared POIs' in text.get_text() for text in figure.texts)
    plt.close(figure)


def test_overview_marks_synthetic_dependence_and_unavailable_reference(frozen):
    from scripts.plot_chain_workbench import _overview_figure
    import matplotlib.pyplot as plt
    report=api().evaluate_run(frozen['run'])
    trace=deepcopy(report['cases'][0]);trace['id']='trace-case5-paper'
    trace['fixed_reference_summary'].update(chain_count=3,covered_positive_events=4,
        singleton_positive_events=27,paths_containing_synthetic_lineage=3)
    missing=deepcopy(report['cases'][0]);missing['id']='theia-case5'
    missing['fixed_reference_summary'].update(chain_count=None,covered_positive_events=None,singleton_positive_events=None)
    for variant in missing['variants']:
        for point in variant['rows']:
            point['reference_chain_count']=None;point['reference_chain_retention']=None
    report['cases']=[trace,missing]
    figure=_overview_figure(report)
    assert any('All reference paths depend on synthetic LINEAGE' in text.get_text() for text in figure.axes[0].texts)
    assert not figure.axes[1].lines
    assert any('N/A' in text.get_text() for text in figure.axes[1].texts)
    plt.close(figure)


def test_empty_started_case_directory_is_rejected_by_shared_global_validator(frozen,monkeypatch):
    path=frozen['root']/'configs/chain_workbench_v2.json';config=json.loads(path.read_text())
    config['cases'].append({'id':'cadets12','provider':'CADETS'});write_json(path,config)
    (frozen['run']/'cadets12').mkdir()
    monkeypatch.setattr(api(),'_load_reference',lambda *_:pytest.fail('empty started case reached labels'))
    with pytest.raises(ValueError,match='unfinished|incomplete'):
        api()._validate_all(frozen['run'])
    with pytest.raises(ValueError,match='unfinished|incomplete'):
        api().evaluate_run(frozen['run'],allow_partial=True)


def test_auxiliary_output_directories_are_not_misread_as_unfinished_cases(frozen):
    (frozen['run']/'figures').mkdir();(frozen['run']/'exports').mkdir()
    assert api().evaluate_run(frozen['run'])['completed_cases']==1
