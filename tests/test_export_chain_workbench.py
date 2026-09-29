"""Export an actually frozen small v2 run, never recompute its selection."""
from __future__ import annotations
import csv
import gzip
import hashlib
import json
from pathlib import Path
import numpy as np
import pytest


@pytest.fixture
def frozen(tmp_path):
    from scripts.run_adaptive_chains import synthetic_case
    from tc_pruning.chain_workbench import prepare_evidence, run_variant, freeze_variant
    data=synthetic_case(81,noise_count=60,chain_count=2)
    offset=1_700_000_000_000_000_000
    for row in data['rows']+data['history']:
        row['timestamp_ns']+=offset
    cutoff=data['cutoff_ns']+offset
    evidence=prepare_evidence(data['rows'],data['history'],cutoff)
    online=run_variant(data['rows'],evidence,'adaptive',[16,24],max_anchors=32,max_pois=4)
    path=tmp_path/'frozen'
    manifest=freeze_variant(path,data['rows'],evidence,online,case_id='synthetic-export-v2',track='expanded',provenance={'kind':'synthetic-test-only'})
    return path,manifest


def exporter():
    from scripts.export_chain_workbench import export_frozen
    return export_frozen


def test_export_exact_frozen_mask_scores_timestamps_poi_roles_and_source(frozen,tmp_path):
    path,manifest=frozen
    with gzip.open(path/'candidates.json.gz','rt') as stream:rows=json.load(stream)
    with np.load(path/'decisions.npz',allow_pickle=False) as decisions:mask=decisions['reliability_chain@16'].copy()
    with np.load(path/'scores.npz',allow_pickle=False) as data:scores=data['reliability_chain'].copy()
    expected={r['event_id']:(r,float(scores[i])) for i,r in enumerate(rows) if mask[i]}
    before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}
    output=tmp_path/'out';result=exporter()(path,'reliability_chain',16,output)
    actual=json.loads((output/'retained-graph.json').read_text())
    assert {e['event_id'] for e in actual['events']}==set(expected)
    assert actual['retained_edges']==int(mask.sum())<=16
    for event in actual['events']:
        row,score=expected[event['event_id']]
        assert event['timestamp_ns']==row['timestamp_ns'] and isinstance(event['timestamp_ns'],str)
        assert int(event['timestamp_ns'])>2**53
        assert event['score']==score
        assert event['is_declared_poi']==row['is_declared_poi']
    assert {eid for p in actual['paths'] for eid in p['event_ids']}==set(expected)
    roles=actual['poi_roles']
    diagnostics=manifest['poi_diagnostics']
    assert roles['original_declared_event_ids']==diagnostics['original_declared_event_ids']
    assert roles['selected_event_ids']==diagnostics['selected_event_ids']
    assert roles['suggested_event_ids']==diagnostics['suggested_event_ids']
    assert roles['suggestions_are_verified_alerts'] is False
    assert set(roles['retained_original_declared_event_ids'])==set(diagnostics['original_declared_event_ids'])&set(expected)
    assert set(roles['retained_suggested_event_ids'])==set(diagnostics['suggested_event_ids'])&set(expected)
    source=actual['frozen_source']
    assert source['source_manifest_sha256']==before['manifest.json']
    assert source['case_id']=='synthetic-export-v2' and source['track']=='expanded' and source['poi_policy']=='adaptive'
    assert source['decision_key']=='reliability_chain@16' and source['validation']['valid']
    assert result['frozen_source']==source
    assert actual['reference_labels_used'] is False
    with (output/'retained-events.csv').open(newline='') as stream:csv_rows=list(csv.DictReader(stream))
    assert {r['event_id']:r['timestamp_ns'] for r in csv_rows}=={e['event_id']:e['timestamp_ns'] for e in actual['events']}
    assert before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}


@pytest.mark.parametrize('method,budget',[('unknown',16),('RELIABILITY_CHAIN',16),('reliability_chain',17),('reliability_chain',16.0),('reliability_chain',True),('reliability_chain','16')])
def test_absent_or_coerced_method_budget_rejected_without_output(frozen,tmp_path,method,budget):
    with pytest.raises(ValueError):exporter()(frozen[0],method,budget,tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_tampered_frozen_artifact_rejected_without_output(frozen,tmp_path):
    path,_=frozen
    p=path/'decisions.npz';p.write_bytes(p.read_bytes()+b'tampered')
    with pytest.raises(ValueError,match='hash'):exporter()(path,'reliability_chain',16,tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_refuses_overwrite_and_preserves_existing_export(frozen,tmp_path):
    output=tmp_path/'out';exporter()(frozen[0],'rarity_only',16,output)
    before={p.name:p.read_bytes() for p in output.iterdir()}
    with pytest.raises(FileExistsError):exporter()(frozen[0],'rarity_only',24,output)
    assert before=={p.name:p.read_bytes() for p in output.iterdir()}


def test_cli_uses_integer_budget_and_outputs_only_summary(frozen,tmp_path,capsys):
    from scripts.export_chain_workbench import main
    assert main(['--frozen',str(frozen[0]),'--method','rarity_only','--budget','16','--output',str(tmp_path/'out')])==0
    summary=json.loads(capsys.readouterr().out)
    assert summary['budget']==16 and summary['counts']['retained_events']<=16
    with pytest.raises(SystemExit):main(['--frozen',str(frozen[0]),'--method','rarity_only','--budget','0.2','--output',str(tmp_path/'other')])
