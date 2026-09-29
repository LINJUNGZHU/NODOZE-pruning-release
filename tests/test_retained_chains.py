from collections import Counter
import csv
import hashlib
import importlib.util
import json
import xml.etree.ElementTree as ET

import numpy as np
import pytest


def module():
    assert importlib.util.find_spec('tc_pruning.retained_chains') is not None, 'retained graph export is not implemented'
    from tc_pruning import retained_chains
    return retained_chains


def rows():
    return [dict(event_id=e,src=a,dst=b,relation=r,timestamp_ns=t,host='host',
                 src_type='process',dst_type='file',src_semantic=a+'<&',dst_semantic=b,
                 is_declared_poi=i==0)
            for i,(e,a,b,r,t) in enumerate([
                ('E1','A','B','WRITE',1523028000000000001),
                ('E2','B','C','WRITE',1523028000000000002),
                ('E3','B','D','WRITE',1523028000000000002),
                ('E4','C','E','WRITE',1523028000000000003),
                ('SINGLE','X','Y','WRITE',1523028000000000004)])]


def build(source=None, mask=None, **kwargs):
    source=rows() if source is None else source
    mask=np.ones(len(source),bool) if mask is None else mask
    return module().build_retained_artifact(source,mask,case_id='test',method='adaptive',budget_edges=len(source),**kwargs)


def test_export_event_union_equals_selection_and_includes_isolated_edges():
    artifact=build(mask=np.array([True,True,False,True,True]))
    assert {r['event_id'] for r in artifact['events']}=={'E1','E2','E4','SINGLE'}
    assert artifact['retained_edges']==4 and artifact['candidate_edges']==5
    cover=[i for path in artifact['paths'] for i in path['event_indices']]
    assert Counter(cover)==Counter(range(4))
    assert any(path['event_ids']==['SINGLE'] and path['singleton'] for path in artifact['paths'])
    assert all(type(r['timestamp_ns']) is str for r in artifact['events'])
    assert artifact['actual_compression']==pytest.approx(.2)


def test_branching_and_equal_time_never_form_a_fake_single_directed_path():
    source=rows();source.append(dict(source[0],event_id='SAME_TIME',src='C',dst='BAD',timestamp_ns=source[1]['timestamp_ns']))
    artifact=build(source)
    for path in artifact['paths']:
        event_rows=[artifact['events'][i] for i in path['event_indices']]
        assert all(a['causal_dst']==b['causal_src'] and int(a['timestamp_ns'])<int(b['timestamp_ns']) for a,b in zip(event_rows,event_rows[1:]))
    assert all(not {'E2','E3'}<=set(p['event_ids']) for p in artifact['paths'])


def test_execute_retains_raw_direction_and_reverses_only_causal_direction():
    source=rows()[:2];source[0].update(src='B',dst='A',relation='EVENT_EXECUTE')
    artifact=build(source)
    event=artifact['events'][0]
    assert (event['src'],event['dst'])==('B','A')
    assert (event['causal_src'],event['causal_dst'])==('A','B')
    assert event['causal_direction']=='dst_to_src'
    assert artifact['paths'][0]['event_ids']==['E1','E2']


def test_path_cover_does_not_merge_identical_entities_on_different_hosts():
    source=rows()[:2];source[1]['host']='other-host'
    artifact=build(source)
    assert len(artifact['paths'])==2
    assert len(artifact['nodes'])==4


def test_export_stable_under_input_permutation_and_ignores_labels():
    source=rows();a=build(source,scores=np.arange(5,dtype=float))
    order=[4,2,0,3,1]
    changed=[dict(source[i],groundtruth='secret',attack_label=True) for i in order]
    b=build(changed,scores=np.arange(5,dtype=float)[order])
    assert a==b
    assert 'groundtruth' not in json.dumps(a)


@pytest.mark.parametrize('mask', [[1,1,1,1,1],[True],[[True]*5],[False]*4+[None]])
def test_malformed_selection_mask_is_rejected(mask):
    with pytest.raises(ValueError,match='mask'):
        build(mask=mask)


@pytest.mark.parametrize('timestamp', [True,1.5,1.0,'1.1',None])
def test_noninteger_source_timestamps_are_rejected(timestamp):
    source=rows();source[0]['timestamp_ns']=timestamp
    with pytest.raises(ValueError,match='timestamp'):
        build(source)


def test_duplicate_identity_and_infeasible_budgets_fail():
    source=rows();source[1]['event_id']=source[0]['event_id']
    with pytest.raises(ValueError,match='duplicate'):
        build(source)
    with pytest.raises(ValueError,match='budget'):
        module().build_retained_artifact(rows(),np.ones(5,bool),case_id='test',method='m',budget_edges=4)
    with pytest.raises(ValueError,match='score'):
        build(scores=[0,0,0,float('nan'),0])


def test_empty_selection_has_empty_graph_and_undefined_zero_candidate_compression():
    a=build(mask=np.zeros(5,bool))
    assert a['events']==a['paths']==a['nodes']==[]
    b=module().build_retained_artifact([],[],case_id='empty',method='m',budget_edges=0)
    assert b['actual_compression'] is None


def test_only_fully_retained_bundles_export_with_remapped_indices():
    source=rows();order=[4,0,2,1,3];source=[source[i] for i in order]
    bundles=[{'id':'whole','event_indices':[1,3,4], 'paths':[[1,3,4]],'complete_in_candidate':True},
             {'id':'partial','event_indices':[1,2],'paths':[[1],[2]],'complete_in_candidate':False}]
    a=build(source,mask=np.array([True,True,False,True,True]),bundles=bundles)
    assert len(a['observed_bundles'])==1
    b=a['observed_bundles'][0]
    assert b['event_indices']==[0,1,2]
    assert b['paths']==[[0,1,2]]
    assert b['scope']=='observed_witness_only_not_complete_attack'


def test_malformed_or_noncausal_bundle_never_exported_as_valid_witness():
    with pytest.raises(ValueError,match='bundle'):
        build(bundles=[{'id':'bad','event_indices':[0,2], 'paths':[[0,2,1]],'complete_in_candidate':True}])
    with pytest.raises(ValueError,match='bundle'):
        build(bundles=[{'id':'bad','event_indices':[1,2], 'paths':[[1,2]],'complete_in_candidate':True}])


def test_writer_roundtrips_json_csv_graphml_hashes_and_refuses_overwrite(tmp_path):
    artifact=build();target=tmp_path/'export';manifest=module().write_retained_export(target,artifact)
    assert json.loads((target/'retained-graph.json').read_text())==artifact
    with (target/'retained-events.csv').open(newline='') as f:
        csv_rows=list(csv.DictReader(f))
    assert {r['event_id'] for r in csv_rows}=={r['event_id'] for r in artifact['events']}
    assert csv_rows[0]['timestamp_ns']=='1523028000000000001'
    tree=ET.parse(target/'retained-graph.graphml');ns={'g':'http://graphml.graphdrawing.org/xmlns'}
    assert len(tree.findall('.//g:edge',ns))==5
    assert any('<&' in (d.text or '') for d in tree.findall('.//g:data',ns))
    for filename,digest in manifest['artifacts'].items():
        assert hashlib.sha256((target/filename).read_bytes()).hexdigest()==digest
    before={p.name:p.read_bytes() for p in target.iterdir()}
    with pytest.raises(FileExistsError):module().write_retained_export(target,artifact)
    assert before=={p.name:p.read_bytes() for p in target.iterdir()}


def test_frozen_export_roundtrip_and_tamper_rejection(tmp_path):
    assert importlib.util.find_spec('scripts.export_retained_chains') is not None
    from scripts import export_retained_chains as cli
    from scripts import run_adaptive_chains as runner
    data=runner.synthetic_case(6,noise_count=40,chain_count=1)
    online=runner.run_online(data['rows'],data['history'],data['cutoff_ns'],[.2],max_anchors=32)
    frozen=tmp_path/'frozen';runner.freeze_online(frozen,data['rows'],online)
    output=tmp_path/'export'
    assert cli.main(['--frozen',str(frozen),'--method','adaptive','--budget','.2','--output',str(output),'--case-id','synthetic'])==0
    artifact=json.loads((output/'retained-graph.json').read_text())
    expected={row['event_id'] for row,kept in zip(data['rows'],online['masks']['adaptive@0.2']) if kept}
    assert {row['event_id'] for row in artifact['events']}==expected
    assert artifact['frozen_source']['validation']['valid'] is True
    path=frozen/'decisions.npz';path.write_bytes(path.read_bytes()+b'tamper')
    with pytest.raises(ValueError,match='hash'):
        cli.main(['--frozen',str(frozen),'--method','adaptive','--budget','.2','--output',str(tmp_path/'bad')])
    assert not (tmp_path/'bad').exists()
