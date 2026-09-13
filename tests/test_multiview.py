import copy
import numpy as np
import pytest

from tc_pruning.optc import parse_event


def event(eid, second, action='READ', obj='FILE', actor='p', target='f'):
    return parse_event(dict(id=eid, hostname='test', timestamp=f'2019-09-23T11:20:{second:02d}-04:00',
        actorID=actor, objectID=target, object=obj, action=action, pid=1, ppid=2,
        properties=dict(image_path='worker.exe', parent_image_path='parent.exe', command_line='worker test')))


def test_causal_input_excludes_target_action_and_same_timestamp_peers():
    from tc_pruning.multiview import causal_samples
    edges=[event('a',1),event('b',2,'WRITE'),event('c',2,'CREATE'),event('d',3)]
    first=causal_samples(edges)
    changed=copy.deepcopy(edges);changed[1]['relation']='FILE_DELETE';changed[1]['raw']['action']='DELETE'
    other=causal_samples(changed)
    np.testing.assert_array_equal(first['x'][:3],other['x'][:3])
    assert first['y'][1]!=other['y'][1]
    assert not np.array_equal(first['x'][3],other['x'][3])
    # Adding a future event cannot alter any earlier predictor input.
    np.testing.assert_array_equal(first['x'],causal_samples(edges+[event('z',59)])['x'][:4])


def test_structure_ignores_identity_and_text_but_uses_relation():
    from tc_pruning.multiview import structural_graphs
    edges=[event('a',1,'CREATE','PROCESS',target='q'),event('b',2,actor='q')]
    altered=copy.deepcopy(edges)
    for e in altered:
        e['raw']['properties']={'image_path':'renamed.exe','command_line':'anything'}
        e['raw']['pid']=999;e['reference_label']='attack'
    a,b=structural_graphs(edges)[0],structural_graphs(altered)[0]
    np.testing.assert_array_equal(a['x'],b['x'])
    np.testing.assert_array_equal(a['relations'],b['relations'])
    altered[0]['relation']='PROCESS_OPEN';altered[0]['raw']['action']='OPEN'
    assert not np.array_equal(a['relations'],structural_graphs(altered)[0]['relations'])


def test_fusion_constant_scores_abstain_and_novel_all_views_vote():
    from tc_pruning.multiview import calibrate_fusion,fusion_decision
    cal=calibrate_fusion(np.ones((30,3)))
    assert fusion_decision([1,1,1],cal)['votes']==0
    cal=calibrate_fusion(np.array([[i,i/2,i*2] for i in range(1,101)]))
    assert not fusion_decision([2,1,4],cal)['predicted']
    assert fusion_decision([200,100,400],cal)['predicted']
    with pytest.raises(ValueError):fusion_decision([float('nan'),1,2],cal)


def test_fit_model_roundtrip_checksum_and_temporal_guard(tmp_path):
    from tc_pruning.multiview import fit_model,score_nodes
    train=[event(str(i),i,'READ' if i%2 else 'WRITE') for i in range(1,10)]
    val=[event('v'+str(i),i,'READ' if i%2 else 'WRITE') for i in range(11,15)]
    cal=[event('c'+str(i),i,'READ' if i%2 else 'WRITE',actor='p'+str(i)) for i in range(16,25)]
    fit_model(train,val,cal,tmp_path,epochs=2)
    result=score_nodes([event('test',40)],tmp_path)
    assert set(result['nodes']['p']['views'])=={'attribute','structural','causal'}
    assert np.isfinite(result['nodes']['p']['score'])
    with pytest.raises(ValueError,match='overlap'):score_nodes(cal,tmp_path)
    with (tmp_path/'weights.pt').open('ab') as f:f.write(b'tamper')
    with pytest.raises(ValueError,match='checksum'):score_nodes([event('test',40)],tmp_path)


def test_rejects_stale_feature_manifest(tmp_path):
    import json
    from tc_pruning.multiview import fit_model,score_nodes
    fit_model([event('a',1),event('b',2)], [event('v',3)],
              [event('c',4,actor='p'),event('d',5,actor='q')],tmp_path,epochs=1)
    path=tmp_path/'manifest.json';manifest=json.loads(path.read_text())
    manifest['feature_sources']={'tc_pruning/multiview.py':'incompatible'};path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='feature'):score_nodes([event('t',40)],tmp_path)


def test_structural_and_causal_scores_include_context_inputs(tmp_path):
    from tc_pruning.multiview import fit_model,score_nodes,resolve_context
    fit_model([event('a',1),event('b',2)], [event('v',3)],
              [event('c',4,actor='p'),event('d',5,actor='q')],tmp_path,epochs=1)
    edges=[event('pq',30,'CREATE','PROCESS',target='q'),event('qr',31,'CREATE','PROCESS',actor='q',target='r'),
           event('remote',32,actor='r'),event('prior',33,actor='p'),event('target',34,actor='p')]
    report=score_nodes(edges,tmp_path);result=report['nodes']['p']
    assert 'remote' in resolve_context(result['views']['structural'],report['context_index'])
    causal=result['views']['causal'];target=causal['target_event_ids'][0]
    timestamp=next(e['timestamp_ns'] for e in edges if e['id']==target)
    required={e['id'] for e in edges if e['timestamp_ns']<timestamp}|{target}
    assert required<=set(resolve_context(causal,report['context_index']))


def test_context_is_shared_instead_of_repeated_for_every_process(tmp_path):
    from tc_pruning.multiview import fit_model,score_nodes
    fit_model([event('a',1),event('b',2)], [event('v',3)],
              [event('c',4,actor='p'),event('d',5,actor='q')],tmp_path,epochs=1)
    edges=[event(f't{i}',40,actor=f'p{i}') for i in range(20)]
    report=score_nodes(edges,tmp_path)
    assert 'context_index' in report
    assert sum(len(v) for v in report['context_index'].values())==20
    assert sum(len(v['evidence_event_ids']) for n in report['nodes'].values() for v in n['views'].values())<=120
