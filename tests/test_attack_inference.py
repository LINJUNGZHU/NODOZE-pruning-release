import copy

import pytest

from tc_pruning.attack_inference import infer_attack, temporal_paths, check_path, process_metadata, command_signals
from tc_pruning.attack_evaluation import node_metrics
from tc_pruning.optc import parse_event


def event(id, second, actor, target, obj='FLOW', action='START', pid=2, props=None):
    raw=dict(id=id,hostname='test',timestamp=f'2019-09-23T11:20:{second:02d}-04:00',
             actorID=actor,objectID=target,object=obj,action=action,pid=pid,ppid=1,
             properties=props or dict(image_path='worker.exe',direction='outbound',dest_ip='203.0.113.5',dest_port='80'))
    e=parse_event(raw)
    e.update(evidence_score=.6,historical_count=0,decision=dict(certified_background_lift=True,temporal_witness=True))
    return e


def fixture():
    return [event('birth',1,'parent','child','PROCESS','CREATE',props=dict(image_path='powershell.exe',parent_image_path='parent.exe',command_line='powershell -enc AAA -w Hidden')),
            event('flow',2,'child','socket'),event('poi',3,'child','socket2')]


def stable(report):
    return {k:v for k,v in report.items() if k!='runtime_seconds'}


def test_behaviour_requires_followup_and_does_not_taint_parent_or_resource():
    edges=fixture();a=infer_attack(edges,'poi')
    assert {n['id'] for n in a['nodes'] if n['predicted_attack']}=={'child'}
    assert 'parent' in a['connector_node_ids']
    assert 'socket' in a['resource_node_ids']
    assert all(n['id'] not in ('socket','socket2') for n in a['nodes'])
    assert not infer_attack([edges[0]],'birth')['summary']['inferred_attack_nodes']
    # Equal-time outbound traffic cannot corroborate a creation event.
    edges[1]['timestamp_ns']=edges[0]['timestamp_ns']
    assert not infer_attack(edges[:2],'birth')['summary']['inferred_attack_nodes']


def test_seed_is_not_an_automatic_detection_and_uniform_scores_abstain():
    a=infer_attack([event('poi',1,'normal','socket')],'poi')
    n=a['nodes'][0]
    assert n['seed_node'] and not n['predicted_attack']
    assert not a['paths']


def test_detection_is_independent_of_retention_labels_order_and_duplicate_family():
    edges=fixture();a=infer_attack(edges,'poi')
    changed=copy.deepcopy(edges)
    for e in changed:
        e.update(retained=False,score=999,reference_evidence=['FAKE MALICIOUS'])
    assert stable(a)==stable(infer_attack(list(reversed(changed)),'poi'))
    duplicate=copy.deepcopy(edges[1]);duplicate['id']='duplicate';duplicate['timestamp_ns']+=1
    b=infer_attack(edges+[duplicate],'poi')
    assert [(n['id'],n['anomaly_score'],n['family_count'],n['predicted_attack']) for n in a['nodes']]==[(n['id'],n['anomaly_score'],n['family_count'],n['predicted_attack']) for n in b['nodes']]


def test_process_identity_on_creation_is_child_not_parent():
    m=process_metadata(fixture())
    assert m['parent']['pids']==[1] and m['child']['pids']==[2]
    assert m['parent']['images']==['parent.exe']


@pytest.mark.parametrize('command',['powershell -Encoding UTF8 -w Hidden','powershell -enc AAA','powershell -w Hidden'])
def test_single_command_feature_is_not_full_behavior(command):
    r=fixture()[0]['raw'];r['properties']['command_line']=command
    assert len(command_signals(r))<2


def test_temporal_paths_preserve_direction_time_and_ignore_process_open():
    edges=[event('a',1,'p','q','PROCESS','CREATE'),event('b',1,'q','r','PROCESS','CREATE'),
           event('c',2,'q','s','PROCESS','OPEN'),event('d',3,'q','t','PROCESS','CREATE'),
           event('reverse',4,'z','p','PROCESS','CREATE')]
    paths=temporal_paths(edges,'p',0)
    assert paths['t']==('a','d') and 'r' not in paths and 's' not in paths and 'z' not in paths
    by_id={e['id']:e for e in edges}
    assert check_path(['a','d'],by_id)
    assert not check_path(['a','b'],by_id)
    assert not check_path(['d','a'],by_id)
    assert not check_path(['a','c'],by_id)


def test_temporal_reachability_matches_independent_exhaustive_search():
    edges=[event('a',1,'p','q','PROCESS','CREATE'),event('b',2,'q','r','PROCESS','CREATE'),
           event('c',3,'r','p','PROCESS','CREATE'),event('d',2,'q','s','PROCESS','CREATE'),
           event('e',4,'s','z','PROCESS','CREATE')]
    reachable={'p'}
    def walk(node,when):
        for e in edges:
            if e['source']==node and e['timestamp_ns']>when:
                reachable.add(e['target']);walk(e['target'],e['timestamp_ns'])
    walk('p',0)
    assert set(temporal_paths(edges,'p',0))==reachable


def test_unknown_labels_are_not_false_positives_or_true_negatives():
    m=node_metrics(['a','b','c'],['a','b'],{'a':True})
    assert m['tp']==1 and m['fp']==0 and m['tn']==0 and m['unreviewed_predictions']==1
    assert m['precision'] is None and m['accuracy'] is None and m['f1'] is None
    assert m['precision_bounds']==[.5,1.] and m['known_positive_recall']==1


def test_complete_labels_produce_correct_confusion_matrix():
    m=node_metrics(['a','b','c','d'],['a','b'],dict(a=True,b=False,c=True,d=False))
    assert (m['tp'],m['fp'],m['fn'],m['tn'])==(1,1,1,1)
    assert m['precision']==m['recall']==m['f1']==m['accuracy']==.5


@pytest.mark.parametrize('quantile',[0,1,True,'0.9',float('nan')])
def test_invalid_node_threshold_is_rejected(quantile):
    with pytest.raises(ValueError,match='anomaly_quantile'):infer_attack(fixture(),'poi',dict(anomaly_quantile=quantile))


def test_downloaded_path_audit_detects_tampering():
    from webapp.scripts.verify_attack_report import verify
    es=fixture();a=infer_attack(es,'poi');ids=set(a['path_event_ids'])|set(a['evidence_event_ids'])|set(a['activity_event_ids'])
    doc=dict(attack=a,events=[e for e in es if e['id'] in ids])
    assert verify(doc)['strict_temporal_paths_verified']
    tampered=copy.deepcopy(doc);tampered['attack']['paths'][0]['event_ids'].reverse()
    with pytest.raises(ValueError):verify(tampered)
    tampered=copy.deepcopy(doc);tampered['events'][0]['timestamp_ns']+=1
    with pytest.raises(ValueError,match='raw record'):verify(tampered)


def test_public_label_import_preserves_granularity_and_checks_event_identity(tmp_path):
    import json
    import zipfile
    from webapp.scripts.prepare_attack_reference import build
    edges=fixture()
    tasks=[dict(hostname='test',object_id='child',event_id='birth',labels=['malicious','process']),
           dict(hostname='test',object_id='parent',event_id='birth',labels=['malicious','event']),
           dict(hostname='test',object_id='parent',event_id='birth',labels=['malicious','process','invalid'])]
    with zipfile.ZipFile(tmp_path/'tasks.zip','w') as z:z.writestr('tasks.json',json.dumps(tasks))
    with zipfile.ZipFile(tmp_path/'malicious.zip','w') as z:z.writestr('malicious.json',json.dumps(edges[1]['raw'])+'\n')
    report=build(dict(edges=edges),tmp_path)
    assert report['node_labels']==dict(child=True,parent=False)
    assert report['malicious_event_ids']==['flow']
    altered=copy.deepcopy(edges[1]['raw']);altered['actorID']='wrong-process'
    with zipfile.ZipFile(tmp_path/'malicious.zip','w') as z:z.writestr('malicious.json',json.dumps(altered)+'\n')
    with pytest.raises(ValueError,match='disagree'):build(dict(edges=edges),tmp_path)


def test_public_benchmark_does_not_apply_to_another_window(tmp_path,monkeypatch):
    import json
    import hashlib
    import tc_pruning.attack_evaluation as evaluation
    es=fixture();report=infer_attack(es,'poi')
    source=tmp_path/'labels.json'
    source.write_text(json.dumps(dict(scope=dict(event_ids_sha256='different-window',process_ids_sha256='different-processes'))))
    monkeypatch.setattr(evaluation,'PUBLIC_LABELS',source)
    assert 'published_benchmark' not in evaluation.evaluate_attack(report,es)


def chain_fixture():
    return [
        event('shell',0,'desktop','launcher','PROCESS','CREATE',props=dict(image_path='cmd.exe',parent_image_path='explorer.exe',command_line='cmd /c arbitrary-script.cmd')),
        event('helper',1,'launcher','console','PROCESS','CREATE',props=dict(image_path='console-helper.exe',parent_image_path='cmd.exe')),
        event('root',2,'launcher','agent','PROCESS','CREATE',props=dict(image_path='powershell.exe',parent_image_path='cmd.exe',command_line='powershell -enc XYZ -w Hidden')),
        event('network',3,'agent','socket'),
        event('discovery',4,'agent','tool','PROCESS','CREATE',props=dict(image_path='arbitrary-tool.exe',parent_image_path='powershell.exe')),
        event('unrelated-open',5,'agent','service','PROCESS','OPEN'),
    ]


def test_lineage_recovers_launcher_helpers_and_tools_without_tainting_desktop():
    from webapp.scripts.verify_attack_report import verify
    es=chain_fixture();report=infer_attack(es,'network');pred={n['id'] for n in report['nodes'] if n['predicted_attack']}
    assert pred=={'agent','launcher','console','tool'}
    assert not {'desktop','socket','service'} & pred
    assert report['rule_summary']==dict(strong_roots=1,launchers=1,descendants=2,review_only=0,policy=report['contract']['classification'])
    ids=set(report['evidence_event_ids'])|set(report['path_event_ids'])|set(report['activity_event_ids'])
    doc=dict(attack=report,events=[e for e in es if e['id'] in ids])
    assert verify(doc)['rule_witnesses_verified']
    tampered=copy.deepcopy(doc)
    next(n for n in tampered['attack']['nodes'] if n['id']=='tool')['rule_witness']['active_since_ns']-=1
    with pytest.raises(ValueError,match='lineage target'):verify(tampered)


def test_lineage_enforces_time_depth_and_does_not_merge_same_pid():
    es=chain_fixture();es.append(event('grandchild',5,'tool','grandchild','PROCESS','CREATE'))
    report=infer_attack(es,'network',dict(lineage_depth=1))
    assert 'grandchild' not in {n['id'] for n in report['nodes'] if n['predicted_attack']}
    es[-1]['timestamp_ns']=es[4]['timestamp_ns']
    report=infer_attack(es,'network');assert not next(n for n in report['nodes'] if n['id']=='grandchild')['predicted_attack']
    es[4]['timestamp_ns']=es[2]['timestamp_ns']+601_000_000_000
    report=infer_attack(es,'network');assert not next(n for n in report['nodes'] if n['id']=='tool')['predicted_attack']
    es=chain_fixture();es[2]['timestamp_ns']=es[0]['timestamp_ns']+121_000_000_000;es[3]['timestamp_ns']=es[2]['timestamp_ns']+1
    assert not next(n for n in infer_attack(es,'network')['nodes'] if n['id']=='launcher')['predicted_attack']


def test_rule_v2_ignores_poi_gating_and_does_not_promote_anomaly_alone():
    es=chain_fixture()
    for e in es:e['decision']['temporal_witness']=False
    report=infer_attack(es,'unrelated-open')
    assert {n['id'] for n in report['nodes'] if n['predicted_attack']}=={'agent','launcher','console','tool'}
    clean=[event(f'{actor}-{j}',j,actor,f'{actor}-flow-{j}',props=dict(image_path=actor+'.exe',dest_ip=f'203.0.113.{j}',dest_port='80',direction='outbound')) for actor in ['a','b'] for j in range(1,4)]
    for e in clean:e['evidence_score']=.9 if e['raw']['actorID']=='a' else .1
    old=infer_attack(clean,'a-1',detector='rules_legacy');new=infer_attack(clean,'a-1')
    assert old['summary']['inferred_attack_nodes']==1
    assert new['summary']['inferred_attack_nodes']==0
    assert new['rule_summary']['review_only']==1


def test_labels_and_specific_ids_cannot_be_used_as_rules():
    es=chain_fixture();first=infer_attack(es,'network')
    mapped={n:'renamed-'+n for e in es for n in (e['source'],e['target'])};altered=[]
    for e in es:
        raw=copy.deepcopy(e['raw']);raw['id']='event-'+raw['id'];raw['actorID']=mapped[raw['actorID']];raw['objectID']=mapped[raw['objectID']]
        raw['pid']=98765;raw['ppid']=87654
        if raw['object']=='FLOW':raw['properties']['dest_ip']='198.51.100.17'
        raw['properties']['command_line']=raw['properties'].get('command_line','').replace('arbitrary-script.cmd','renamed-payload.bat')
        new=parse_event(raw);new.update(evidence_score=e['evidence_score'],historical_count=0,decision=e['decision'],reference_evidence=['fake label'])
        altered.append(new)
    second=infer_attack(altered,'event-network')
    assert {mapped[n['id']] for n in first['nodes'] if n['predicted_attack']}=={n['id'] for n in second['nodes'] if n['predicted_attack']}


def test_tapas_membership_is_separate_and_scope_bound(tmp_path,monkeypatch):
    import hashlib
    import json
    import tc_pruning.attack_evaluation as evaluation
    es=chain_fixture();report=infer_attack(es,'network')
    ids={e['id'] for e in es};nodes={n for e in es for n in (e['source'],e['target'])}
    digest=lambda values:hashlib.sha256('\n'.join(sorted(values)).encode()).hexdigest()
    path=tmp_path/'tapas.json';path.write_text(json.dumps(dict(source_path='fixture',source_sha256='abc',source_node_count=2,
        granularity='static membership',limitation='no timestamps',windows={digest(ids):dict(node_ids_sha256=digest(nodes),positive_node_ids=['agent','service'],matched_types=dict(process=2,file=0,flow=0))})))
    monkeypatch.setattr(evaluation,'TAPAS_LABELS',path)
    before=copy.deepcopy(report);result=evaluation.evaluate_attack(report,es)
    assert report==before  # truth cannot mutate a prediction
    m=result['tapas_benchmark']['node_metrics'];assert (m['tp'],m['fn'],m['fp'])==(1,1,3)
    assert result['tapas_benchmark']['full_attack_path_recall'] is None
    assert 'tapas_benchmark' not in evaluation.evaluate_attack(report,es[:-1])


def test_tapas_reference_export_rejects_invalid_ids_and_preserves_types(tmp_path):
    from webapp.scripts.prepare_tapas_reference import build
    a='00000000-0000-4000-8000-000000000001';b='00000000-0000-4000-8000-000000000002'
    source=tmp_path/'gt.txt';source.write_text(a+'\n'+b+'\n')
    data=dict(dataset=dict(id='fixture'),edges=[dict(id='e')],nodes=[dict(id=a,type='process'),dict(id=b,type='file')])
    result=build(source,[data]);scope=next(iter(result['windows'].values()))
    assert scope['matched_types']==dict(process=1,file=1,flow=0)
    assert result['source_node_count']==2
    source.write_text('bad-id\n')
    with pytest.raises(ValueError):build(source,[data])


def test_activity_output_is_complete_for_observed_lifetime_and_not_a_path():
    from webapp.scripts.verify_attack_report import verify
    es=chain_fixture()+[event('early',1,'agent','early-socket'),
                        event('end',5,'launcher','agent','PROCESS','TERMINATE'),
                        event('late',6,'agent','late-socket')]
    report=infer_attack(es,'network');activity=set(report['activity_event_ids'])
    assert {'root','network','discovery','helper','shell','end'}<=activity
    assert not {'early','late'}&activity
    assert 'unrelated-open' in activity  # actor activity does not label its target
    assert not next(n for n in report['nodes'] if n['id']=='service')['predicted_attack']
    ids=activity|set(report['evidence_event_ids'])|set(report['path_event_ids'])
    doc=dict(attack=report,events=[e for e in es if e['id'] in ids])
    assert verify(doc)['activity_membership_verified']
    bad=copy.deepcopy(doc);bad['attack']['activity_event_ids'].remove('network')
    with pytest.raises(ValueError,match='activity membership'):verify(bad)


def test_dead_process_cannot_spawn_a_new_inferred_descendant_or_corroborate():
    es=chain_fixture()+[event('end',3,'launcher','agent','PROCESS','TERMINATE')]
    # Death and the only network corroboration are simultaneous; later creation
    # cannot rescue the root. The shell/console cannot bootstrap themselves.
    report=infer_attack(es,'network')
    assert report['summary']['inferred_attack_nodes']==0
    es=chain_fixture()+[event('end',4,'launcher','tool','PROCESS','TERMINATE'),
                        event('posthumous',5,'tool','ghost','PROCESS','CREATE')]
    report=infer_attack(es,'network')
    assert not next(n for n in report['nodes'] if n['id']=='ghost')['predicted_attack']
