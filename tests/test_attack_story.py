import copy
import pytest
from tc_pruning.optc import parse_event
from tc_pruning.attack_inference import infer_attack


def fixture():
    def edge(eid, second, obj, action, actor, target, **props):
        return parse_event(dict(id=eid, hostname='test', timestamp=f'2019-09-23T11:20:{second:02d}-04:00',
            actorID=actor, objectID=target, object=obj, action=action, pid=2, ppid=1, properties=props))
    return [edge('birth',1,'PROCESS','CREATE','parent','child',image_path='powershell.exe',command_line='powershell -enc AAA -w Hidden'),
            edge('write',2,'FILE','WRITE','child','file'),
            edge('flow',3,'FLOW','START','child','socket',direction='outbound')]


def test_story_references_observations_without_inventing_attack_stages():
    report=infer_attack(fixture(),'birth')
    assert 'story' in report
    story=report['story']
    assert story['generator']=='deterministic_evidence_summary'
    assert {s['kind'] for s in story['stages']}=={'process_execution','file_activity','network_activity'}
    assert {i for s in story['stages'] for i in s['event_ids']}=={'birth','write','flow'}
    assert all(s['maliciousness_proven'] is False for s in story['stages'])


def test_story_verifier_rejects_fabricated_stage_or_omitted_evidence():
    from tc_pruning.attack_story import verify_story
    report=infer_attack(fixture(),'birth')
    assert verify_story(report,fixture())
    for field,value in [('kind','privilege_escalation'),('event_ids',['fake']),('event_count',999)]:
        changed=copy.deepcopy(report);changed['story']['stages'][0][field]=value
        with pytest.raises(ValueError,match='story'):verify_story(changed,fixture())


def test_multiview_predictions_are_not_overridden_by_rule_or_poi():
    scores=dict(model_id='test',threshold=4,calibration='frozen',fusion={},nodes={
        'child':dict(score=0.,predicted=False,votes=0,views={},flags=[False]*7,evidence_event_ids=[]),
        'parent':dict(score=5.,predicted=True,votes=5,views={},flags=[True]*5+[False]*2,evidence_event_ids=['birth'])})
    report=infer_attack(fixture(),'birth',detector='multiview',neural_scores=scores)
    assert {n['id'] for n in report['nodes'] if n['predicted_attack']}=={'parent'}
    assert report['threshold']['comparison']=='>='
    assert report['contract']['truth_used'] is False


def test_export_verifier_rejects_fabricated_view_reference():
    from webapp.scripts.verify_attack_report import verify
    edges=fixture();report=infer_attack(edges,'birth')
    node=next(n for n in report['nodes'] if n['predicted_attack'])
    node['multiview']=dict(views={k:dict(evidence_event_ids=['fabricated'] if k=='causal' else node['evidence_event_ids']) for k in ('attribute','structural','causal')},
                          evidence_event_ids=node['evidence_event_ids'],flags=[True]*7,votes=7,predicted=True)
    with pytest.raises(ValueError,match='view'):verify(dict(attack=report,events=edges))


def test_shared_context_is_exportable_and_cannot_change_target_time():
    from webapp.scripts.verify_attack_report import verify
    edges=fixture();minute=edges[0]['timestamp_ns']//60_000_000_000
    views={k:dict(score=1,percentile=1,evidence_event_ids=['birth','flow'],target_event_ids=[],context_scope=None)
           for k in ('attribute','structural','causal')}
    views['structural']['context_scope']=dict(minute=minute)
    views['causal'].update(evidence_event_ids=['flow'],target_event_ids=['flow'],context_scope=dict(minute=minute,before_ns=edges[-1]['timestamp_ns']))
    scores=dict(model_id='test',threshold=4,calibration='frozen',fusion={},
        context_index={str(minute):[[e['id'],e['timestamp_ns']] for e in edges]},
        nodes={'child':dict(score=7,predicted=True,votes=7,views=views,flags=[True]*7,evidence_event_ids=['birth','flow'])})
    report=infer_attack(edges,'birth',detector='multiview',neural_scores=scores)
    assert verify(dict(attack=report,events=edges))['multiview_references_verified']
    report['nodes'][0]['multiview']['views']['causal']['context_scope']['before_ns']+=1
    with pytest.raises(ValueError,match='cutoff'):verify(dict(attack=report,events=edges))
