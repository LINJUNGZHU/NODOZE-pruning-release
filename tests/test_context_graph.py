import copy
import pytest
from tc_pruning.optc import parse_event


def edge(eid,sec,actor,target,obj='FILE',action='WRITE'):
    return parse_event(dict(id=eid,hostname='test',timestamp=f'2019-09-23T11:20:{sec:02d}-04:00',actorID=actor,objectID=target,
        object=obj,action=action,pid=1,properties={}))


def fixture():
    edges=[edge('birth',1,'parent','attack','PROCESS','CREATE'),edge('w1',2,'attack','payload'),edge('w2',3,'attack','payload'),
           edge('r1',4,'reader','payload','FILE','READ'),edge('hub',5,'attack','shared')]
    edges += [edge('noise'+str(i),10+i,'normal'+str(i),'shared','FILE','READ') for i in range(6)]
    report=dict(nodes=[dict(id='attack',predicted_attack=True,evidence_event_ids=['birth'],rule_witness={'active_since_ns':edges[0]['timestamp_ns']})],
                evidence_event_ids=['birth'],path_event_ids=[],activity_event_ids=['birth','w1','w2','hub'],contract={'truth_used':False})
    return report,edges


def test_context_preserves_witnesses_but_stops_shared_resource_fanout():
    from tc_pruning.context_graph import build_context,verify_context
    report,edges=fixture();c=build_context(report,edges)
    assert {'birth','w1','w2','r1','hub'}<=set(c['event_ids'])
    assert not any(i.startswith('noise') for i in c['event_ids'])
    assert 'reader' in c['context_process_ids'] and c['predicted_process_ids']==['attack']
    assert verify_context(c,report,edges)


def test_bundles_are_reversible_without_collapsing_event_count():
    from tc_pruning.context_graph import build_context
    report,edges=fixture();c=build_context(report,edges)
    bundle=next(b for b in c['bundles'] if set(b['event_ids'])=={'w1','w2'})
    assert bundle['event_count']==2
    assert sorted(i for b in c['bundles'] for i in b['event_ids'])==sorted(c['event_ids'])


def test_context_rejects_missing_evidence_and_has_no_truth_dependency():
    from tc_pruning.context_graph import build_context,verify_context
    report,edges=fixture();c=build_context(report,edges)
    changed=copy.deepcopy(report);changed['evaluation']={'labels':{'normal':True}};assert build_context(changed,edges)==c
    bad=copy.deepcopy(c);bad['event_ids'].remove('birth')
    with pytest.raises(ValueError,match='context'):verify_context(bad,report,edges)
    with pytest.raises(ValueError,match='evidence'):build_context(report,edges[1:])


def test_context_does_not_go_backwards_or_expand_from_open_only():
    from tc_pruning.context_graph import build_context
    report,edges=fixture();edges += [edge('before',1,'early','payload','FILE','READ'),edge('open',6,'attack','opened','FILE','OPEN'),edge('open-reader',7,'other','opened','FILE','READ')]
    c=build_context(report,edges)
    assert 'before' not in c['event_ids'] and 'open-reader' not in c['event_ids']


def test_attack_export_accepts_extra_context_reader_events():
    from tc_pruning.attack_inference import infer_attack
    from tc_pruning.context_graph import build_context
    from webapp.scripts.verify_attack_report import verify
    es=[parse_event(dict(id='birth',hostname='test',timestamp='2019-09-23T11:20:01-04:00',actorID='parent',objectID='attack',
        object='PROCESS',action='CREATE',pid=2,ppid=1,properties={'image_path':'powershell.exe','command_line':'powershell -enc AAA -w Hidden'})),
        edge('net',2,'attack','socket','FLOW','START'),edge('write',3,'attack','payload'),edge('read',4,'other','payload','FILE','READ')]
    es[1]['raw']['properties']['direction']='outbound'
    report=infer_attack(es,'birth');c=build_context(report,es)
    assert 'read' in c['event_ids'] and 'read' not in report['activity_event_ids']
    result=verify(dict(attack=report,context_graph=c,events=es))
    assert result['context_bundle_references_verified']


def test_multiview_full_scoring_context_is_preserved():
    from tc_pruning.context_graph import build_context
    report,edges=fixture();report['context_event_ids']=['noise0']
    c=build_context(report,edges)
    assert 'noise0' in c['required_event_ids'] and 'noise0' in c['event_ids']
