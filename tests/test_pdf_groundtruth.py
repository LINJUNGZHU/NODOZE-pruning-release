import copy
import pytest
from tc_pruning.optc import parse_event


def edge(eid='flow', actor='agent', host='Sysclient0201.systemia.com', pid=5452, when='11:25:00', **properties):
    return parse_event(dict(id=eid,hostname=host,timestamp=f'2019-09-23T{when}-04:00',actorID=actor,objectID=eid+'-object',
        pid=pid,object='FLOW',action='START',properties=dict(image_path='powershell.exe',dest_ip='132.197.158.98',dest_port=80,direction='outbound',**properties)))


def reference():
    return dict(source='test.pdf',sha256='test',agents=[dict(id='a',host='Sysclient0201',date='2019-09-23',pid=5452,
        c2_ip='132.197.158.98',page=1,excerpt='test',active_start='2019-09-23T11:24:54-04:00',active_end='2019-09-23T11:26:56-04:00')],artifacts=[],activities=[])


def test_pdf_resolver_keeps_host_and_time_scope_and_unknowns():
    from tc_pruning.pdf_groundtruth import resolve_pdf_reference
    r=resolve_pdf_reference([edge(),edge('other','other','Sysclient0202',5452),edge('early','early',when='09:00:00')],reference())
    assert r['labels']=={'agent':True}
    assert r['agents'][0]['status']=='resolved'
    assert 'other' not in r['labels'] and 'early' not in r['labels']


def test_pdf_does_not_merge_two_c2_actors_with_same_pid():
    from tc_pruning.pdf_groundtruth import resolve_pdf_reference
    r=resolve_pdf_reference([edge(),edge('duplicate','duplicate')],reference())
    assert r['labels']=={}
    assert r['agents'][0]['status']=='ambiguous'
    assert set(r['agents'][0]['candidate_node_ids'])=={'agent','duplicate'}


def test_attack_before_reference_start_is_not_confirmed_by_later_pid():
    from tc_pruning.pdf_groundtruth import resolve_pdf_reference
    r=resolve_pdf_reference([edge(when='10:59:00')],reference())
    assert r['labels']=={} and r['agents'][0]['status']=='outside_window'


def test_pdf_failed_injection_does_not_label_target():
    from tc_pruning.pdf_groundtruth import resolve_pdf_reference
    ref=reference();ref['activities']=[dict(kind='process_injection',outcome='failed',target='lsass',page=1)]
    r=resolve_pdf_reference([edge(),edge('target','lsass',pid=500)],ref)
    assert r['labels']=={'agent':True}
    assert r['activities'][0]['outcome']=='failed'


def test_reference_is_bound_to_actual_pdf_and_excerpts():
    from pathlib import Path
    import json
    from tc_pruning.pdf_groundtruth import validate_reference
    root=Path(__file__).resolve().parents[1];ref=json.loads((root/'poi/optc-pdf-reference.json').read_text())
    assert validate_reference(root/'OpTCRedTeamGroundTruth.pdf',ref)
    bad=copy.deepcopy(ref);bad['sha256']='0'*64
    with pytest.raises(ValueError,match='hash'):validate_reference(root/'OpTCRedTeamGroundTruth.pdf',bad)
    bad=copy.deepcopy(ref);bad['agents'][0]['excerpt']='fabricated PDF sentence'
    with pytest.raises(ValueError,match='excerpt'):validate_reference(root/'OpTCRedTeamGroundTruth.pdf',bad)


@pytest.mark.parametrize('field,value',[('pid',99999),('host','invented'),('id','FAKE'),('c2_ip','1.2.3.4'),('active_start','2018-01-01T00:00:00+00:00')])
def test_resolution_fields_must_match_their_cited_pdf_text(field,value):
    import json
    from pathlib import Path
    from tc_pruning.pdf_groundtruth import validate_reference
    root=Path(__file__).resolve().parents[1];ref=json.loads((root/'poi/optc-pdf-reference.json').read_text());ref['agents'][0][field]=value
    with pytest.raises(ValueError,match='source|identity|time|C2'):validate_reference(root/'OpTCRedTeamGroundTruth.pdf',ref)
