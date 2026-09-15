import json

import pytest

from tc_pruning.detectors.alert_evidence import VeloxEvidenceAdapter, RCAIDEvidenceAdapter, NODLINKEvidenceAdapter


def test_velox_keeps_raw_origin_collision_and_support_in_contract():
    row = {'event_uuid': 'e#2', 'stored_event_id': 'e#2', 'original_event_id': 'e',
           'src_node_uuid': 'p', 'dst_node_uuid': 'c', 'loss': 2,
           'edge_type': 10, 'relation': 'EVENT_CLONE', 'raw_relation': 'EVENT_FORK',
           'identity_collision': 'True', 'identity_origin': 'OTHER_STORED_ID',
           'supporting_event_ids': '["e#2","e3"]', 'time': 123}
    evidence = VeloxEvidenceAdapter(version='test').adapt([row], [1])[0]
    assert evidence.relation == 'EVENT_FORK'
    assert evidence.supporting_event_ids == ('e#2', 'e3')
    assert evidence.detector_metadata['stored_event_id'] == 'e#2'
    assert evidence.detector_metadata['original_event_id'] == 'e'
    assert evidence.detector_metadata['identity_collision'] is True
    assert evidence.detector_metadata['identity_origin'] == 'OTHER_STORED_ID'
    assert evidence.detector_metadata['supporting_event_ids'] == ('e#2', 'e3')


@pytest.mark.parametrize('adapter', [RCAIDEvidenceAdapter, NODLINKEvidenceAdapter])
def test_node_context_is_preserved_without_inventing_roles(adapter):
    rows = [{'node_uuid': 'p', 'node': 1, 'loss': 2, 'timestamp_start': 10,
             'timestamp_end': 20, 'supporting_event_ids': '["e1"]'},
            {'node_uuid': 'p', 'node': 1, 'loss': 3, 'timestamp_start': 30,
             'timestamp_end': 40, 'supporting_event_ids': '[]'}]
    evidence = adapter(version='test').adapt(rows, [1])
    assert {(row.timestamp_start, row.timestamp_end) for row in evidence} == {(10, 20), (30, 40)}
    assert {row.role_hint.value for row in evidence} == {'OBSERVATION'}
    assert all(not row.structural_context and 'root_context' not in row.detector_metadata for row in evidence)
    assert next(row for row in evidence if row.timestamp_start == 10).supporting_event_ids == ('e1',)


def test_invalid_native_collision_and_support_fail_closed():
    row = {'event_uuid': 'e', 'src_node_uuid': 'p', 'dst_node_uuid': 'c', 'loss': 2}
    with pytest.raises(ValueError):
        VeloxEvidenceAdapter(version='test').adapt([dict(row, identity_collision='maybe')], [1])
    with pytest.raises(ValueError):
        VeloxEvidenceAdapter(version='test').adapt([dict(row, supporting_event_ids='not JSON')], [1])


def test_partial_identity_never_claims_exact_mapping():
    row = {'event_uuid': 'e', 'src_node_uuid': 'p', 'dst_node_uuid': 'c', 'loss': 2}
    evidence = VeloxEvidenceAdapter(version='test').adapt([row], [1])[0]
    assert evidence.mapping_quality.value != 'EXACT'
    with pytest.raises(ValueError):
        VeloxEvidenceAdapter(version='test').adapt([dict(row, stored_event_id='different')], [1])
