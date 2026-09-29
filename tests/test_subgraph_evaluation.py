"""Complete reference subgraphs differ from surviving paths and reachability."""
from copy import deepcopy
import json

import pytest


def api():
    from tc_pruning import subgraph_evaluation
    return subgraph_evaluation


def event(identity, src, dst, time, relation='EVENT_WRITE', host='H1'):
    return {'event_id': identity, 'src': src, 'dst': dst, 'timestamp_ns': time,
            'relation': relation, 'host': host}


def diamond():
    return [event('ENTRY', 'A', 'B', 1), event('LEFT', 'B', 'C', 2),
            event('RIGHT', 'B', 'C', 3), event('EXIT', 'C', 'D', 4)]


def test_lost_branch_preserves_terminal_reachability_but_not_complete_subgraph():
    model=api().derive_reference_subgraphs(diamond())
    result=api().evaluate_subgraphs(model, {'source': {'ENTRY','LEFT','RIGHT','EXIT'},
                                          'retained': {'ENTRY','RIGHT','EXIT'}}, detail=True)
    full=result['stages']['source']; kept=result['stages']['retained']
    assert full['reference_subgraph_count']==full['complete_subgraphs']==1
    assert kept['complete_subgraphs']==0 and kept['subgraph_retention']==0
    assert kept['terminal_pairs']==kept['reachable_terminal_pairs']==1
    assert kept['terminal_reachability']==1
    assert kept['retained_reference_events']==3 and kept['reference_events']==4
    assert kept['reference_dependencies']==4 and kept['retained_dependencies']==2
    assert kept['fork_count']==kept['join_count']==1
    assert kept['complete_forks']==kept['complete_joins']==0
    assert result['first_loss_counts']=={'source':0,'retained':1,'surviving':0}
    detail=result['components'][0]
    assert detail['stages']['retained']['missing_event_ids']==['LEFT']
    assert detail['first_loss_stage']=='retained'


def test_components_form_disjoint_event_partition_with_explicit_singletons():
    rows=diamond()+[event('OTHER1','X','Y',5),event('OTHER2','Y','Z',6),event('SINGLE','L','M',7)]
    model=api().derive_reference_subgraphs(rows)
    all_members=[e for component in model['components'] for e in component['event_ids']]
    assert len(all_members)==len(set(all_members))==7
    assert model['summary']['reference_subgraph_count']==2
    assert model['summary']['singleton_event_count']==1
    result=api().evaluate_subgraphs(model,{'retained':{'ENTRY','LEFT','RIGHT','EXIT','OTHER1','SINGLE'}})
    point=result['stages']['retained']
    assert point['complete_subgraphs']==1 and point['subgraph_retention']==.5
    assert point['retained_singleton_events']==1
    assert point['retained_reference_events']==6
    assert 'components' not in result


def test_transitive_reduction_only_defines_neighborhoods_not_masked_reachability():
    rows=[event('A','P','P',1),event('B','P','P',2),event('C','P','P',3)]
    model=api().derive_reference_subgraphs(rows)
    component=model['components'][0]
    assert component['dependencies']==[['A','B'],['A','C'],['B','C']]
    assert component['cover_dependencies']==[['A','B'],['B','C']]
    assert component['fork_event_ids']==component['join_event_ids']==[]
    point=api().evaluate_subgraphs(model,{'retained':{'A','C'}})['stages']['retained']
    assert point['complete_subgraphs']==0
    assert point['reachable_terminal_pairs']==1 and point['terminal_reachability']==1
    assert point['retained_dependencies']==1 and point['dependency_retention']==pytest.approx(1/3)
    assert point['fork_retention'] is None and point['join_retention'] is None


def test_multiple_roots_merging_have_fixed_reachable_terminal_pairs():
    rows=[event('ROOT1','A','C',1),event('ROOT2','B','C',2),
          event('MERGE','C','D',3),event('SINK','D','E',4)]
    model=api().derive_reference_subgraphs(rows)
    assert model['components'][0]['terminal_pairs']==[['ROOT1','SINK'],['ROOT2','SINK']]
    point=api().evaluate_subgraphs(model,{'retained':{'ROOT2','MERGE','SINK'}})['stages']['retained']
    assert point['terminal_pairs']==2 and point['reachable_terminal_pairs']==1
    assert point['terminal_reachability']==.5 and point['subgraph_retention']==0
    assert point['join_count']==1 and point['complete_joins']==0


def test_terminal_denominator_excludes_originally_unreachable_root_sink_pairs():
    rows=[event('ROOT_A','A','JOINT',2,host='H1'),
          event('ROOT_B','B','JOINT',1,host=None),
          event('SINK_C','JOINT','C',3,host='H1'),
          event('SINK_D','JOINT','D',3,host='H2')]
    model=api().derive_reference_subgraphs(rows)
    pairs=model['components'][0]['terminal_pairs']
    assert len(pairs)==3 and ['ROOT_A','SINK_D'] not in pairs
    point=api().evaluate_subgraphs(model,{'retained':{'ROOT_A','SINK_C','SINK_D'}})['stages']['retained']
    assert point['terminal_pairs']==3 and point['reachable_terminal_pairs']==1
    assert point['terminal_reachability']==pytest.approx(1/3)


def test_equal_timestamps_never_create_dependency():
    rows=[event('A','P','Q',1),event('B','Q','R',1)]
    model=api().derive_reference_subgraphs(rows)
    assert model['summary']['reference_subgraph_count']==0
    assert model['summary']['singleton_event_count']==2
    point=api().evaluate_subgraphs(model,{'retained':{'A','B'}})['stages']['retained']
    assert point['subgraph_retention'] is None and point['terminal_reachability'] is None


def test_unknown_time_is_required_isolated_event_not_causal_evidence():
    rows=[event('UNKNOWN','A','B',0),event('KNOWN','B','C',1),event('MISSING','C','D',None)]
    model=api().derive_reference_subgraphs(rows)
    assert model['summary']['unverifiable_time_events']==2
    assert model['summary']['reference_events']==model['summary']['singleton_event_count']==3
    assert model['summary']['reference_dependencies']==0
    point=api().evaluate_subgraphs(model,{'retained':{'KNOWN'}})['stages']['retained']
    assert point['retained_reference_events']==1 and point['event_retention']==pytest.approx(1/3)
    assert point['complete_subgraphs']==0 and point['subgraph_retention'] is None


def test_execute_direction_matches_existing_source_contract():
    rows=[event('WRITE','PARENT','BIN',1),event('EXEC','CHILD','BIN',2,'EVENT_EXECUTE'),
          event('CONNECT','CHILD','NET',3)]
    model=api().derive_reference_subgraphs(rows)
    assert model['components'][0]['dependencies']==[['WRITE','EXEC'],['EXEC','CONNECT']]
    execute=next(row for row in model['events'] if row['event_id']=='EXEC')
    assert execute['src']=='CHILD' and execute['dst']=='BIN'
    assert execute['causal_src']=='BIN' and execute['causal_dst']=='CHILD'


def test_entity_cycle_does_not_create_event_cycle_or_reverse_time():
    rows=[event('A','P','Q',1),event('B','Q','P',2),event('C','P','R',3)]
    model=api().derive_reference_subgraphs(rows)
    assert model['components'][0]['dependencies']==[['A','B'],['B','C']]
    assert model['components'][0]['terminal_pairs']==[['A','C']]


def test_known_host_mismatch_is_disallowed_but_unknown_links_are_counted():
    different=[event('A','P','Q',1,host='H1'),event('B','Q','R',2,host='H2')]
    model=api().derive_reference_subgraphs(different)
    assert model['summary']['reference_subgraph_count']==0
    assert model['summary']['inferred_host_dependencies']==0
    different[1]['host']=''
    inferred=api().derive_reference_subgraphs(different)
    assert inferred['summary']['reference_subgraph_count']==1
    assert inferred['summary']['inferred_host_dependencies']==1


@pytest.mark.parametrize('synthetic',[
    event('LINEAGE_BRIDGE','B','C',2),event('BRIDGE','B','C',2,'EVENT_LINEAGE')])
def test_native_excludes_synthetic_bridge_while_augmented_declares_it(synthetic):
    rows=[event('FIRST','A','B',1),synthetic,event('LAST','C','D',3)]
    native=api().derive_reference_subgraphs(rows)
    augmented=api().derive_reference_subgraphs(rows,include_synthetic=True)
    assert native['summary']['excluded_synthetic_events']==1
    assert native['summary']['synthetic_events']==0
    assert native['summary']['reference_subgraph_count']==0 and native['summary']['singleton_event_count']==2
    assert augmented['summary']['synthetic_events']==1 and augmented['summary']['excluded_synthetic_events']==0
    assert augmented['summary']['reference_subgraph_count']==1
    assert augmented['summary']['independent_attack_count'] is None
    assert augmented['summary']['attack_stage_completeness'] is None


@pytest.mark.parametrize('value',[True,1.5,'1.5','bad','1e3',-1,2**63])
def test_nonexact_or_invalid_times_are_rejected(value):
    with pytest.raises(ValueError,match='timestamp'):
        api().derive_reference_subgraphs([event('A','P','Q',value)])


def test_decimal_string_nanoseconds_preserve_exact_order():
    rows=[event('A','P','Q','1523028012106173690'),event('B','Q','R','1523028012106173691')]
    assert api().derive_reference_subgraphs(rows)['summary']['reference_dependencies']==1


def test_duplicates_after_canonicalization_are_rejected():
    with pytest.raises(ValueError,match='duplicate'):
        api().derive_reference_subgraphs([event('a','P','Q',1),event(' A ','Q','R',2)])


def test_order_and_unused_label_fields_cannot_change_reference_or_evaluation():
    rows=diamond(); original=deepcopy(rows)
    class Forbidden:
        def __str__(self):
            pytest.fail('unused annotation field was consumed')
    expected=api().derive_reference_subgraphs(rows)
    for row in rows:
        row.update(ground_truth=Forbidden(),attack_stage=Forbidden(),score=Forbidden(),is_attack=True)
    actual=api().derive_reference_subgraphs(rows[::-1])
    assert actual==expected
    assert rows[0]['event_id']==original[0]['event_id']
    stages={'source':{'ENTRY','LEFT','RIGHT','EXIT','UNRELATED'},'retained':{'ENTRY','RIGHT','EXIT'}}
    before=deepcopy(expected)
    assert api().evaluate_subgraphs(actual,stages)==api().evaluate_subgraphs(expected,stages)
    assert expected==before


def test_non_nested_reference_stages_rejected_but_unrelated_events_ignored():
    model=api().derive_reference_subgraphs(diamond())
    with pytest.raises(ValueError,match='nested'):
        api().evaluate_subgraphs(model,{'candidate':{'ENTRY'},'retained':{'LEFT'}})
    result=api().evaluate_subgraphs(model,{'source':{'ENTRY','LEFT','RIGHT','EXIT'},
                                          'retained':{'ENTRY','LEFT','RIGHT','EXIT','UNRELATED'}})
    assert result['stages']['retained']['subgraph_retention']==1


def test_first_loss_counts_components_once_and_public_result_contains_no_identities():
    rows=diamond()+[event('PRIVATE_X','X','Y',10),event('PRIVATE_Y','Y','Z',11)]
    model=api().derive_reference_subgraphs(rows)
    result=api().evaluate_subgraphs(model,{'source':{r['event_id'] for r in rows},
                                          'candidate':{'ENTRY','RIGHT','EXIT','PRIVATE_X','PRIVATE_Y'},
                                          'retained':{'ENTRY','RIGHT','EXIT','PRIVATE_X'}})
    assert result['first_loss_counts']=={'source':0,'candidate':1,'retained':1,'surviving':0}
    text=json.dumps(result)
    assert 'PRIVATE' not in text and 'ENTRY' not in text and 'components' not in result
    assert result['stages']['retained']['attack_stage_completeness'] is None


def test_empty_reference_has_null_ratios_not_perfect_completeness():
    result=api().evaluate_subgraphs(api().derive_reference_subgraphs([]),{'retained':set()})
    point=result['stages']['retained']
    for key in ('subgraph_retention','event_retention','dependency_retention',
                'terminal_reachability','fork_retention','join_retention'):
        assert point[key] is None
    assert result['summary']['reference_events']==0
    assert result['first_loss_counts']=={'retained':0,'surviving':0}


@pytest.mark.parametrize('stages',[{}, {'retained':None}, {'retained':'ENTRY'}, {'surviving':set()}])
def test_pipeline_stage_presence_and_types_are_explicit(stages):
    with pytest.raises(ValueError,match='stage'):
        api().evaluate_subgraphs(api().derive_reference_subgraphs(diamond()),stages)


def test_private_component_details_carry_graph_and_stage_metrics_without_aliasing_model():
    model=api().derive_reference_subgraphs(diamond())
    original=deepcopy(model)
    result=api().evaluate_subgraphs(model,{'source':{'ENTRY','LEFT','RIGHT','EXIT'},
                                         'retained':{'ENTRY','RIGHT','EXIT'}},detail=True)
    component=result['components'][0]
    assert component['dependencies']==model['components'][0]['dependencies']
    assert component['cover_dependencies']==model['components'][0]['cover_dependencies']
    assert component['roots']==['ENTRY'] and component['sinks']==['EXIT']
    assert component['fork_event_ids']==['ENTRY'] and component['join_event_ids']==['EXIT']
    point=component['stages']['retained']
    assert point['status']=='partial' and not point['complete']
    assert point['retained_event_ids']==['ENTRY','EXIT','RIGHT']
    assert point['reference_events']==4 and point['retained_events']==3
    assert point['terminal_pairs']==point['reachable_terminal_pairs']==1
    assert point['reference_dependencies']==4 and point['retained_dependencies']==2
    assert point['complete_forks']==point['complete_joins']==0
    component['dependencies'][0][0]='MUTATED'
    component['roots'].append('MUTATED')
    assert model==original
