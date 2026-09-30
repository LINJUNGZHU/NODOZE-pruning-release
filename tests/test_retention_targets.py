"""A retention floor must constrain the same observed budget point."""
import copy
import pytest

from scripts.analyze_retention_targets import select_budget, analyze_report


def point(budget, events, dependencies, terminals=100, *, retained=None):
    retained = budget if retained is None else retained
    return dict(method='fusion', budget=budget, retained_events=retained,
                compression=1-retained/1000, fixed_scope_compression=1-retained/2000,
                scopes={'native':dict(reference_events=100, retained_reference_events=events,
                    event_retention=events/100, reference_dependencies=100,
                    retained_dependencies=dependencies, dependency_retention=dependencies/100,
                    terminal_pairs=100, reachable_terminal_pairs=terminals,
                    terminal_reachability=terminals/100,
                    event_stage_counts=dict(source=100,candidate=100,temporal_eligible=100,retained=events))})


def test_joint_floor_cannot_combine_different_points_or_assume_monotonicity():
    rows=[point(100,100,90),point(200,90,100),point(300,95,95),point(400,80,80)]
    result=select_budget(rows,.95)
    assert result['status']=='met'
    assert result['selected']['budget']==300
    assert result['selected']['compression']==.7
    assert select_budget(rows,.99)['status']=='unmet'


def test_maximum_actual_compression_and_budget_tie_break():
    rows=[point(100,95,95),point(200,99,99,retained=99),point(300,99,99,retained=99)]
    assert select_budget(rows,.95)['selected']['budget']==200


def test_terminal_floor_is_an_explicit_additional_constraint():
    rows=[point(100,99,99,80),point(200,100,100,100)]
    assert select_budget(rows,.95)['selected']['budget']==100
    assert select_budget(rows,.95,require_terminals=True)['selected']['budget']==200


def test_zero_dependency_denominator_is_unavailable_not_success():
    row=point(100,100,100)
    row['scopes']['native'].update(reference_dependencies=0,retained_dependencies=0,dependency_retention=None)
    result=select_budget([row],.95)
    assert result['status']=='unavailable' and result['selected'] is None


@pytest.mark.parametrize('stage,reason',[('candidate','candidate_event_ceiling'),('temporal_eligible','temporal_event_ceiling')])
def test_budget_cannot_recover_events_excluded_before_selection(stage,reason):
    row=point(100,80,70)
    row['scopes']['native']['event_stage_counts'][stage]=80
    if stage=='candidate':row['scopes']['native']['event_stage_counts']['temporal_eligible']=80
    result=select_budget([row],.95)
    assert result['reason']==reason
    assert result['closest']['event_retention']==.8


def test_closest_point_uses_joint_floor_not_one_large_ratio():
    result=select_budget([point(100,100,20),point(200,90,90)],.95)
    assert result['status']=='unmet'
    assert result['closest']['budget']==200
    assert result['best_joint_retention']==.9


@pytest.mark.parametrize('target',[0,1.01,True,float('nan')])
def test_invalid_target_is_rejected(target):
    with pytest.raises(ValueError):select_budget([point(100,95,95)],target)


def test_inconsistent_ratio_fixed_denominator_and_duplicate_budget_rejected():
    bad=point(100,95,95);bad['scopes']['native']['event_retention']=1.
    with pytest.raises(ValueError):select_budget([bad],.95)
    with pytest.raises(ValueError):select_budget([point(100,95,95),point(100,95,95)],.95)
    bad=point(200,95,95);bad['scopes']['native']['reference_events']=200;bad['scopes']['native']['event_retention']=.475
    with pytest.raises(ValueError):select_budget([point(100,95,95),bad],.95)


def test_report_keeps_variants_methods_and_missing_references_separate():
    a=point(100,90,90);b=point(200,100,100)
    for row in [a,b]:row['scopes']['augmented']=copy.deepcopy(row['scopes']['native'])
    report=dict(schema_version='chain-subgraph-report-v1',data_visibility='aggregate_only',base_report_sha256='b'*64,
        cases=[dict(id='fixture',source_missing_positive_events=0,variants=[dict(track='base',poi_policy='declared',
            candidate_events=1000,source_scope_events=2000,rows=[a,b])])])
    result=analyze_report(report,input_sha256='a'*64,targets=[.95])
    assert len(result['rows'])==4
    assert all(row['selected']['budget']==200 for row in result['rows'])
    assert result['methodology']['reference_used_for_budget_selection'] is True
    assert result['methodology']['unseen_data_guarantee'] is False
    assert result['source_report_sha256']=='a'*64
    report['cases'][0]['variants'][0]['rows'][0]['compression']=.5
    with pytest.raises(ValueError):analyze_report(report,input_sha256='a'*64)


def test_private_extras_do_not_enter_selected_public_point():
    row=point(100,95,95);row['event_ids']=['PRIVATE-CANARY']
    result=select_budget([row],.95)
    assert 'PRIVATE-CANARY' not in repr(result)
