import pytest
from scripts.evaluate_budget_evidence_v7 import evaluate_selection


def reference():
    return {'critical_event_ids':['a','b','c'], 'exemplars':[{'stage':'one','parallel_event_ids':['a','b']},{'stage':'two','parallel_event_ids':['c']}], 'uncertain_event_ids':[]}


def test_proxy_group_any_full_and_incremental_exclude_mandatory():
    result=evaluate_selection(['a','b','x'],['a'],reference(),5)
    assert result['tp_known']==2
    assert result['group_any']==.5 and result['group_full']==.5
    assert result['recall_incremental']==.5
    assert result['precision_proxy']==pytest.approx(2/3)
    assert result['official_equivalent']['precision'] is None


def test_empty_incremental_denominator_and_missing_decision_are_null():
    r={'critical_event_ids':['a'],'exemplars':[{'stage':'x','parallel_event_ids':['a']}], 'uncertain_event_ids':[]}
    assert evaluate_selection(['a'],['a'],r,1)['recall_incremental'] is None
    assert evaluate_selection(None,['a'],r,1)['tp_known'] is None
