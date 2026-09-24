import pytest
from scripts.evaluate_cross_domain import summarize_random,validate_decision


def test_random_summary_reports_variation_not_fake_case_count():
    result=summarize_random([{'proxy_recall':.2,'proxy_f1':.1},{'proxy_recall':.4,'proxy_f1':.3}])
    assert result['runs']==2
    assert result['proxy_recall_mean']==pytest.approx(.3)
    assert result['proxy_recall_std']==pytest.approx(2**.5*.1)


def test_decision_rejects_unknown_ids_and_missing_pois():
    row=dict(status='ok',selected_ids=['a','x'],raw_events=2,raw_cap=2)
    with pytest.raises(ValueError,match='unknown'):validate_decision(row,{'a','b'},{'a'})
    row.update(selected_ids=['b'],raw_events=1)
    with pytest.raises(ValueError,match='POI'):validate_decision(row,{'a','b'},{'a'})


def test_infeasible_is_not_zero_accuracy_observation():
    assert validate_decision({'status':'infeasible_mandatory','mandatory_events':5,'raw_cap':4},{'a'},{'a'}) is None


def test_episode_audit_exposes_partial_poi_evidence():
    from scripts.evaluate_cross_domain import episode_audit
    a=episode_audit(['a','c'],{'a':0,'b':0,'c':1},[2,1],{'a'})
    assert a['complete_episodes']==1 and a['partial_episodes']==1
    assert a['complete_poi_episodes']==0 and a['poi_episodes']==1
