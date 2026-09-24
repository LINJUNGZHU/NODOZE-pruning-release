import pytest
from scripts.evaluate_frequency_diffusion import metrics


def test_proxy_counts_are_raw_and_stages_do_not_imply_full_recall():
    ref={'critical_event_ids':['a','b','c'],'exemplars':[
        {'stage':'x','parallel_event_ids':['a','b']},
        {'stage':'y','parallel_event_ids':['c']} ]}
    m=metrics(['a','c','d'],ref,10)
    assert (m['proxy_tp'],m['proxy_fp'],m['proxy_fn'],m['proxy_tn'])==(2,1,1,6)
    assert m['groups_hit']==2 and m['stages_hit']==2
    assert m['proxy_recall']==pytest.approx(2/3)
    assert m['proxy_f1']==pytest.approx(2/3)
    assert m['official_equivalent']['precision'] is None


def test_duplicate_selected_ids_rejected():
    with pytest.raises(ValueError,match='duplicate'):
        metrics(['a','a'],{'critical_event_ids':['a'],'exemplars':[]},2)
