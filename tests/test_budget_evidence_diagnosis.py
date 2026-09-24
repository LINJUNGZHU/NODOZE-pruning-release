from scripts.diagnose_budget_evidence_v7 import label_oracle,first_loss_stage


def test_label_oracle_respects_union_budget_and_one_certificate_per_anchor():
    pool={'actions':[
        {'anchor_id':'a','event_ids':['p','a','x'],'witness_id':'w1'},
        {'anchor_id':'a','event_ids':['p','a','y'],'witness_id':'w2'},
        {'anchor_id':'b','event_ids':['p','b'],'witness_id':'w3'}]}
    result=label_oracle(pool,{'p'},{'x','y'},4,time_limit=5)
    assert result['status'] in ('optimal','feasible_gap')
    assert result['incumbent_tp']==1
    assert result['upper_bound_tp']>=1


def test_postselection_stage_counts_passive_path_closure():
    pool={'materialized_ids':['p','a','x'],'actions':[{'anchor_id':'a','event_ids':['p','a','x'],'witness_id':'w1'}]}
    assert first_loss_stage('x',{'p','a','x'},True,pool,{'p'},3,{'p','a','x'})=='selected'
    assert first_loss_stage('x',{'p','a','x'},True,pool,{'p'},3,{'p'})=='not_attributed'
    assert first_loss_stage('z',{'p','a','x','z'},True,pool,{'p'},3,{'p'})=='candidate_not_materialized'
    assert first_loss_stage('x',{'p','a','x'},False,pool,{'p'},3,{'p'})=='time_rule_unreachable'
