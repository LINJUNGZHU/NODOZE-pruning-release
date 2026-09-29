from pathlib import Path
import json
import numpy as np
import pytest


def runner():
    from scripts import run_adaptive_chains
    return run_adaptive_chains


def test_frozen_online_decisions_do_not_depend_on_labels_and_respect_caps(tmp_path):
    r=runner(); data=r.synthetic_case(101,noise_count=120,chain_count=2)
    rows,history,cutoff=data['rows'],data['history'],data['cutoff_ns']
    online=r.run_online(rows,history,cutoff,[.1,.2],max_anchors=128)
    other=r.run_online([dict(x,ground_truth='different',attack=False) for x in rows],history,cutoff,[.1,.2],max_anchors=128)
    assert online['input_sha256']==other['input_sha256']
    for k,mask in online['masks'].items():
        assert np.array_equal(mask,other['masks'][k])
        assert int(mask.sum())<=int(len(rows)*float(k.split('@')[1]))
        assert all(mask[i] for i,x in enumerate(rows) if x['is_declared_poi'])
    r.freeze_online(tmp_path/'frozen',rows,online)
    assert r.validate_frozen(tmp_path/'frozen')['valid']
    p=tmp_path/'frozen/decisions.npz';p.write_bytes(p.read_bytes()+b'tamper')
    with pytest.raises(ValueError,match='hash'):r.validate_frozen(tmp_path/'frozen')


def test_synthetic_reference_is_complete_but_never_human_reviewed_attack_truth(tmp_path):
    r=runner();data=r.synthetic_case(22,noise_count=120,chain_count=2)
    online=r.run_online(data['rows'],data['history'],data['cutoff_ns'],[.2],max_anchors=128)
    result=r.evaluate_case('synthetic','test','synthetic',data['rows'],online,data['chains'],data['rows'],data['positive_ids'],{})
    assert len(result['reference_chains'])==2
    for point in result['results']:
        assert point['verified_attack_chain_retention']['value'] is None
        assert point['complete_reference_retention']['denominator']==2
        assert point['actual_compression']==1-point['retained_edges']/len(data['rows'])
        assert sum(point['chain_evaluation']['event_funnel']['first_loss_counts'].values())==14


def test_empty_truth_stays_unavailable():
    r=runner();data=r.synthetic_case(23,noise_count=80,chain_count=1)
    online=r.run_online(data['rows'],data['history'],data['cutoff_ns'],[.2])
    result=r.evaluate_case('empty','empty','real',data['rows'],online,[],data['rows'],[],{})
    assert all(x['complete_reference_retention']['value'] is None for x in result['results'])


def _small_online():
    r=runner();data=r.synthetic_case(4,noise_count=40,chain_count=1)
    return r,data,r.run_online(data['rows'],data['history'],data['cutoff_ns'],[.2],max_anchors=64)


def _rewrite_npz(directory,filename,mutate):
    r=runner();path=directory/filename
    with np.load(path,allow_pickle=False) as src:arrays={key:src[key] for key in src.files}
    mutate(arrays)
    np.savez_compressed(path,**arrays)
    manifest=json.loads((directory/'manifest.json').read_text())
    manifest['artifacts'][filename]=r._hash(path)
    (directory/'manifest.json').write_text(json.dumps(manifest))


def test_history_content_is_frozen_and_changes_input_identity(tmp_path):
    import gzip
    r,data,online=_small_online()
    changed=r.run_online(data['rows'],[dict(h,relation='WRITE') for h in data['history']],data['cutoff_ns'],[.2],max_anchors=64)
    assert online['history_count']==changed['history_count']
    assert online['input_sha256']!=changed['input_sha256']
    assert online['history_sha256']!=changed['history_sha256']
    directory=tmp_path/'frozen';manifest=r.freeze_online(directory,data['rows'],online)
    with gzip.open(directory/'history-inputs.json.gz','rt') as stream:history=json.load(stream)
    assert sum(row['count'] for row in history)==online['history_count']
    assert manifest['history_sha256']==online['history_sha256']
    assert manifest['config']['contextual_model']['confidence_support']>0
    assert r.validate_frozen(directory)['valid']


@pytest.mark.parametrize('budgets', [[],[True],[float('nan')],[0],[1.1],[.2,.2]])
def test_invalid_original_budget_configuration_is_rejected(budgets):
    r=runner();data=r.synthetic_case(4,noise_count=40,chain_count=1)
    with pytest.raises(ValueError,match='budget'):
        r.run_online(data['rows'],data['history'],data['cutoff_ns'],budgets,max_anchors=64)


def test_precise_budget_value_survives_freeze_without_rounding(tmp_path):
    r=runner();data=r.synthetic_case(4,noise_count=40,chain_count=1)
    budget=.2123456789012345
    online=r.run_online(data['rows'],data['history'],data['cutoff_ns'],[budget],max_anchors=64)
    assert all(float(key.split('@')[1])==budget for key in online['masks'])
    r.freeze_online(tmp_path/'frozen',data['rows'],online)
    assert r.validate_frozen(tmp_path/'frozen')['valid']


@pytest.mark.parametrize('filename,mutation', [
    ('decisions.npz',lambda values:values.clear()),
    ('decisions.npz',lambda values:values.pop(next(iter(values)))),
    ('scores.npz',lambda values:values.__setitem__('rasp',np.zeros(1))),
    ('scores.npz',lambda values:values.__setitem__('rasp',np.full_like(values['rasp'],np.nan))),
    ('eligibility.npz',lambda values:values.__setitem__('adaptive',np.zeros_like(values['adaptive']))),
])
def test_structurally_invalid_artifacts_rejected_even_with_matching_hashes(tmp_path,filename,mutation):
    r,data,online=_small_online();directory=tmp_path/'frozen';r.freeze_online(directory,data['rows'],online)
    _rewrite_npz(directory,filename,mutation)
    with pytest.raises(ValueError):r.validate_frozen(directory)


def test_frozen_poi_indices_must_match_consumed_candidate_flags(tmp_path):
    r,data,online=_small_online();directory=tmp_path/'frozen';r.freeze_online(directory,data['rows'],online)
    manifest=json.loads((directory/'manifest.json').read_text());manifest['poi_indices']=[]
    (directory/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='POI'):r.validate_frozen(directory)


def test_frozen_event_order_must_match_consumed_candidate_inputs(tmp_path):
    import gzip
    r,data,online=_small_online();directory=tmp_path/'frozen';r.freeze_online(directory,data['rows'],online)
    p=directory/'event-ids.json.gz'
    with gzip.open(p,'wt') as stream:json.dump([row['event_id'] for row in reversed(data['rows'])],stream)
    manifest=json.loads((directory/'manifest.json').read_text());manifest['artifacts'][p.name]=r._hash(p)
    (directory/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='event'):r.validate_frozen(directory)


def test_default_study_config_uses_independent_captain_references():
    r=runner();config_path=r.ROOT/'configs/adaptive_chain_study.json'
    assert config_path.is_file()
    cases=json.loads(config_path.read_text())['cases']
    for code in ('06','12','13'):
        spec=cases[f'E3-CADETS/node_Nginx_Backdoor_{code}.csv']
        assert not Path(spec['annotation']).is_absolute()
        assert spec['annotation']==f'configs/chain_references/cadets-{code}.json'
        assert r.resolve_input_path(spec['annotation'])==r.ROOT/spec['annotation']
        assert len(spec['upstream_annotation_sha256'])==64
        assert set(spec['upstream_annotation_sha256'])<=set('0123456789abcdef')
    assert 'not independently reviewed complete attack chains' in json.loads(config_path.read_text())['reference_semantics']


@pytest.mark.parametrize('metadata', [
    {'groundtruth_family':'UBC','scenario':'06'},
    {'groundtruth_family':'CAPTAIN/human_readable_gt','scenario':'12'},
])
def test_offline_annotation_rejects_wrong_source_or_scenario(tmp_path,metadata):
    r=runner();path=tmp_path/'reference.json'
    path.write_text(json.dumps({'attack_event_ids':['a'],'metadata':metadata}))
    with pytest.raises(ValueError):r.load_reference_annotation(path,'06')


def test_external_chain_manifest_is_offline_and_preserves_frozen_identity(tmp_path):
    r,data,online=_small_online();directory=tmp_path/'frozen';r.freeze_online(directory,data['rows'],online)
    frozen_before=(directory/'manifest.json').read_bytes()
    chain=dict(data['chains'][0],provenance={'kind':'independent_review','source':'reviewer contract'},
               reviewed_by='human reviewer',scope={'incident':'fixed experiment scope'},scope_complete=True)
    external=tmp_path/'reviewed-chains.json';external.write_text(json.dumps({'cadets06':[chain]}))
    loaded=r.load_chain_references(external,'cadets06')
    assert loaded==[chain]
    assert r.load_chain_references(external,'cadets12') is None
    ids=r.reference_event_ids(loaded)
    assert set(chain['event_ids'])<=ids
    assert set(chain['branches'][0])<=ids
    result=r.evaluate_case('cadets06','reviewed fixture','real',data['rows'],online,loaded,
                           data['rows'],data['positive_ids'],{})
    assert all(point['verified_attack_chain_retention']['denominator']==1 for point in result['results'])
    assert result['admitted_complete_chain_count']==1
    assert '已声明独立审核' in result['reference_scope']
    assert (directory/'manifest.json').read_bytes()==frozen_before
    assert r.validate_frozen(directory)['input_sha256']==online['input_sha256']


def test_external_manifest_without_review_scope_stays_unreviewed(tmp_path):
    r,data,online=_small_online()
    chain=dict(data['chains'][0],provenance={'kind':'independent_review'},scope_complete=True)
    chain.pop('scope',None)
    path=tmp_path/'unreviewed.json';path.write_text(json.dumps({'cadets06':[chain]}))
    loaded=r.load_chain_references(path,'cadets06')
    result=r.evaluate_case('cadets06','unreviewed','real',data['rows'],online,loaded,
                           data['rows'],data['positive_ids'],{})
    assert all(point['verified_attack_chain_retention']['value'] is None for point in result['results'])


def test_reference_source_lookup_includes_required_events_outside_positive_labels():
    r=runner()
    chains=[{'id':'contract','event_ids':['main'],'branches':[['branch']], 'required_event_ids':['outside-positive']}]
    assert r.reference_event_ids(chains)=={'main','branch','outside-positive'}


def test_displayed_reference_events_include_candidate_scoring_evidence():
    r,data,online=_small_online()
    result=r.evaluate_case('synthetic','evidence','synthetic',data['rows'],online,data['chains'],
                           data['rows'],data['positive_ids'],{})
    index={row['event_id'].upper():i for i,row in enumerate(data['rows'])}
    event=result['reference_chains'][0]['events'][0];i=index[event['event_id']]
    evidence=event.get('evidence')
    assert evidence is not None
    assert evidence['raw_rarity']==data['rows'][i]['components']['rarity']
    assert evidence['anomaly_score']==online['context'][i]['anomaly_score']
    assert evidence['score_rasp']==online['scores']['rasp'][i]
    assert evidence['score_contextual']==online['scores']['contextual'][i]
