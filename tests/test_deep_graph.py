import copy
import hashlib
import json

import numpy as np
import pytest

torch=pytest.importorskip('torch')
from tc_pruning.deep_graph import snapshots,make_model,DIM,DEFAULT_MODEL,score_nodes,load_model
from tc_pruning.attack_inference import infer_attack
from tc_pruning.optc import parse_event


def events():
    def event(id,actor,target,obj,action,second,props):
        return parse_event(dict(id=id,hostname='host',timestamp=f'2019-09-23T11:20:{second:02d}-04:00',
                                actorID=actor,objectID=target,object=obj,action=action,pid=2,ppid=1,properties=props))
    return [event('create','parent','child','PROCESS','CREATE',1,dict(parent_image_path='parent.exe',image_path='child.exe',command_line='child --mode worker')),
            event('flow','child','socket','FLOW','START',2,dict(image_path='child.exe',direction='outbound',dest_ip='203.0.113.1'))]


def test_snapshots_ignore_labels_pruning_order_duplicates_and_future():
    es=events();original=snapshots(es)[0];changed=copy.deepcopy(es)
    for e in changed:e.update(score=999,retained=True,reference_evidence=['malicious'],historical_count=999)
    future=copy.deepcopy(es[1]);future['id']='future';future['timestamp_ns']+=60_000_000_000
    result=snapshots(list(reversed(changed))+[changed[0],future])
    assert len(result)==2
    assert original['node_ids']==result[0]['node_ids']==['child','parent']
    np.testing.assert_array_equal(original['x'],result[0]['x'])
    np.testing.assert_array_equal(original['arcs'],result[0]['arcs'])
    assert result[0]['event_ids']==['create','flow']
    assert original['x'].shape==(2,DIM)


def test_message_passing_is_permutation_equivariant_and_depends_on_graph():
    torch.manual_seed(11);model=make_model();x=torch.randn(4,DIM)
    arcs=torch.tensor([[0,1,1,2],[1,0,2,1]])
    perm=torch.tensor([2,0,3,1]);inv=torch.argsort(perm)
    torch.testing.assert_close(model.encode(x,arcs)[perm],model.encode(x[perm],inv[arcs]))
    assert not torch.allclose(model.encode(x,arcs),model.encode(x,torch.empty((2,0),dtype=torch.long)))


def test_masked_training_updates_weights_and_reduces_loss():
    torch.manual_seed(7);torch.set_num_threads(2);model=make_model();x=torch.randn(16,DIM)*.1
    arcs=torch.tensor([list(range(15)),list(range(1,16))]);mask=torch.arange(16)%2==0
    opt=torch.optim.Adam(model.parameters(),lr=.01)
    before={k:v.clone() for k,v in model.state_dict().items()}
    initial=float((model(x,arcs,mask)[mask]-x[mask]).square().mean().detach())
    for _ in range(35):
        opt.zero_grad();loss=(model(x,arcs,mask)[mask]-x[mask]).square().mean();loss.backward();opt.step()
    assert float(loss.detach())<initial*.7
    assert not torch.equal(before['first.weight'],model.first.weight)
    assert not torch.equal(before['mask_token'],model.mask_token)


def test_checkpoint_integrity_roundtrip_and_temporal_rejection(tmp_path):
    if not (DEFAULT_MODEL/'weights.pt').exists():pytest.skip('trained artifact unavailable')
    es=events();first=score_nodes(es);load_model.cache_clear();second=score_nodes(es)
    assert first==second
    old=copy.deepcopy(es);old[0]['timestamp_ns']=0
    with pytest.raises(ValueError,match='overlaps'):score_nodes(old)
    (tmp_path/'manifest.json').write_bytes((DEFAULT_MODEL/'manifest.json').read_bytes())
    (tmp_path/'weights.pt').write_bytes(b'corrupted checkpoint')
    with pytest.raises(ValueError,match='checksum'):score_nodes(es,tmp_path)


def test_neural_decisions_ignore_rule_channel_poi_and_pruning(monkeypatch):
    import tc_pruning.attack_inference as module
    es=events()
    neural=dict(nodes={'child':dict(score=1.,predicted=False,evidence_event_ids=['flow']),
                       'parent':dict(score=2.,predicted=True,evidence_event_ids=['create'])},threshold=1.5,calibration='frozen')
    first=infer_attack(es,'flow',detector='neural',neural_scores=neural)
    monkeypatch.setattr(module,'command_signals',lambda raw:['encoded_command','hidden_window'])
    changed=copy.deepcopy(es)
    for e in changed:e.update(retained=True,score=999,evidence_score=.99,historical_count=0,decision={'certified_background_lift':True,'temporal_witness':True})
    second=infer_attack(changed,'create',detector='neural',neural_scores=neural)
    for report in (first,second):
        assert {n['id'] for n in report['nodes'] if n['predicted_attack']}=={'parent'}
        assert not report['contract']['truth_used']
        assert report['threshold']['value']==1.5


def test_path_search_cap_does_not_drop_predictions():
    es=events();neural=dict(nodes={n:dict(score=2.,predicted=True,evidence_event_ids=['create']) for n in ('parent','child')},threshold=1.5,calibration='frozen')
    report=infer_attack(es,'flow',config=dict(max_path_anchors=1),detector='neural',neural_scores=neural)
    assert report['summary']['inferred_attack_nodes']==2
    assert report['summary']['path_anchor_nodes']==1
    assert report['summary']['untraced_predictions']==1
