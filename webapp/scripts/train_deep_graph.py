"""Train a real three-seed masked graph model on disjoint temporal splits."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import numpy as np
import torch
from tc_pruning.optc import parse_event,timestamp_ns
from tc_pruning.deep_graph import snapshots,make_model,normalized,reconstruction_errors,embeddings,neighbor_distances,FEATURE_NAMES

SPLIT=dict(train=['2019-09-23T09:10:00-04:00','2019-09-23T10:00:00-04:00'],
           validation=['2019-09-23T10:00:00-04:00','2019-09-23T10:10:00-04:00'],
           calibration=['2019-09-23T10:10:00-04:00','2019-09-23T10:40:00-04:00'],
           normal_test=['2019-09-23T10:50:00-04:00','2019-09-23T11:10:00-04:00'])


def read_edges(database,start,end):
    with sqlite3.connect(f'file:{database}?mode=ro',uri=True) as c:
        return [parse_event(json.loads(r[0])) for r in c.execute(
            'SELECT payload FROM records JOIN events USING(event_id) WHERE timestamp_ns>=? AND timestamp_ns<? ORDER BY timestamp_ns,event_id',
            (timestamp_ns(start),timestamp_ns(end)))]


def train(database,output,epochs=120,seeds=(731,732,733)):
    started=time.monotonic();torch.set_num_threads(4)
    device='cuda' if torch.cuda.is_available() else 'cpu'
    datasets={};splits={};all_ids=set()
    for name,(start,end) in SPLIT.items():
        edges=read_edges(database,start,end);ids={e['id'] for e in edges}
        if ids & all_ids:raise ValueError('Temporal split event overlap')
        all_ids.update(ids);datasets[name]=snapshots(edges)
        if not edges:raise ValueError(f'empty {name} split')
        splits[name]=dict(start=start,end=end,events=len(edges),snapshots=len(datasets[name]),
                          process_snapshots=sum(len(g['node_ids']) for g in datasets[name]),
                          event_ids_sha256=hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest())
        print(name,splits[name],flush=True)
    all_x=np.concatenate([g['x'] for g in datasets['train']]);mean=all_x.mean(0);scale=np.maximum(all_x.std(0),.2)
    xs=[];arcs=[];offset=0
    for g in datasets['train']:
        xs.append(normalized(g,mean,scale));arcs.append(g['arcs']+offset);offset+=len(g['x'])
    x=torch.tensor(np.concatenate(xs),device=device);arc=torch.tensor(np.concatenate(arcs,axis=1),device=device)
    models=[];records=[]
    for seed in seeds:
        torch.manual_seed(seed);np.random.seed(seed)
        model=make_model().to(device);optim=torch.optim.AdamW(model.parameters(),lr=.003,weight_decay=.0001)
        best=float('inf');best_state=None;history=[];best_epoch=0
        for epoch in range(1,epochs+1):
            model.train();mask=torch.rand(len(x),device=device)<.5
            optim.zero_grad();loss=(model(x,arc,mask)[mask]-x[mask]).square().mean()
            loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),5);optim.step()
            if epoch==1 or epoch%5==0:
                model.eval();val=float(np.concatenate([reconstruction_errors(model,g,mean,scale,device) for g in datasets['validation']]).mean())
                history.append(dict(epoch=epoch,train_loss=float(loss.detach()),validation_loss=val))
                if val<best:best=val;best_state=copy.deepcopy(model.state_dict());best_epoch=epoch
        model.load_state_dict(best_state);model.eval();models.append(model)
        records.append(dict(seed=seed,best_epoch=best_epoch,validation_loss=best,loss_history=history))
        print('trained seed',seed,'best epoch',best_epoch,'validation loss',best,flush=True)
    def score_set(graphs):
        aggregated={};baseline={};single=[{} for _ in models]
        for g in graphs:
            errs=np.stack([reconstruction_errors(m,g,mean,scale,device) for m in models])
            avg=errs.mean(0);raw=np.square(normalized(g,mean,scale)).mean(1)
            for i,nid in enumerate(g['node_ids']):
                aggregated[nid]=max(aggregated.get(nid,0),float(avg[i]));baseline[nid]=max(baseline.get(nid,0),float(raw[i]))
                for j in range(len(models)):single[j][nid]=max(single[j].get(nid,0),float(errs[j,i]))
        return aggregated,baseline,single
    cal,cal_base,cal_single=score_set(datasets['calibration']);threshold=float(np.quantile(list(cal.values()),.99))
    test,test_base,test_single=score_set(datasets['normal_test']);base_threshold=float(np.quantile(list(cal_base.values()),.99))
    train_embeddings=np.concatenate([embeddings(models,g,mean,scale,device) for g in datasets['train']])
    embedding_mean=train_embeddings.mean(0);embedding_scale=np.maximum(train_embeddings.std(0),.1)
    reference=(train_embeddings-embedding_mean)/embedding_scale
    def latent_scores(graphs):
        scores={}
        for g in graphs:
            z=(embeddings(models,g,mean,scale,device)-embedding_mean)/embedding_scale
            distances=neighbor_distances(z,reference)
            for i,nid in enumerate(g['node_ids']):scores[nid]=max(scores.get(nid,0),float(distances[i]))
        return scores
    latent_cal=latent_scores(datasets['calibration']);latent_test=latent_scores(datasets['normal_test'])
    latent_threshold=float(np.quantile(list(latent_cal.values()),.99))
    output.mkdir(parents=True,exist_ok=True)
    torch.save(dict(states=[{k:v.cpu() for k,v in m.state_dict().items()} for m in models],
                    mean=torch.tensor(mean),scale=torch.tensor(scale),reference_embeddings=torch.tensor(reference),
                    embedding_mean=torch.tensor(embedding_mean),embedding_scale=torch.tensor(embedding_scale)),output/'weights.pt')
    manifest=dict(model_id='optc-gmae-v1',architecture='2-layer masked GraphSAGE + 2-layer reconstruction decoder',hidden=64,
                  features=FEATURE_NAMES,seeds=list(seeds),threshold=latent_threshold,threshold_quantile=.99,
                  scoring='5-neighbor distance in standardized learned graph embedding; reconstruction error retained as ablation',
                  reconstruction_threshold=threshold,
                  calibration_processes=len(cal),calibration_end_ns=timestamp_ns(SPLIT['calibration'][1]),split=splits,
                  weights_sha256=hashlib.sha256((output/'weights.pt').read_bytes()).hexdigest(),
                  model_parameters=sum(p.numel() for p in models[0].parameters()),
                  labels_used_for_training=False,attack_rules_used=False,normality_assumption='Early pre-campaign telemetry; verify with external labels after freezing model',
                  runtime_seconds=time.monotonic()-started,device=device,
                  feature_source_sha256=hashlib.sha256((ROOT/'tc_pruning/deep_graph.py').read_bytes()).hexdigest())
    report=dict(manifest=manifest,training=records,normal_holdout=dict(processes=len(test),
                  flagged=sum(v>latent_threshold for v in latent_test.values()),threshold=latent_threshold,
                  scores=latent_test,reconstruction_flagged=sum(v>threshold for v in test.values()),
                  reconstruction_threshold=threshold,baseline_threshold=base_threshold,baseline_flagged=sum(v>base_threshold for v in test_base.values())),
                  reconstruction_seed_thresholds=[float(np.quantile(list(v.values()),.99)) for v in cal_single],
                  baseline='Squared standardized feature distance; identical training normalization and calibration protocol')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (ROOT/'docs/deep-graph-training.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Finished',json.dumps(dict(threshold=latent_threshold,holdout=report['normal_holdout']['flagged'],seconds=manifest['runtime_seconds'])),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--corpus',type=Path,default=ROOT/'webapp/runtime/optc-corpus.sqlite')
    p.add_argument('--output',type=Path,default=ROOT/'models/optc-gmae-v1');p.add_argument('--epochs',type=int,default=120)
    a=p.parse_args();train(a.corpus,a.output,a.epochs)
