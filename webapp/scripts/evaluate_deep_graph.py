"""Evaluate frozen models, ablations and rules. Labels are read only for scoring.

The three attack windows overlap: do not average them as independent samples.
No threshold is selected using these attack labels.
"""
import hashlib
import json
from pathlib import Path
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import numpy as np
import torch
from tc_pruning.deep_graph import DEFAULT_MODEL,load_model,snapshots,normalized,reconstruction_errors,embeddings,neighbor_distances
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack,node_metrics
from webapp.scripts.train_deep_graph import read_edges,SPLIT


def aggregate(graphs,values):
    result={}
    for g,vs in zip(graphs,values):
        for n,v in zip(g['node_ids'],vs):result[n]=max(result.get(n,0.),float(v))
    return result


def main():
    torch.set_num_threads(4)
    folder=DEFAULT_MODEL;manifest,models,bundle=load_model(str(folder.resolve()),(folder/'manifest.json').stat().st_mtime_ns)
    frozen=manifest['weights_sha256'];mean,scale=bundle['mean'].numpy(),bundle['scale'].numpy()
    ref=bundle['reference_embeddings'].numpy();em=bundle['embedding_mean'].numpy();es=bundle['embedding_scale'].numpy()
    database=ROOT/'webapp/runtime/optc-corpus.sqlite'
    split_edges={k:read_edges(database,*v) for k,v in SPLIT.items()}
    for name,evs in split_edges.items():
        digest=hashlib.sha256('\n'.join(sorted(e['id'] for e in evs)).encode()).hexdigest()
        if digest!=manifest['split'][name]['event_ids_sha256']:
            raise ValueError(f'{name} corpus differs from frozen training manifest')
    split_graphs={k:snapshots(v) for k,v in split_edges.items()}
    cal=split_graphs['calibration'];train=split_graphs['train']
    rawref=np.concatenate([normalized(g,mean,scale) for g in train])
    def variants(graphs):
        z=[(embeddings(models,g,mean,scale)-em)/es for g in graphs]
        result={
            'reconstruction_only':aggregate(graphs,[np.mean([reconstruction_errors(m,g,mean,scale) for m in models],0) for g in graphs]),
            'raw_feature_distance':aggregate(graphs,[np.square(normalized(g,mean,scale)).mean(1) for g in graphs]),
            'raw_feature_knn':aggregate(graphs,[neighbor_distances(normalized(g,mean,scale),rawref) for g in graphs]),
        }
        for j,seed in enumerate(manifest['seeds']):
            sl=slice(j*32,(j+1)*32)
            result[f'latent_seed_{seed}']=aggregate(graphs,[neighbor_distances(v[:,sl],ref[:,sl]) for v in z])
        return result
    cal_scores=variants(cal);thresholds={k:float(np.quantile(list(v.values()),.99)) for k,v in cal_scores.items()}
    # Audit split contamination only after training and calibration were frozen.
    archives=ROOT/'webapp/runtime/research/optc-labels'
    ids={e['id']:k for k,evs in split_edges.items() for e in evs}
    observed={k:set() for k in SPLIT}
    with zipfile.ZipFile(archives/'malicious.zip') as z:
        with z.open('malicious.json') as stream:
            for line in stream:
                if b'sysclient0201' not in line.lower():continue
                e=json.loads(line)
                if e['id'] in ids:observed[ids[e['id']]].add(e['id'])
    with zipfile.ZipFile(archives/'tasks.zip') as z:tasks=json.load(z.open('tasks.json'))
    positive={t.get('object_id') for t in tasks if t.get('hostname','').lower()=='sysclient0201.systemia.com' and
              t.get('event_id') and 'process' in (t.get('labels') or []) and 'malicious' in (t.get('labels') or []) and 'invalid' not in (t.get('labels') or [])}
    audit={k:dict(events=len(evs),matched_malicious_events=len(observed[k]),
                  process_ids_with_lifetime_attack_label=len({n for g in split_graphs[k] for n in g['node_ids']} & positive)) for k,evs in split_edges.items()}
    print('SPLIT LABEL AUDIT',audit,flush=True)
    catalog=json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text());results=[]
    for entry in catalog:
        data=json.loads(Path(entry['cache_path']).read_text());start=time.monotonic()
        neural=infer_attack(data['edges'],data['poi']['event_id'],detector='neural')
        evaluation=evaluate_attack(neural,data['edges']);neural['evaluation']=evaluation
        labels=evaluation['published_benchmark']['labels'];universe=set(labels)
        scores=variants(snapshots(data['edges']))
        alternatives={k:dict(threshold=thresholds[k],metrics=node_metrics(universe,{n for n,v in values.items() if v>thresholds[k]},labels)) for k,values in scores.items()}
        bm=evaluation['published_benchmark'];rb=data['attack']['evaluation']['published_benchmark']
        result=dict(id=entry['id'],events=len(data['edges']),processes=len(universe),retained_edges=data['metrics']['retained_edges'],
                    rules=dict(nodes=rb['node_metrics'],path_events=rb['path_event_metrics'],runtime_seconds=data['attack']['runtime_seconds']),
                    neural=dict(nodes=bm['node_metrics'],path_events=bm['path_event_metrics'],runtime_seconds=neural['runtime_seconds'],
                                threshold=neural['threshold']['value'],predictions=[dict(id=n['id'],pids=n['pids'],label=n['label'],score=n['anomaly_score'],reference=labels[n['id']]) for n in neural['nodes'] if n['predicted_attack']],
                                paths=neural['summary']),ablations=alternatives,evaluation_seconds=time.monotonic()-start)
        results.append(result)
        (ROOT/'webapp/runtime/examples'/f'{entry["id"]}-neural-report.json').write_text(json.dumps(neural,ensure_ascii=False))
        output=dict(model_id=manifest['model_id'],weights_sha256=frozen,split_audit=audit,
                    comparison_note='Overlapping same-host windows; exploratory evaluation, not independent benchmarks or proof of generalization. Earlier reconstruction trial failed and motivated latent-distance experiment. No attack-label threshold tuning.',
                    threshold_protocol='Maximum score per process UUID over each window; q=0.99 in disjoint earlier calibration interval. Longer windows change maximum-score distribution; no guaranteed FPR.',
                    examples=results)
        (ROOT/'docs/deep-graph-evaluation.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
        print(entry['id'],'rules',rb['node_metrics'],'neural',bm['node_metrics'],flush=True)
    assert hashlib.sha256((folder/'weights.pt').read_bytes()).hexdigest()==frozen


if __name__=='__main__':main()
