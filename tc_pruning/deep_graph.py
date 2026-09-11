"""Self-supervised masked GraphSAGE on minute-level process behavior graphs.

No attack rules, POI scores, labels, IP lists or UUID embeddings enter the model.
UUIDs only identify graph vertices; windows never mix future observations.
"""
from collections import defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path

import numpy as np

RELATIONS=('FILE_READ','FILE_WRITE','FILE_CREATE','FILE_DELETE','FILE_MODIFY',
           'PROCESS_CREATE','PROCESS_OPEN','PROCESS_TERMINATE','FLOW_START','FLOW_MESSAGE','OTHER')
FEATURE_NAMES=([f'out:{s}' for s in RELATIONS]+[f'in:{s}' for s in RELATIONS]+
               ['unique_files','unique_flows','unique_processes','duration','mean_gap','max_command_length']+
               [f'image_trigram:{i}' for i in range(32)]+[f'command_trigram:{i}' for i in range(32)])
DIM=len(FEATURE_NAMES)
WINDOW_NS=60_000_000_000
DEFAULT_MODEL=Path(__file__).resolve().parents[1]/'models/optc-gmae-v1'


@lru_cache(maxsize=8192)
def text_vector(value):
    value=' '.join(value.lower().split())[:2048]
    result=np.zeros(32,dtype=np.float32)
    for i in range(max(0,len(value)-2)):
        digest=hashlib.blake2b(value[i:i+3].encode(),digest_size=2).digest()
        result[int.from_bytes(digest,'little')%32]+=1
    norm=np.linalg.norm(result)
    return result/norm if norm else result


def snapshots(edges):
    grouped=defaultdict(list);seen=set()
    for e in edges:
        if e['id'] not in seen:grouped[e['timestamp_ns']//WINDOW_NS].append(e);seen.add(e['id'])
    result=[]
    for minute,events in sorted(grouped.items()):
        events=sorted(events,key=lambda e:(e['timestamp_ns'],e['id']))
        nodes=set()
        for e in events:
            r=e['raw'];nodes.add(r['actorID'])
            if r['object']=='PROCESS':nodes.add(r['objectID'])
        ids=sorted(nodes);index={n:i for i,n in enumerate(ids)}
        x=np.zeros((len(ids),DIM),dtype=np.float32);neighbors=set()
        files=defaultdict(set);flows=defaultdict(set);processes=defaultdict(set)
        times=defaultdict(list);image={};commands={};evidence=defaultdict(list)
        for e in events:
            r=e['raw'];p=r.get('properties',{});a=index[r['actorID']]
            rel=e['relation'];j=RELATIONS.index(rel) if rel in RELATIONS else len(RELATIONS)-1
            x[a,j]+=1;times[a].append(e['timestamp_ns']);evidence[a].append(e['id'])
            if r['object']=='PROCESS':
                b=index[r['objectID']];x[b,len(RELATIONS)+j]+=1
                evidence[b].append(e['id']);times[b].append(e['timestamp_ns']);processes[a].add(r['objectID'])
                if a!=b:neighbors.update(((a,b),(b,a)))
                if r['action']=='CREATE':
                    image[a]=p.get('parent_image_path','').replace('/', '\\').split('\\')[-1]
                    image[b]=p.get('image_path','').replace('/', '\\').split('\\')[-1]
                    command=p.get('command_line','')
                    if len(command)>len(commands.get(b,'')):commands[b]=command
                elif a not in image:image[a]=p.get('image_path','').replace('/', '\\').split('\\')[-1]
            else:
                image[a]=p.get('image_path','').replace('/', '\\').split('\\')[-1]
                (files if r['object']=='FILE' else flows)[a].add(r['objectID'])
        for i in range(len(ids)):
            ts=sorted(set(times[i]));gaps=np.diff(ts)/1e9 if len(ts)>1 else np.array([0.])
            pos=2*len(RELATIONS)
            x[i,pos:pos+6]=[len(files[i]),len(flows[i]),len(processes[i]),
                            (ts[-1]-ts[0])/1e9 if ts else 0.,float(gaps.mean()),len(commands.get(i,''))]
            x[i,:pos+6]=np.log1p(x[i,:pos+6])
            x[i,pos+6:pos+38]=text_vector(image.get(i,''))
            x[i,pos+38:]=text_vector(commands.get(i,''))
        arc=np.array(sorted(neighbors),dtype=np.int64).T if neighbors else np.empty((2,0),dtype=np.int64)
        result.append(dict(minute=int(minute),node_ids=ids,x=x,arcs=arc,
                           evidence={ids[i]:list(dict.fromkeys(evidence[i])) for i in range(len(ids))},
                           event_ids=[e['id'] for e in events]))
    return result


def make_model(hidden=64):
    import torch
    from torch import nn
    class MaskedGraphSAGE(nn.Module):
        def __init__(self):
            super().__init__()
            self.mask_token=nn.Parameter(torch.zeros(DIM))
            self.first=nn.Linear(DIM*2,hidden)
            self.second=nn.Linear(hidden*2,hidden//2)
            self.decoder=nn.Sequential(nn.Linear(hidden//2,hidden),nn.GELU(),nn.Linear(hidden,DIM))
        def neighbors(self,x,arcs):
            agg=torch.zeros_like(x);degree=torch.zeros((len(x),1),device=x.device)
            if arcs.shape[1]:
                agg.index_add_(0,arcs[1],x[arcs[0]])
                degree.index_add_(0,arcs[1],torch.ones((arcs.shape[1],1),device=x.device))
            return agg/degree.clamp_min(1)
        def forward(self,x,arcs,mask):
            visible=torch.where(mask[:,None],self.mask_token[None,:],x)
            return self.decoder(self.encode(visible,arcs))
        def encode(self,visible,arcs):
            h=torch.nn.functional.gelu(self.first(torch.cat((visible,self.neighbors(visible,arcs)),dim=1)))
            z=torch.nn.functional.gelu(self.second(torch.cat((h,self.neighbors(h,arcs)),dim=1)))
            return z
    return MaskedGraphSAGE()


def normalized(snapshot,mean,scale):
    return np.clip((snapshot['x']-mean)/scale,-12,12).astype(np.float32)


def reconstruction_errors(model,graph,mean,scale,device='cpu',feature_errors=False):
    import torch
    x=torch.tensor(normalized(graph,mean,scale),device=device)
    arcs=torch.tensor(graph['arcs'],device=device);error=torch.zeros_like(x)
    with torch.no_grad():
        for fold in range(4):
            mask=torch.arange(len(x),device=device)%4==fold
            if mask.any():error[mask]=(model(x,arcs,mask)[mask]-x[mask]).square()
    arr=error.cpu().numpy()
    return arr if feature_errors else arr.mean(axis=1)


def embeddings(models,graph,mean,scale,device='cpu'):
    import torch
    with torch.no_grad():
        x=torch.tensor(normalized(graph,mean,scale),device=device);arcs=torch.tensor(graph['arcs'],device=device)
        return torch.cat([m.encode(x,arcs) for m in models],dim=1).cpu().numpy()


def neighbor_distances(vectors,reference,k=5):
    import torch
    parts=[];ref=torch.as_tensor(reference,dtype=torch.float32)
    for start in range(0,len(vectors),256):
        distances=torch.cdist(torch.as_tensor(vectors[start:start+256],dtype=torch.float32),ref)
        parts.append(distances.topk(min(k,len(ref)),largest=False).values.mean(1).numpy())
    return np.concatenate(parts) if parts else np.array([],dtype=np.float32)


@lru_cache(maxsize=4)
def load_model(directory,version):
    import torch
    folder=Path(directory);manifest=json.loads((folder/'manifest.json').read_text())
    weights=folder/'weights.pt'
    if hashlib.sha256(weights.read_bytes()).hexdigest()!=manifest['weights_sha256']:
        raise ValueError('Neural model checksum mismatch')
    bundle=torch.load(weights,map_location='cpu',weights_only=True)
    models=[]
    for state in bundle['states']:
        model=make_model(manifest['hidden']);model.load_state_dict(state);model.eval();models.append(model)
    return manifest,models,bundle


def available_model(directory=None):
    folder=Path(directory or DEFAULT_MODEL)
    return folder/'manifest.json' if (folder/'manifest.json').is_file() and (folder/'weights.pt').is_file() else None


def score_nodes(edges,directory=None):
    import torch
    torch.set_num_threads(min(torch.get_num_threads(),4))
    folder=Path(directory or DEFAULT_MODEL);path=available_model(folder)
    if path is None:raise ValueError('Deep model is not trained; run train_deep_graph.py')
    manifest,models,bundle=load_model(str(folder.resolve()),path.stat().st_mtime_ns)
    mean,scale=bundle['mean'].numpy(),bundle['scale'].numpy()
    if edges and min(e['timestamp_ns'] for e in edges)<manifest['calibration_end_ns']:
        raise ValueError('Candidate window overlaps neural training/calibration; use a later example')
    graphs=snapshots(edges);rows={}
    for graph in graphs:
        errors=np.mean([reconstruction_errors(m,graph,mean,scale,feature_errors=True) for m in models],axis=0)
        latent=(embeddings(models,graph,mean,scale)-bundle['embedding_mean'].numpy())/bundle['embedding_scale'].numpy()
        scores=neighbor_distances(latent,bundle['reference_embeddings'].numpy())
        for i,nid in enumerate(graph['node_ids']):
            value=float(scores[i]);old=rows.get(nid)
            if old is None or value>old['score']:
                top=np.argsort(-errors[i])[:5]
                rows[nid]=dict(score=value,predicted=value>manifest['threshold'],
                               minute=graph['minute'],evidence_event_ids=graph['evidence'][nid],
                               feature_errors=[dict(feature=FEATURE_NAMES[j],error=float(errors[i,j])) for j in top],
                               explanation='重建误差分量仅为辅助观察，不是神经表示距离的因果归因')
    return dict(model_id=manifest['model_id'],threshold=manifest['threshold'],nodes=rows,
                training=manifest['split'],weights_sha256=manifest['weights_sha256'],
                score_meaning='学习到的图表示与早期历史近邻的距离；不是恶意概率',
                calibration='独立较晚校准时段，按进程聚合后固定 99% 分位线；不保证实际误报率',
                window_seconds=60,ensemble_seeds=manifest['seeds'])
