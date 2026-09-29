"""Freeze label-free pruning, then audit whole reference chains at every budget.

Run: python -m scripts.run_adaptive_chains --output output/adaptive-chain-study --publish
The real-data references are derived from CAPTAIN positives, never human-reviewed
complete attack truth. Synthetic complete truth is shown in separate cases.

Optional --chain-references FILE supplies an offline JSON object mapping case IDs
(e.g. "cadets06") to lists of chain dictionaries accepted by evaluate_chains.
Absent cases fall back to derived references. This file is first read only after
online decisions are frozen and validated. Independent completeness requires
provenance.kind="independent_review", scope_complete=true, reviewed_by and scope;
loading a manifest does not grant a review declaration. Required source events
are loaded from the pre-pruning database, including events outside positive IDs.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import time
from datetime import datetime, timezone

import numpy as np

from tc_pruning.adaptive_chains import build_chain_bundles, select_adaptive_bundles, causal_endpoints
from tc_pruning.contextual_rarity import ContextualRarityModel
from tc_pruning.chain_evaluation import evaluate_chains, evaluate_event_funnel
from tc_pruning.rasp import propagate, temporal_routes, temporal_fork_routes, select_fork_bundles

ROOT = Path(__file__).resolve().parents[1]
BUDGETS = [.01, .02, .05, .1, .15, .2, .3, .5, 1.]
METHODS = {'rarity_only':'仅原始稀有度', 'diffusion_only':'仅图扩散', 'rasp':'原 RASP',
           'contextual':'上下文稀有度 + 扩散', 'chain_only':'RASP + 整链选择',
           'adaptive':'上下文稀有度 + 扩散 + 整链选择'}
SCORING = json.loads((ROOT/'configs/rasp_v1.json').read_text())
HISTORY_FIELDS = ('src_type','dst_type','src_semantic','dst_semantic','relation','host','timestamp_ns')
FIELDS = ('event_id','src','dst','relation','timestamp_ns','src_type','dst_type','src_semantic','dst_semantic','host','is_declared_poi')


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def _write(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp');temporary.write_bytes(_canonical(data)+b'\n');temporary.replace(path)


def _ratio(n,d):
    return {'numerator':int(n),'denominator':int(d),'value':n/d if d else None}


def resolve_input_path(value):
    """Resolve study configuration paths against the repository, never cwd."""
    path=Path(value)
    return path if path.is_absolute() else ROOT/path


def load_reference_annotation(path, scenario):
    """Offline admission check; call only after all decisions are frozen."""
    annotation=json.loads(Path(path).read_text())
    metadata=annotation.get('metadata',{})
    if metadata.get('groundtruth_family')!='CAPTAIN/human_readable_gt':
        raise ValueError('reference groundtruth_family must be CAPTAIN/human_readable_gt')
    if metadata.get('scenario')!=scenario:
        raise ValueError('reference scenario does not match the selected case')
    events=annotation.get('attack_event_ids')
    if not isinstance(events,list) or any(not isinstance(e,str) or not e.strip() for e in events):
        raise ValueError('reference attack_event_ids must be a list of nonempty strings')
    return annotation


def load_chain_references(path,case_id):
    """Read an offline {case_id: [chain, ...]} contract; None means fallback."""
    document=json.loads(Path(path).read_text())
    if not isinstance(document,dict):raise ValueError('chain reference manifest must map case IDs to chain lists')
    if case_id not in document:return None
    chains=document[case_id]
    if not isinstance(chains,list) or any(not isinstance(chain,dict) for chain in chains):
        raise ValueError('each external chain reference case must be a list of chain objects')
    return chains


def reference_event_ids(chains):
    """Include every branch and explicit requirement in source lookup."""
    events=set()
    for chain in chains:
        paths=[chain.get('event_ids',[]),chain.get('required_event_ids',[])]+chain.get('branches',[])
        for path in paths:
            if not isinstance(path,list) or any(not isinstance(e,str) or not e.strip() for e in path):
                raise ValueError('chain event sequences must be lists of nonempty IDs')
            events.update(path)
    return events


def _validated_budgets(values,n,poi_count):
    if not isinstance(values,(list,tuple)) or not values:
        raise ValueError('budgets must be a nonempty sequence')
    result=[]
    for value in values:
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise ValueError('budget values must be finite numeric ratios')
        ratio=float(value)
        if not math.isfinite(ratio) or not 0<ratio<=1 or int(n*ratio)<poi_count:
            raise ValueError('each fixed budget must fit all POIs without overflow')
        if ratio in result:
            raise ValueError('duplicate budget ratios are not allowed')
        result.append(ratio)
    return result


def _input_identity(candidate_digest,history_digest,cutoff_ns):
    return hashlib.sha256(_canonical({'candidate_sha256':candidate_digest,
        'history_sha256':history_digest,'cutoff_ns':int(cutoff_ns)})).hexdigest()


def _arrays(rows):
    nodes={};process=set();src=[];dst=[];relations={};relation=[]
    for row in rows:
        for side in ('src','dst'):
            node=nodes.setdefault(str(row[side]),len(nodes))
            if row.get(side+'_type')=='process':process.add(node)
        a,b=causal_endpoints(row);src.append(nodes[a]);dst.append(nodes[b])
        relation.append(relations.setdefault(row['relation'],len(relations)))
    p=np.zeros(len(nodes),dtype=bool);p[list(process)]=True
    return {'src':np.asarray(src),'dst':np.asarray(dst),'relation':np.asarray(relation),
            'timestamp':np.asarray([int(r['timestamp_ns']) for r in rows],dtype=np.int64),
            'poi':np.asarray([bool(r.get('is_declared_poi')) for r in rows]),'process':p,
            'tie':np.asarray([int.from_bytes(hashlib.sha256(str(r['event_id']).encode()).digest()[:8],'big') for r in rows],dtype=np.uint64)}


def run_online(rows, history_rows, cutoff_ns, budgets, *, max_anchors=4096, max_hops=64):
    """No annotation/reference argument: history and candidates only."""
    tick=time.perf_counter();a=_arrays(rows);n=len(rows)
    if not n or not a['poi'].any():raise ValueError('nonempty candidates with declared POIs required')
    budgets=_validated_budgets(budgets,n,int(a['poi'].sum()))
    history_rows=list(history_rows)
    model=ContextualRarityModel().fit(history_rows,cutoff_ns)
    history_inputs=[{**{key:row.get(key) for key in HISTORY_FIELDS},'count':row.get('count',1)}
                    for row in history_rows if row['timestamp_ns']<cutoff_ns]
    history_inputs.sort(key=_canonical)
    history_digest=hashlib.sha256(_canonical(history_inputs)).hexdigest()
    context=model.score_rows(rows)
    raw=np.asarray([float(r.get('components',{}).get('rarity',context[i]['raw_rarity'])) for i,r in enumerate(rows)])
    anomaly=np.asarray([x['anomaly_score'] for x in context])
    # Leave a nonzero novelty channel: missing history is uncertainty, not a
    # reason to remove a causal bridge. Constants fixed before reference load.
    adjusted=.25*raw+.75*anomaly
    scores={};propagation={}
    for name,weights in [('rasp',raw),('contextual',adjusted),('diffusion_only',np.zeros(n))]:
        score,diag=propagate(a['src'],a['dst'],a['relation'],weights,a['poi'],a['process'],SCORING)
        scores[name]=score
        propagation[name]={k:diag[k] for k in ('background','personalized','unique_channels')}
    scores['rarity_only']=raw.copy();scores['rarity_only'][a['poi']]=1.
    scores['chain_only']=scores['rasp'];scores['adaptive']=scores['contextual']
    back=temporal_routes(a['src'],a['dst'],a['timestamp'],a['poi'])[0][0]
    parent,pivot,reachable,_=temporal_fork_routes(a['src'],a['dst'],a['timestamp'],a['poi'],back)
    bundles={};bundle_diag={};eligible={}
    for name in ('chain_only','adaptive'):
        bundles[name],bundle_diag[name]=build_chain_bundles(rows,scores[name],max_hops=max_hops,max_anchors=max_anchors)
        members={i for b in bundles[name] if b['complete_in_candidate'] for i in b['event_indices']}
        members.update(np.flatnonzero(a['poi']).tolist())
        mask=reachable.copy();mask[list(members)]=True;eligible[name]=mask
    for name in METHODS:
        if name not in eligible:eligible[name]=reachable.copy()
    masks={};diagnostics={}
    for ratio in budgets:
        budget=int(n*ratio)
        for method in METHODS:
            key=f'{method}@{ratio!r}';started=time.perf_counter()
            if method in bundles:
                kept,diag=select_adaptive_bundles(rows,scores[method],bundles[method],budget)
                diag={**{k:v for k,v in bundle_diag[method].items() if k!='eligible_event_ids'},**diag}
            else:
                kept,_=select_fork_bundles(scores[method],a['poi'],back,parent,pivot,budget,a['tie'])
                diag={'budget_edges':budget,'budget_feasible':True,'unused_budget':budget-int(kept.sum())}
            assert kept.sum()<=budget and np.all(kept[a['poi']]) and np.all(~kept | eligible[method])
            masks[key]=kept;diagnostics[key]={**diag,'selection_seconds':time.perf_counter()-started}
    consumed=[{**{k:r.get(k) for k in FIELDS},'rarity':float(raw[i])} for i,r in enumerate(rows)]
    candidate_digest=hashlib.sha256(_canonical(consumed)).hexdigest()
    identity=_input_identity(candidate_digest,history_digest,cutoff_ns)
    return {'masks':masks,'scores':scores,'context':context,'eligible':eligible,'reachable':reachable,
            'bundles':bundles,'diagnostics':diagnostics,'input_sha256':identity,
            'candidate_inputs':consumed,'candidate_sha256':candidate_digest,
            'history_inputs':history_inputs,'history_sha256':history_digest,
            'history_count':model.history_count,'cutoff_ns':int(cutoff_ns),'propagation':propagation,
            'config':{'budgets':budgets,'methods':list(METHODS),
                      'contextual_model':{'smoothing':model.smoothing,'prior_strength':model.prior_strength,
                                          'confidence_support':model.confidence_support},'scoring':SCORING,'contextual_weight':.75,'raw_rarity_weight':.25,
                      'max_anchors':max_anchors,'max_hops':max_hops,'ground_truth_used_for_selection':False},
            'online_seconds':time.perf_counter()-tick}


def freeze_online(directory,rows,online):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    np.savez_compressed(directory/'decisions.npz',**online['masks'])
    np.savez_compressed(directory/'scores.npz',**online['scores'])
    np.savez_compressed(directory/'eligibility.npz',**online['eligible'],temporal=online['reachable'])
    for name,value in [('event-ids.json.gz',[r['event_id'] for r in rows]),('bundles.json.gz',online['bundles']),('contextual-evidence.json.gz',online['context']),
                       ('candidate-inputs.json.gz',online['candidate_inputs']),('history-inputs.json.gz',online['history_inputs'])]:
        with (directory/name).open('wb') as stream:
            with gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as zipped:zipped.write(_canonical(value))
    implementation={str(p.relative_to(ROOT)):_hash(p) for p in [Path(__file__),ROOT/'tc_pruning/adaptive_chains.py',ROOT/'tc_pruning/contextual_rarity.py',ROOT/'tc_pruning/rasp.py',ROOT/'configs/rasp_v1.json']}
    manifest={'schema_version':'adaptive-chain-frozen-v2','ground_truth_used_for_selection':False,
              'input_sha256':online['input_sha256'],'candidate_sha256':online['candidate_sha256'],
              'history_sha256':online['history_sha256'],
              'history_source':online.get('history_source',{'kind':'provided_weighted_history_rows'}),
              'history_source_sha256':hashlib.sha256(_canonical({'source':online.get('history_source',{'kind':'provided_weighted_history_rows'}),
                                                               'history_sha256':online['history_sha256']})).hexdigest(),
              'candidate_edges':len(rows),'poi_indices':[i for i,r in enumerate(rows) if r.get('is_declared_poi')],
              'history_count':online['history_count'],'cutoff_ns':str(online['cutoff_ns']),
              'config':online['config'],'diagnostics':online['diagnostics'],'online_seconds':online['online_seconds'],
              'implementation':implementation,'artifacts':{p.name:_hash(p) for p in directory.iterdir() if p.is_file()}}
    _write(directory/'manifest.json',manifest)
    return manifest


def validate_frozen(directory):
    """Check artifacts against original configuration and consumed inputs."""
    directory=Path(directory);manifest=json.loads((directory/'manifest.json').read_text())
    if manifest.get('schema_version')!='adaptive-chain-frozen-v2':
        raise ValueError('unsupported frozen artifact schema')
    required={'decisions.npz','scores.npz','eligibility.npz','event-ids.json.gz','bundles.json.gz',
              'contextual-evidence.json.gz','candidate-inputs.json.gz','history-inputs.json.gz'}
    if set(manifest.get('artifacts',{}))!=required:
        raise ValueError('frozen artifact set is incomplete or unexpected')
    for name,digest in manifest['artifacts'].items():
        if Path(name).name!=name or _hash(directory/name)!=digest:
            raise ValueError('frozen artifact hash mismatch: '+name)
    n=manifest.get('candidate_edges')
    if isinstance(n,bool) or not isinstance(n,int) or n<=0:
        raise ValueError('invalid candidate_edges')
    def read_json(name):
        with gzip.open(directory/name,'rt') as stream:return json.load(stream)
    candidates=read_json('candidate-inputs.json.gz');event_ids=read_json('event-ids.json.gz')
    if not isinstance(candidates,list) or len(candidates)!=n or not isinstance(event_ids,list) or len(event_ids)!=n:
        raise ValueError('invalid candidate/event input dimensions')
    if any(not isinstance(e,str) or not e.strip() for e in event_ids) or len(set(event_ids))!=n:
        raise ValueError('event identities must be unique nonempty strings')
    if event_ids!=[row.get('event_id') for row in candidates]:
        raise ValueError('event identity order differs from consumed candidates')
    if any(type(row.get('is_declared_poi')) is not bool for row in candidates):
        raise ValueError('candidate POI declarations must be booleans')
    expected_poi=[i for i,row in enumerate(candidates) if row['is_declared_poi']]
    poi=manifest.get('poi_indices')
    if (not expected_poi or not isinstance(poi,list) or any(type(i) is not int for i in poi)
            or poi!=expected_poi):
        raise ValueError('manifest POI indices differ from consumed candidate declarations')
    config=manifest.get('config',{})
    if config.get('methods')!=list(METHODS):
        raise ValueError('frozen method configuration differs from the study contract')
    budgets=_validated_budgets(config.get('budgets'),n,len(poi))
    expected={f'{method}@{ratio!r}':(method,int(n*ratio)) for method in METHODS for ratio in budgets}
    cutoff=int(manifest['cutoff_ns'])
    history=read_json('history-inputs.json.gz')
    if not isinstance(history,list) or any(row.get('timestamp_ns',cutoff)>=cutoff for row in history):
        raise ValueError('frozen history must contain only strict-past rows')
    model=ContextualRarityModel(**config['contextual_model']).fit(history,cutoff)
    if model.history_count!=manifest.get('history_count'):
        raise ValueError('frozen historical support count mismatch')
    candidate_digest=hashlib.sha256(_canonical(candidates)).hexdigest()
    history_digest=hashlib.sha256(_canonical(history)).hexdigest()
    if (candidate_digest!=manifest.get('candidate_sha256') or history_digest!=manifest.get('history_sha256')
            or _input_identity(candidate_digest,history_digest,cutoff)!=manifest.get('input_sha256')):
        raise ValueError('frozen consumed input identity mismatch')
    source_digest=hashlib.sha256(_canonical({'source':manifest.get('history_source'),
                                           'history_sha256':history_digest})).hexdigest()
    if source_digest!=manifest.get('history_source_sha256'):
        raise ValueError('frozen history source identity mismatch')
    context=read_json('contextual-evidence.json.gz')
    if not isinstance(context,list) or len(context)!=n:
        raise ValueError('invalid contextual evidence dimensions')
    for row in context:
        if row.get('history_count')!=model.history_count or row.get('history_cutoff_ns')!=cutoff:
            raise ValueError('contextual evidence history differs from frozen inputs')
        for key in ('raw_rarity','novelty','contextual_surprise','confidence','anomaly_score'):
            value=row.get(key)
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=1:
                raise ValueError('invalid contextual evidence score')
    with np.load(directory/'scores.npz',allow_pickle=False) as data:
        if set(data.files)!=set(METHODS):raise ValueError('frozen score method set mismatch')
        for name in data.files:
            score=data[name]
            if score.shape!=(n,) or score.dtype.kind not in 'fi' or not np.all(np.isfinite(score)) or np.any(score<0):
                raise ValueError('invalid frozen score array')
    with np.load(directory/'eligibility.npz',allow_pickle=False) as data:
        if set(data.files)!=set(METHODS)|{'temporal'}:raise ValueError('frozen eligibility method set mismatch')
        eligible={name:data[name] for name in data.files}
        for value in eligible.values():
            if value.dtype!=np.bool_ or value.shape!=(n,) or not np.all(value[poi]):
                raise ValueError('invalid frozen eligibility/POI array')
    with np.load(directory/'decisions.npz',allow_pickle=False) as data:
        if set(data.files)!=set(expected):raise ValueError('frozen method/budget decision set mismatch')
        for name in data.files:
            mask=data[name];method,budget=expected[name]
            if (mask.dtype!=np.bool_ or mask.shape!=(n,) or mask.sum()>budget
                    or not np.all(mask[poi]) or np.any(mask & ~eligible[method])):
                raise ValueError('invalid frozen budget/POI/eligibility decision')
            audit=manifest.get('diagnostics',{}).get(name,{})
            if audit.get('budget_edges')!=budget or audit.get('unused_budget')!=budget-int(mask.sum()):
                raise ValueError('frozen decision diagnostics mismatch')
    bundles=read_json('bundles.json.gz')
    if not isinstance(bundles,dict) or set(bundles)!={'adaptive','chain_only'}:
        raise ValueError('frozen bundle method set mismatch')
    for values in bundles.values():
        for bundle in values:
            members=bundle.get('event_indices',[])
            if (not members or len(members)!=len(set(members))
                    or any(type(i) is not int or not 0<=i<n for i in members)):
                raise ValueError('invalid frozen bundle event indices')
    return {'valid':True,'candidate_edges':n,'methods':len(METHODS),'decision_points':len(expected),
            'input_sha256':manifest['input_sha256'],'history_sha256':history_digest}


def evaluate_case(case_id,label,kind,rows,online,chains,source_rows,positive_ids,provenance):
    """Offline only: called after freeze_online has persisted every mask."""
    canon=lambda x:str(x).strip().upper()
    source={canon(r['event_id']):r for r in source_rows}
    candidate_index={canon(r['event_id']):i for i,r in enumerate(rows)}
    candidate=set(candidate_index)
    positive={canon(e) for e in positive_ids}
    reference_ids={canon(e) for c in chains for path in ([c.get('event_ids',[])]+c.get('branches',[])+[c.get('required_event_ids',[])]) for e in path}
    needed=reference_ids|positive
    source_ids=set(source)&needed
    source_small=[source[e] for e in sorted(source_ids)]
    temporal={canon(rows[i]['event_id']) for i in np.flatnonzero(online['reachable'])}
    results=[]
    for key,mask in online['masks'].items():
        method,ratio=key.split('@');kept={canon(rows[i]['event_id']) for i in np.flatnonzero(mask)}
        eligible={canon(rows[i]['event_id']) for i in np.flatnonzero(online['eligible'][method])}
        stages={'source':source_ids,'candidate':source_ids&candidate,
                'temporal_eligible':source_ids&candidate&temporal,
                'bundle_eligible':source_ids&candidate&temporal&eligible,
                'retained':source_ids&kept}
        evaluation=evaluate_chains(chains,source_small,stages)
        event_funnel=evaluate_event_funnel(positive,stages)
        end=evaluation['stages']['retained'];coverage=evaluation['stages']['candidate']
        # Paths and provenance live once per case. Avoid hundreds of MB of
        # repeated UUIDs for browser clients; full evaluation is reproducible.
        evaluation['chains']=[{k:r[k] for k in ('id','admission_status','source_validation','first_loss_stage')} | {'stages':{stage:{'complete':v['complete']} for stage,v in r['stages'].items()}} for r in evaluation['chains']]
        for event_stage in evaluation['event_funnel']['stages'].values():
            event_stage.pop('missing_ids',None);event_stage.pop('lost_ids',None)
        results.append({'method':method,'method_label':METHODS[method],'budget_ratio':float(ratio),
                        'budget_edges':int(len(rows)*float(ratio)),'retained_edges':int(mask.sum()),
                        'actual_compression':1-float(mask.mean()),
                        'complete_reference_retention':end['reference_chain_retention'],
                        'verified_attack_chain_retention':end['complete_chain_retention'],
                        'candidate_chain_coverage':coverage['reference_chain_retention'],
                        'conditional_reference_retention':_ratio(end['reference_chain_count'],coverage['reference_chain_count']),
                        'positive_event_retention':_ratio(len(kept&positive),len(positive)),
                        'positive_event_funnel':event_funnel,'chain_evaluation':evaluation,
                        'retained_event_ids':sorted(kept&needed),'diagnostics':{k:v for k,v in online['diagnostics'][key].items() if k!='selected_bundle_ids'}})
    display=[]
    for chain in chains:
        event_ids=list(dict.fromkeys([e for path in ([chain.get('event_ids',[])]+chain.get('branches',[])+[chain.get('required_event_ids',[])]) for e in path]))
        events=[]
        for event in event_ids:
            r=source.get(canon(event))
            if r is None:continue
            i=candidate_index.get(canon(event));evidence=None
            if i is not None:
                evidence={key:online['context'][i][key] for key in
                          ('novelty','contextual_surprise','confidence','anomaly_score','reason')}
                evidence.update(raw_rarity=online['candidate_inputs'][i]['rarity'],
                                score_rasp=float(online['scores']['rasp'][i]),
                                score_contextual=float(online['scores']['contextual'][i]))
            events.append({'event_id':canon(event),'src':r['src'],'dst':r['dst'],'src_label':r.get('src_semantic',r['src']),
                           'evidence':evidence,
                           'dst_label':r.get('dst_semantic',r['dst']),'relation':r['relation'],'timestamp_ns':str(r['timestamp_ns']),
                           'causal_direction':'dst_to_src' if r['relation']=='EVENT_EXECUTE' else 'src_to_dst'})
        display.append({**chain,'kind':chain.get('provenance',{}).get('kind','unreviewed_reference'),
                        'event_ids':[canon(e) for e in chain.get('event_ids',[])],
                        'branches':[[canon(e) for e in path] for path in chain.get('branches',[])],
                        'title':chain.get('title',chain['id']),'events':events})
    admitted=results[0]['chain_evaluation']['admitted_complete_chain_count'] if results else 0
    external=provenance.get('chain_reference_source',{}).get('kind')=='external_chain_manifest'
    scope=('合成完整真值；不代表真实数据泛化' if kind=='synthetic' else
           f'外部合同中已声明独立审核且范围完整的链：{admitted}；结构有效性另行验证' if admitted else
           '外部参考链合同；尚无满足独立审核与完整范围准入条件的攻击链' if external else
           'CAPTAIN 正例事件派生路径；未获得独立审核的完整攻击链真值')
    return {'id':case_id,'label':label,'kind':kind,'candidate_edges':len(rows),
            'reference_scope':scope,'admitted_complete_chain_count':admitted,
            'source_provenance':provenance,'reference_chains':display,'results':results,
            'online_seconds':online['online_seconds'],'input_sha256':online['input_sha256'],
            'history_count':online['history_count'],'history_cutoff_ns':str(online['cutoff_ns']),
            'context_summary':{'mean_novelty':float(np.mean([x['novelty'] for x in online['context']])),
                               'mean_confidence':float(np.mean([x['confidence'] for x in online['context']])),
                               'unknown_context_events':sum(x['confidence']==0 for x in online['context'])}}


def synthetic_case(seed,*,noise_count=1000,chain_count=6):
    """Fixed multi-stage attacks and novel benign branches; labels separate."""
    rng=np.random.default_rng(seed);rows=[];history=[];chains=[];positive=[]
    cutoff=1_000_000_000_000;step=1_000_000
    def row(e,a,b,t,rel='WRITE',rarity=.8,poi=False,program='service'):
        return dict(event_id=e,src=a,dst=b,src_type='process',dst_type='process',src_semantic='process:'+program,
                    dst_semantic='process:'+program,relation=rel,timestamp_ns=int(t),host='synthetic',is_declared_poi=poi,
                    components={'rarity':rarity})
    for c in range(chain_count):
        ids=[];nodes=[f'c{c}-v{i}' for i in range(6)]
        for j in range(5):
            e=f's{seed}-attack-{c}-{j}';ids.append(e)
            rows.append(row(e,nodes[j],nodes[j+1],cutoff+(j+1)*step,'EXECUTE' if j==2 else 'WRITE',.9 if j!=3 else .02,j==2))
        branch=[]
        for j,(a,b) in enumerate([(nodes[2],f'c{c}-branch'),(f'c{c}-branch',f'c{c}-sink')]):
            e=f's{seed}-branch-{c}-{j}';branch.append(e)
            rows.append(row(e,a,b,cutoff+(4+j)*step,'CONNECT',.85))
        chains.append({'id':f'synthetic-{seed}-{c}','event_ids':ids,'branches':[ids[:2]+branch],
                       'scope_complete':True,'provenance':{'kind':'synthetic','source':'fixed seeded generator v1'},
                       'scope':{'seed':seed,'required_branches':2}})
        positive.extend(ids+branch)
    for k in range(noise_count):
        c=int(rng.integers(chain_count));node=f'c{c}-v{int(rng.integers(1,5))}'
        rows.append(row(f's{seed}-benign-{k}',node,f'cache-{k}',cutoff+int(rng.integers(1,8))*step+int(rng.integers(1000)),
                        'READ',1.,False,'browser'))
    for program in ('service','browser'):
        h=row('history-'+program,'h-a','h-b',cutoff-1,'READ',.1,False,program);h['count']=1000;history.append(h)
    order=rng.permutation(len(rows));rows=[rows[i] for i in order]
    return {'rows':rows,'history':history,'cutoff_ns':cutoff,'chains':chains,'positive_ids':positive}


def export_figures(report,output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    colors={'rarity_only':'#9b8c75','diffusion_only':'#8c8ca5','rasp':'#596c85','contextual':'#50a4aa','chain_only':'#c78731','adaptive':'#067c61'}
    labels={'rarity_only':'Rarity only','diffusion_only':'Diffusion only','rasp':'RASP','contextual':'Contextual + diffusion','chain_only':'RASP + chains','adaptive':'Contextual + diffusion + chains'}
    cases=report['cases'];cols=3;fig,axes=plt.subplots(math.ceil(len(cases)/cols),cols,figsize=(15,4.2*math.ceil(len(cases)/cols)),squeeze=False)
    for ax,case in zip(axes.flat,cases):
        for method in METHODS:
            points=[r for r in case['results'] if r['method']==method and r['complete_reference_retention']['value'] is not None]
            points.sort(key=lambda r:r['actual_compression'])
            ax.plot([r['actual_compression']*100 for r in points],[r['complete_reference_retention']['value']*100 for r in points],marker='o',ms=3,color=colors[method],label=labels[method])
        ceiling=case['results'][0]['candidate_chain_coverage']['value']
        if ceiling is not None:ax.axhline(100*ceiling,ls='--',color='#baaaaa',lw=1,label='Candidate coverage ceiling')
        ax.set(xlim=(0,100),ylim=(-2,103),xlabel='Actual raw-event compression (%)',ylabel='Whole reference-chain retention (%)',title=case['label']+(' (synthetic)' if case['kind']=='synthetic' else ' (derived references)'))
        ax.grid(alpha=.16)
    for ax in list(axes.flat)[len(cases):]:ax.set_visible(False)
    axes.flat[0].legend(fontsize=7,loc='lower left')
    fig.suptitle('Compression vs. whole-reference retention\nReal references are derived, not independently verified complete attacks.',fontsize=12)
    fig.tight_layout(rect=(0,0,1,.94));output=Path(output);output.mkdir(parents=True,exist_ok=True)
    for ext in ('pdf','png','svg'):fig.savefig(output/f'compression-complete-reference.{ext}',dpi=180)
    plt.close(fig)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,default=ROOT/'configs/adaptive_chain_study.json')
    parser.add_argument('--synthetic-only',action='store_true');parser.add_argument('--publish',action='store_true')
    parser.add_argument('--chain-references',type=Path,help='offline JSON mapping cadets06/cadets12/cadets13 to chain lists; missing cases use derived references')
    parser.add_argument('--case',action='append',choices=['06','12','13'])
    parser.add_argument('--budgets',type=float,nargs='+',default=BUDGETS)
    parser.add_argument('--max-anchors',type=int,default=4096)
    parser.add_argument('--validate',action='store_true')
    args=parser.parse_args(argv)
    if args.validate:
        print(json.dumps(validate_frozen(args.output)));return
    args.output.mkdir(parents=True,exist_ok=False)
    report={'schema_version':'adaptive-chain-study-v1','generated_at':datetime.now(timezone.utc).isoformat(),
            'methodology':{'method_labels':METHODS,'ground_truth_used_for_selection':False,
                           'primary_metric':'whole reference chain, every required branch and event',
                           'real_truth_status':'derived references by default; external manifests require independent-review and complete-scope admission, reported per case',
                           'parameter_policy':'fixed before evaluation; development cases, no held-out claim',
                           'budgets':args.budgets,'candidate_extraction':'unchanged','actual_compression':'1 - retained raw events / candidate raw events'},'cases':[]}
    if not args.synthetic_only:
        from scripts.adaptive_chain_inputs import load_historical_rows,load_source_events,derive_reference_chains
        inputs=json.loads(args.inputs.read_text())['cases']
        for code in args.case or ['06','12','13']:
            spec=inputs[f'E3-CADETS/node_Nginx_Backdoor_{code}.csv'];ledger=resolve_input_path(spec['ledger'])
            database=resolve_input_path(spec['database']);annotation_path=resolve_input_path(spec['annotation'])
            print(f'CADETS-{code}: loading frozen candidates',flush=True)
            with gzip.open(ledger,'rt') as f:rows=[json.loads(line) for line in f]
            manifest=json.loads((ledger.parent/'manifest.json').read_text());cutoff=int(manifest['context']['frequency_cutoff_ns'])
            programs={r[side+'_semantic'] for r in rows for side in ('src','dst') if r.get(side+'_type')=='process' and r.get(side+'_semantic')}
            history,hp=load_historical_rows(database,cutoff,{r['host'] for r in rows},program_semantics=programs)
            print(f'CADETS-{code}: scoring {len(rows):,} events',flush=True)
            online=run_online(rows,history,cutoff,args.budgets,max_anchors=args.max_anchors)
            online['history_source']=hp
            frozen=args.output/f'cadets{code}';freeze_online(frozen,rows,online);validate_frozen(frozen)
            # FIRST access to the annotation; all online decisions are frozen.
            annotation=load_reference_annotation(annotation_path,code);positive=annotation['attack_event_ids']
            external_path=resolve_input_path(args.chain_references) if args.chain_references else None
            external=load_chain_references(external_path,'cadets'+code) if external_path else None
            required=set(positive)|(reference_event_ids(external) if external is not None else set())
            source=load_source_events(database,required)
            if external is None:
                chains,derived=derive_reference_chains(source,source='CAPTAIN:'+_hash(annotation_path))
                reference_source={'kind':'derived_positive_paths',
                                  'fallback_reason':'case_absent_from_external_manifest' if external_path else 'no_external_manifest'}
            else:
                chains=external;derived=None
                reference_source={'kind':'external_chain_manifest','case_id':'cadets'+code,
                                  'admission_policy':'independent review and complete scope required; no automatic promotion'}
            if external_path:
                reference_source.update(path=str(external_path),sha256=_hash(external_path))
            result=evaluate_case('cadets'+code,'CADETS-'+code,'real',rows,online,chains,source,positive,
                                 {'ledger_sha256':_hash(ledger),'annotation_sha256':_hash(annotation_path),
                                  'history':hp,'history_input_sha256':online['history_sha256'],
                                  'input_config_sha256':_hash(args.inputs),
                                  'annotation_source_metadata':annotation['metadata'],
                                  'upstream_annotation_sha256':spec.get('upstream_annotation_sha256'),
                                  'derived_references':derived,'chain_reference_source':reference_source,'frozen_artifacts':str(frozen.resolve())})
            report['cases'].append(result);_write(args.output/'report.json',report)
            print(f'CADETS-{code}: {len(chains)} reference chains; online {online["online_seconds"]:.2f}s',flush=True)
            del rows,history,online
    for seed in (101,202,303):
        data=synthetic_case(seed);rows=data['rows']
        online=run_online(rows,data['history'],data['cutoff_ns'],args.budgets,max_anchors=args.max_anchors)
        frozen=args.output/f'synthetic{seed}';freeze_online(frozen,rows,online);validate_frozen(frozen)
        report['cases'].append(evaluate_case('synthetic'+str(seed),'Synthetic-'+str(seed),'synthetic',rows,online,data['chains'],rows,data['positive_ids'],{'generator_seed':seed,'frozen_artifacts':str(frozen.resolve())}))
    _write(args.output/'report.json',report)
    with (args.output/'curve.csv').open('w',newline='') as f:
        writer=csv.writer(f);writer.writerow(['case','kind','method','budget_ratio','candidate_edges','retained_edges','actual_compression','complete_reference_chains','reference_chain_total','whole_reference_retention','verified_attack_chain_retention','positive_event_retention'])
        for case in report['cases']:
            for p in case['results']:
                metric=p['complete_reference_retention']
                writer.writerow([case['id'],case['kind'],p['method'],p['budget_ratio'],case['candidate_edges'],p['retained_edges'],p['actual_compression'],metric['numerator'],metric['denominator'],metric['value'],p['verified_attack_chain_retention']['value'],p['positive_event_retention']['value']])
    export_figures(report,args.output/'figures')
    if args.publish:
        _write(ROOT/'webapp/frontend/chain-study-results.json',report)
        for ext in ('pdf','png','svg'):
            import shutil
            shutil.copy2(args.output/f'figures/compression-complete-reference.{ext}',ROOT/f'docs/figures/adaptive-chain-compression.{ext}')
        import shutil
        shutil.copy2(args.output/'curve.csv',ROOT/'docs/adaptive-chain-curve.csv')
    print(json.dumps({'output':str(args.output.resolve()),'cases':len(report['cases']),'points':sum(len(c['results']) for c in report['cases'])}),flush=True)


if __name__=='__main__':main()
