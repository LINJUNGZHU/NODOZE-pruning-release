"""Label-free multi-anchor pruning with exact frozen decision artifacts.

This module never receives or opens evaluation labels. Legacy frequency values
are explicit inputs; contextual history is admitted only before the cutoff.
"""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import time

import numpy as np

from .adaptive_pois import reliability_rarity, select_adaptive_pois
from .adaptive_chains import build_chain_bundles, select_adaptive_bundles
from .contextual_rarity import ContextualRarityModel
from .rasp import propagate, temporal_routes, temporal_fork_routes, select_fork_bundles
from scripts.run_adaptive_chains import _arrays

ROOT=Path(__file__).resolve().parents[1]
METHODS={'rarity_only':'仅频率稀有度','diffusion_only':'仅图扩散','rasp':'RASP频率扩散',
         'context_v1':'上一版上下文融合','reliability':'置信度校准融合',
         'adaptive_v1':'上一版融合与整链','reliability_chain':'置信度校准与整链'}
INPUT_FIELDS=('event_id','src','dst','relation','timestamp_ns','host','src_type','dst_type','src_semantic','dst_semantic','is_declared_poi','rarity')
HISTORY_FIELDS=('src_type','dst_type','src_semantic','dst_semantic','relation','host','timestamp_ns','count')
SCORING=json.loads((ROOT/'configs/rasp_v1.json').read_text())
SOURCE_FILES=('tc_pruning/chain_workbench.py','tc_pruning/adaptive_pois.py','tc_pruning/adaptive_chains.py',
              'tc_pruning/contextual_rarity.py','tc_pruning/rasp.py','scripts/run_adaptive_chains.py','configs/rasp_v1.json',
              'scripts/run_chain_workbench.py','scripts/chain_workbench_inputs.py','scripts/chain_workbench_history.py',
              'scripts/adaptive_chain_inputs.py','tc_pruning/frequency.py','tc_pruning/frequency_cache.py','configs/chain_workbench_v2.json')


def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def write_json(path,value):
    Path(path).write_bytes(canonical(value)+b'\n')


def write_gzip(path,value):
    with Path(path).open('wb') as stream:
        with gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as compressed:compressed.write(canonical(value))


def read_gzip(path):
    with gzip.open(path,'rt') as stream:return json.load(stream)


def prepare_evidence(rows,history,cutoff_ns):
    ids=[str(r['event_id']).strip().upper() for r in rows]
    if not rows or any(not e for e in ids) or len(set(ids))!=len(rows):raise ValueError('unique nonempty candidate events required')
    for r in rows:
        t=r['timestamp_ns']
        if isinstance(t,bool) or not isinstance(t,(int,str)) or (isinstance(t,str) and not t.isdigit()) or int(t)<0:raise ValueError('exact nonnegative event timestamps required')
    if int(cutoff_ns)>min(int(r['timestamp_ns']) for r in rows):raise ValueError('history cutoff overlaps candidate interval')
    model=ContextualRarityModel().fit(history,cutoff_ns)
    context=model.score_rows(rows)
    raw=np.asarray([r.get('rarity',r.get('components',{}).get('rarity',context[i]['raw_rarity'])) for i,r in enumerate(rows)],float)
    calibrated=reliability_rarity(raw,context)
    old=.25*raw+.75*np.asarray([r['anomaly_score'] for r in context])
    inputs=[{k:r.get(k,1 if k=='count' else None) for k in HISTORY_FIELDS} for r in history if r['timestamp_ns']<cutoff_ns]
    return {'raw':raw,'reliability':calibrated,'context_v1':old,'context':context,'history':inputs,'cutoff_ns':int(cutoff_ns),
            'history_count':model.history_count,'input_ids':ids}


def _budget_contract(budgets,n,poi_count):
    if not isinstance(budgets,(list,tuple)) or not budgets or len(set(budgets))!=len(budgets):raise ValueError('nonempty unique budgets required')
    if any(isinstance(b,bool) or not isinstance(b,int) or not poi_count<=b<=n or b<1 for b in budgets):raise ValueError('raw budget must fit anchors and candidate count')
    return list(budgets)


def run_variant(rows,evidence,poi_policy,budgets,*,max_anchors=512,max_hops=64,max_pois=8):
    started=time.perf_counter()
    if evidence['input_ids']!=[str(r['event_id']).strip().upper() for r in rows]:raise ValueError('evidence order differs from candidate inputs')
    a=_arrays(rows);declared=np.flatnonzero(a['poi'])
    if not len(declared):raise ValueError('at least one declared investigation anchor required')
    first=min(declared,key=lambda i:(int(rows[i]['timestamp_ns']),str(rows[i]['event_id'])))
    original_ids=[str(rows[i]['event_id']) for i in declared]
    if poi_policy=='declared':
        poi=a['poi'].copy();poi_diag={'policy':'declared_report_assisted','suggested_event_ids':[],'ground_truth_used_for_suggestions':False}
    elif poi_policy in ('single','adaptive'):
        poi=np.zeros(len(rows),dtype=bool);poi[first]=True
        poi_diag={'policy':'earliest_declared_anchor','suggested_event_ids':[],'ground_truth_used_for_suggestions':False}
        if poi_policy=='adaptive':
            prior,_=propagate(a['src'],a['dst'],a['relation'],evidence['reliability'],poi,a['process'],SCORING)
            seed_rows=[dict(r,is_declared_poi=bool(poi[i])) for i,r in enumerate(rows)]
            poi,poi_diag=select_adaptive_pois(seed_rows,prior,max_pois=max_pois)
    else:raise ValueError('unknown POI policy')
    budgets=_budget_contract(budgets,len(rows),int(poi.sum()))
    a['poi']=poi;selected_rows=[dict(r,is_declared_poi=bool(poi[i])) for i,r in enumerate(rows)]
    poi_diag={**poi_diag,'original_declared_event_ids':original_ids,'selected_event_ids':[str(rows[i]['event_id']) for i in np.flatnonzero(poi)],
              'source_scope':'report-assisted investigation; added anchors are algorithm suggestions, not verified alerts'}
    scores={}
    for method,weights in [('rasp',evidence['raw']),('context_v1',evidence['context_v1']),('reliability',evidence['reliability']),('diffusion_only',np.zeros(len(rows)))]:
        scores[method]=propagate(a['src'],a['dst'],a['relation'],weights,poi,a['process'],SCORING)[0]
    scores['rarity_only']=evidence['raw'].copy();scores['rarity_only'][poi]=1.
    scores['adaptive_v1']=scores['context_v1'];scores['reliability_chain']=scores['reliability']
    back=temporal_routes(a['src'],a['dst'],a['timestamp'],poi)[0][0]
    parent,pivot,reachable,_=temporal_fork_routes(a['src'],a['dst'],a['timestamp'],poi,back)
    bundles={};bundle_diag={};eligible={m:reachable.copy() for m in METHODS}
    for method in ('adaptive_v1','reliability_chain'):
        bundles[method],bundle_diag[method]=build_chain_bundles(selected_rows,scores[method],max_anchors=max_anchors,max_hops=max_hops)
        for b in bundles[method]:
            if b['complete_in_candidate']:eligible[method][b['event_indices']]=True
    masks={};diagnostics={}
    for budget in budgets:
        for method in METHODS:
            tick=time.perf_counter();key=f'{method}@{budget}'
            if method in bundles:
                mask,diag=select_adaptive_bundles(selected_rows,scores[method],bundles[method],budget)
                diag={**{key:value for key,value in bundle_diag[method].items() if key!='eligible_event_ids'},**diag}
            else:
                mask,_=select_fork_bundles(scores[method],poi,back,parent,pivot,budget,a['tie'])
                diag={'retained_edges':int(mask.sum()),'unused_budget':int(budget-mask.sum())}
            if mask.sum()>budget or not np.all(mask[poi]) or np.any(mask&~eligible[method]):raise ValueError('selection violates budget, POI or eligibility contract')
            masks[key]=mask;diagnostics[key]={**diag,'selection_seconds':time.perf_counter()-tick}
    return {'poi':poi,'poi_policy':poi_policy,'poi_diagnostics':poi_diag,'scores':scores,'masks':masks,'eligible':eligible,
            'temporal':reachable,'bundles':bundles,'diagnostics':diagnostics,'budgets':budgets,'max_anchors':max_anchors,'max_hops':max_hops,
            'online_seconds':time.perf_counter()-started,'labels_used':False}


def freeze_variant(directory,rows,evidence,online,*,case_id,track,provenance):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    candidates=[]
    for i,r in enumerate(rows):
        item={k:r.get(k) for k in INPUT_FIELDS};item['rarity']=float(evidence['raw'][i])
        item['timestamp_ns']=str(int(r['timestamp_ns']));item['is_declared_poi']=bool(online['poi'][i]);candidates.append(item)
    write_gzip(directory/'candidates.json.gz',candidates)
    write_gzip(directory/'history.json.gz',evidence['history'])
    write_gzip(directory/'bundles.json.gz',online['bundles'])
    np.savez_compressed(directory/'decisions.npz',**online['masks'])
    np.savez_compressed(directory/'scores.npz',**online['scores'])
    np.savez_compressed(directory/'eligibility.npz',**online['eligible'],temporal=online['temporal'])
    np.savez_compressed(directory/'evidence.npz',raw=evidence['raw'],reliability=evidence['reliability'],context_v1=evidence['context_v1'],
                        confidence=np.asarray([x['confidence'] for x in evidence['context']]),surprise=np.asarray([x['contextual_surprise'] for x in evidence['context']]))
    manifest={'schema_version':'chain-workbench-frozen-v2','case_id':case_id,'track':track,'poi_policy':online['poi_policy'],
              'methods':list(METHODS),'budgets':online['budgets'],'candidate_events':len(rows),'poi_count':int(online['poi'].sum()),
              'poi_diagnostics':online['poi_diagnostics'],'diagnostics':online['diagnostics'],'online_seconds':online['online_seconds'],
              'cutoff_ns':str(evidence['cutoff_ns']),'history_count':evidence['history_count'],'labels_used':False,
              'history_support':{'unknown_context_events':sum(x['confidence']==0 for x in evidence['context']),
                                 'mean_confidence':float(np.mean([x['confidence'] for x in evidence['context']]))},
              'config':{'scoring':SCORING,'reliability_weight':.75,'max_anchors':online['max_anchors'],'max_hops':online['max_hops']},
              'provenance':provenance,'implementation':{f:digest(ROOT/f) for f in SOURCE_FILES},
              'artifacts':{p.name:digest(p) for p in directory.iterdir() if p.is_file()}}
    write_json(directory/'manifest.json',manifest)
    return manifest


def validate_variant(directory, *, strict_implementation=True):
    """Check frozen inputs, causal witnesses and decisions without rescoring.

    Hashes bind artifacts to their manifest; they are not a signature against a
    rewritten manifest. Graph, time, budget, evidence and source contracts are
    checked independently. Source matching is strict by default. Explicit
    structural-only validation reports a source mismatch rather than concealing
    it. Diffusion and the online selector are never rerun here.
    """
    directory=Path(directory);m=json.loads((directory/'manifest.json').read_text())
    if type(strict_implementation) is not bool:raise ValueError('strict_implementation must be boolean')
    expected_files={'candidates.json.gz','history.json.gz','bundles.json.gz','decisions.npz','scores.npz','eligibility.npz','evidence.npz'}
    if (not isinstance(m,dict) or m.get('schema_version')!='chain-workbench-frozen-v2'
            or m.get('labels_used') is not False or not isinstance(m.get('artifacts'),dict)
            or set(m['artifacts'])!=expected_files):raise ValueError('invalid frozen contract')
    def sha256(value):
        return isinstance(value,str) and len(value)==64 and set(value)<=set('0123456789abcdef')
    def integer(value,minimum=0):return type(value) is int and value>=minimum
    def decimal_time(value):
        if not isinstance(value,str) or not value.isascii() or not value.isdigit() or int(value)>2**63-1:
            raise ValueError('invalid exact timestamp string')
        return int(value)
    for name,value in m['artifacts'].items():
        if not sha256(value) or digest(directory/name)!=value:raise ValueError('artifact hash mismatch')
    implementation=m.get('implementation')
    if (not isinstance(implementation,dict) or set(implementation)!=set(SOURCE_FILES)
            or not all(sha256(value) for value in implementation.values())):
        raise ValueError('implementation source contract mismatch')
    implementation_matches=all((ROOT/name).is_file() and digest(ROOT/name)==value for name,value in implementation.items())
    if strict_implementation and not implementation_matches:raise ValueError('implementation source hash mismatch')
    config=m.get('config')
    if (not isinstance(config,dict) or set(config)!={'scoring','reliability_weight','max_anchors','max_hops'}
            or canonical(config['scoring'])!=canonical(SCORING) or config['reliability_weight']!=.75
            or not integer(config['max_anchors'],1) or not integer(config['max_hops'],1)):
        raise ValueError('frozen scoring configuration mismatch')
    if m.get('poi_policy') not in ('single','declared','adaptive'):raise ValueError('invalid POI policy')
    rows=read_gzip(directory/'candidates.json.gz')
    if not isinstance(rows,list) or not rows or not integer(m.get('candidate_events'),1) or len(rows)!=m['candidate_events']:
        raise ValueError('candidate dimensions mismatch')
    n=len(rows);ids=[];times=[]
    for row in rows:
        if not isinstance(row,dict) or set(row)!=set(INPUT_FIELDS) or type(row['is_declared_poi']) is not bool:
            raise ValueError('candidate whitelist or POI type mismatch')
        if any(not isinstance(row[key],str) or not row[key].strip() for key in ('event_id','src','dst','relation')):
            raise ValueError('candidate identities must be nonempty strings')
        if any(row[key] is not None and not isinstance(row[key],str) for key in ('host','src_type','dst_type','src_semantic','dst_semantic')):
            raise ValueError('candidate semantic metadata types mismatch')
        if type(row['rarity']) not in (int,float) or not np.isfinite(row['rarity']) or not 0<=row['rarity']<=1:
            raise ValueError('candidate raw rarity must be numeric in [0,1]')
        ids.append(row['event_id'].strip().upper());times.append(decimal_time(row['timestamp_ns']))
    if len(set(ids))!=n:raise ValueError('candidate identities mismatch')
    poi=np.array([row['is_declared_poi'] for row in rows],dtype=bool)
    if not integer(m.get('poi_count'),1) or int(poi.sum())!=m['poi_count']:raise ValueError('POI count mismatch')
    poi_diagnostic=m.get('poi_diagnostics')
    if not isinstance(poi_diagnostic,dict) or [row['event_id'] for row in rows if row['is_declared_poi']]!=poi_diagnostic.get('selected_event_ids'):
        raise ValueError('actual POI identity mismatch')
    if m.get('methods')!=list(METHODS):raise ValueError('method matrix mismatch')
    budgets=_budget_contract(m.get('budgets'),n,int(poi.sum()))
    cutoff=decimal_time(m.get('cutoff_ns'))
    if cutoff>min(times):raise ValueError('history cutoff overlaps frozen candidate interval')
    history=read_gzip(directory/'history.json.gz')
    if not isinstance(history,list):raise ValueError('history must be an input row list')
    for row in history:
        if (not isinstance(row,dict) or set(row)!=set(HISTORY_FIELDS)
                or not integer(row.get('timestamp_ns')) or row['timestamp_ns']>=cutoff
                or not integer(row.get('count'),1)):
            raise ValueError('invalid strict-past history input')
    if not integer(m.get('history_count')) or ContextualRarityModel().fit(history,cutoff).history_count!=m['history_count']:
        raise ValueError('history support mismatch')
    with np.load(directory/'scores.npz',allow_pickle=False) as data:
        if set(data.files)!=set(METHODS):raise ValueError('score methods mismatch')
        scores={key:data[key] for key in data.files}
        for value in scores.values():
            if value.shape!=(n,) or value.dtype.kind not in 'fiu' or not np.isfinite(value).all() or np.any(value<0):
                raise ValueError('invalid score values')
    if (not np.array_equal(scores['adaptive_v1'],scores['context_v1'])
            or not np.array_equal(scores['reliability_chain'],scores['reliability'])):
        raise ValueError('method score aliases differ')
    with np.load(directory/'evidence.npz',allow_pickle=False) as data:
        if set(data.files)!={'raw','reliability','context_v1','confidence','surprise'}:raise ValueError('evidence matrix mismatch')
        evidence={key:data[key] for key in data.files}
        if any(value.shape!=(n,) or value.dtype.kind not in 'fiu' or not np.isfinite(value).all()
               or np.any((value<0)|(value>1)) for value in evidence.values()):raise ValueError('invalid evidence values')
    raw=evidence['raw'];confidence=evidence['confidence'];surprise=evidence['surprise']
    if not np.array_equal(raw,np.asarray([row['rarity'] for row in rows])):raise ValueError('raw evidence identity mismatch')
    expected=(1-.75*confidence)*raw+.75*confidence*surprise
    if not np.allclose(expected,evidence['reliability'],rtol=1e-14,atol=1e-15):raise ValueError('reliability evidence mismatch')
    if not np.allclose(.25*raw+.75*confidence*surprise,evidence['context_v1'],rtol=1e-14,atol=1e-15):
        raise ValueError('legacy context evidence mismatch')
    expected_rarity=raw.copy();expected_rarity[poi]=1.
    if not np.array_equal(expected_rarity,scores['rarity_only']):raise ValueError('rarity score identity mismatch')
    support=m.get('history_support')
    if (not isinstance(support,dict) or not integer(support.get('unknown_context_events'))
            or support['unknown_context_events']!=int(np.count_nonzero(confidence==0))
            or type(support.get('mean_confidence')) not in (int,float)
            or not np.isclose(support['mean_confidence'],np.mean(confidence),rtol=1e-14,atol=1e-15)):
        raise ValueError('historical confidence diagnostics mismatch')

    # Reconstruct reachability from the actual raw/EXECUTE-corrected graph,
    # rather than accepting a supplied all-true eligibility certificate.
    arrays=_arrays(rows)
    backward=temporal_routes(arrays['src'],arrays['dst'],arrays['timestamp'],poi)[0][0]
    temporal=temporal_fork_routes(arrays['src'],arrays['dst'],arrays['timestamp'],poi,backward)[2]
    bundles=read_gzip(directory/'bundles.json.gz')
    if not isinstance(bundles,dict) or set(bundles)!={'adaptive_v1','reliability_chain'}:
        raise ValueError('bundle method structure mismatch')
    bundle_fields={'id','anchor_index','event_indices','paths','complete_in_candidate','boundary_status','scope'}
    derived_eligible={method:temporal.copy() for method in METHODS}
    earliest_in=np.full(len(arrays['process']),np.iinfo(np.int64).max,dtype=np.int64)
    latest_out=np.full(len(arrays['process']),-1,dtype=np.int64)
    np.minimum.at(earliest_in,arrays['dst'],arrays['timestamp'])
    np.maximum.at(latest_out,arrays['src'],arrays['timestamp'])
    for method,values in bundles.items():
        if not isinstance(values,list) or len(values)>max(config['max_anchors'],int(poi.sum())):
            raise ValueError('invalid bounded bundle list')
        seen_members=set()
        for position,bundle in enumerate(values):
            if (not isinstance(bundle,dict) or set(bundle)!=bundle_fields or bundle['id']!=f'bundle-{position+1}'
                    or type(bundle['complete_in_candidate']) is not bool
                    or bundle['boundary_status']!='candidate_boundary_unverified'
                    or bundle['scope']!='selected_observed_witnesses_only'):
                raise ValueError('invalid bundle scope or completeness fields')
            members=bundle['event_indices'];anchor=bundle['anchor_index'];paths=bundle['paths']
            if (not isinstance(members,list) or not members
                    or any(not integer(index) or index>=n for index in members)
                    or len(set(members))!=len(members)
                    or not integer(anchor) or anchor not in members or not temporal[anchor]):
                raise ValueError('invalid bundle event indices or anchor')
            member_set=frozenset(members)
            if member_set in seen_members:raise ValueError('duplicate bundle member set')
            seen_members.add(member_set)
            if not isinstance(paths,list) or not paths:raise ValueError('empty bundle paths')
            union=set();seen_paths=set()
            for path in paths:
                if (not isinstance(path,list) or not path or len(path)>config['max_hops']
                        or any(not integer(index) or index>=n for index in path)):
                    raise ValueError('invalid bounded path indices')
                if tuple(path) in seen_paths:raise ValueError('duplicate bundle path')
                seen_paths.add(tuple(path));union.update(path)
                for previous,current in zip(path,path[1:]):
                    if (arrays['timestamp'][previous]>=arrays['timestamp'][current]
                            or arrays['dst'][previous]!=arrays['src'][current]):
                        raise ValueError('bundle path violates strict time or causal direction')
                if bundle['complete_in_candidate']:
                    first,last=path[0],path[-1]
                    if (earliest_in[arrays['src'][first]]<arrays['timestamp'][first]
                            or latest_out[arrays['dst'][last]]>arrays['timestamp'][last]):
                        raise ValueError('complete bundle has a truncated temporal continuation')
            if union!=member_set:raise ValueError('bundle path union differs from required event set')
            # Individually valid paths must still form one observed witness.
            # Otherwise a disconnected maximal path could falsely admit events
            # that have no relationship to the investigation anchor.
            adjacency={}
            for index in members:
                src,dst=int(arrays['src'][index]),int(arrays['dst'][index])
                adjacency.setdefault(src,set()).add(dst);adjacency.setdefault(dst,set()).add(src)
            seen={int(arrays['src'][anchor])};pending=list(seen)
            while pending:
                for node in adjacency[pending.pop()]:
                    if node not in seen:seen.add(node);pending.append(node)
            if len(seen)!=len(adjacency):raise ValueError('bundle paths are not connected to their anchor')
            if bundle['complete_in_candidate']:
                if not np.any(poi[members]):raise ValueError('complete bundle lacks an investigation anchor')
                derived_eligible[method][members]=True
    with np.load(directory/'eligibility.npz',allow_pickle=False) as data:
        if set(data.files)!=set(METHODS)|{'temporal'}:raise ValueError('eligibility methods mismatch')
        for method in data.files:
            value=data[method];expected=temporal if method=='temporal' else derived_eligible[method]
            if value.dtype!=np.bool_ or value.shape!=(n,) or not np.array_equal(value,expected):
                raise ValueError('frozen eligibility differs from actual temporal graph and bundles')
    expected_keys={f'{method}@{budget}' for method in METHODS for budget in budgets}
    diagnostics=m.get('diagnostics')
    if not isinstance(diagnostics,dict) or set(diagnostics)!=expected_keys:raise ValueError('decision diagnostics matrix mismatch')
    with np.load(directory/'decisions.npz',allow_pickle=False) as data:
        if set(data.files)!=expected_keys:raise ValueError('decision matrix mismatch')
        for key in data.files:
            method,budget=key.split('@');value=data[key];budget=int(budget)
            if (value.dtype!=np.bool_ or value.shape!=(n,) or value.sum()>budget
                    or not np.all(value[poi]) or np.any(value&~derived_eligible[method])):
                raise ValueError('invalid frozen decision')
            count=int(value.sum());audit=diagnostics[key]
            if (not isinstance(audit,dict) or not integer(audit.get('retained_edges')) or audit['retained_edges']!=count
                    or not integer(audit.get('unused_budget')) or audit['unused_budget']!=budget-count):
                raise ValueError('decision diagnostics mismatch')
            if method in bundles:
                values=bundles[method];by_id={bundle['id']:bundle for bundle in values}
                completed=[bundle for bundle in values if bundle['complete_in_candidate'] and np.all(value[bundle['event_indices']])]
                selected=audit.get('selected_bundle_ids')
                anchor_limit=int(np.count_nonzero(temporal&((scores[method]>0)|poi)))>max(config['max_anchors'],int(poi.sum()))
                if (not isinstance(selected,list) or any(not isinstance(name,str) for name in selected)
                        or len(set(selected))!=len(selected)
                        or any(name not in by_id or not by_id[name]['complete_in_candidate']
                               or not np.all(value[by_id[name]['event_indices']]) for name in selected)
                        or audit.get('complete_attack_guarantee') is not False
                        or audit.get('budget_feasible') is not True
                        or not integer(audit.get('budget_edges')) or audit['budget_edges']!=budget
                        or not integer(audit.get('budget_overflow_edges')) or audit['budget_overflow_edges']!=0
                        or not integer(audit.get('retained_complete_bundles')) or audit['retained_complete_bundles']!=len(completed)
                        or not integer(audit.get('bundle_count')) or audit['bundle_count']!=len(values)
                        or not integer(audit.get('truncated_bundles')) or audit['truncated_bundles']!=sum(not b['complete_in_candidate'] for b in values)
                        or type(audit.get('anchor_limit_reached')) is not bool or audit['anchor_limit_reached']!=anchor_limit
                        or audit.get('max_hops')!=config['max_hops'] or audit.get('max_anchors')!=config['max_anchors']):
                    raise ValueError('bundle selection or resource diagnostics mismatch')
    return {'valid':True,'candidate_events':n,'decision_points':len(METHODS)*len(budgets),'poi_count':int(poi.sum()),
            'implementation_matches_current':implementation_matches,'strict_implementation':strict_implementation}
