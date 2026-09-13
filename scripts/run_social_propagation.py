"""Fixed-protocol social propagation ablations; labels opened after masks freeze."""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import io
import json
import resource
import sqlite3
import shutil
import time
import zipfile
from pathlib import Path
import numpy as np
from scripts.run_rasp import load_candidates
from tc_pruning.rasp import propagate,temporal_routes,temporal_fork_routes
from tc_pruning.rasp_diverse import event_families,select_diverse
from tc_pruning.social_propagation import channel_weights,temporal_propagation,select_reserved

ROOT=Path(__file__).resolve().parents[1]

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path,data):Path(path).write_text(json.dumps(data,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
def ratio(a,b):return a/b if b else None


def reference_window(window):
    if window is None:return None,None
    if len(window)!=2 or any(x is None for x in window) or window[0]>window[1]:
        raise ValueError('invalid reference time window')
    return tuple(window)


def verify_witnesses(d,back,parent,pivot,kept,anchors):
    """Replay selected anchors' witnesses; connectors need no alternative route."""
    rows=np.flatnonzero(anchors)
    assert np.all(kept[rows]) and np.all(pivot[rows]>=0)
    reverse_used=np.zeros(len(kept),dtype=bool)
    forward_used=np.zeros(len(kept),dtype=bool)
    for anchor in rows:
        j=int(anchor)
        while j>=0 and not forward_used[j]:
            assert kept[j]
            forward_used[j]=True
            previous=int(parent[j])
            if previous>=0:
                assert d['timestamp'][previous]<d['timestamp'][j]
                assert pivot[previous]==pivot[j]
                assert d['src'][j]==d['dst'][previous] or (pivot[previous]==previous and d['src'][j]==d['src'][previous])
            else:assert pivot[j]==j
            j=previous
        j=int(pivot[anchor])
        while j>=0 and not reverse_used[j]:
            assert kept[j]
            reverse_used[j]=True
            following=int(back[j])
            if following>=0:
                assert d['timestamp'][j]<d['timestamp'][following]
                assert d['dst'][j]==d['src'][following] or (d['poi'][following] and d['dst'][j]==d['dst'][following])
            else:assert d['poi'][j]
            j=following
    assert np.array_equal(kept,forward_used|reverse_used)


def evaluate_frozen(d,masks,spec,case,policy):
    audit=json.loads((ROOT/'docs/uploaded-groundtruth-evaluation.json').read_text())
    assert sha(ROOT/'docs/uploaded-groundtruth-evaluation.json')==policy['audit_sha256']
    item=next(x for x in audit['archive']['files'] if x['case_key']==case)
    archive=Path(audit['archive']['source']['path']);assert sha(archive)==audit['archive']['source']['sha256']
    with zipfile.ZipFile(archive) as z:blob=z.read(item['member'])
    assert hashlib.sha256(blob).hexdigest()==policy['cases'][case]['source_sha256']==item['sha256']
    labels={row[0].strip().upper() for row in csv.reader(io.StringIO(blob.decode('utf-8-sig')))}
    scope=item['evaluation']['derived_events'];start,end=reference_window(scope['protocol_window_ns'])
    database=Path(spec['database']);before=database.stat()
    core=set()
    with sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True) as conn:
        conn.execute('PRAGMA query_only=ON')
        matched={u:kind for u,kind in conn.execute('SELECT uuid,node_type FROM nodes') if u.upper() in labels}
        assert {u.upper() for u in matched}==labels
        placeholders=','.join('?' for _ in matched)
        for source in matched:
            for event,t in conn.execute(f'SELECT event_id,timestamp_ns FROM edges WHERE src=? AND dst IN ({placeholders})',[source,*matched]):
                if start is None or start<=t<=end:core.add(event.upper())
    after=database.stat();assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
    assert hashlib.sha256('\n'.join(sorted(core)).encode()).hexdigest()==scope['protocol_internal_event_ids_sha256']
    node_index={u.upper():i for i,u in enumerate(d['node_ids'])}
    positive=np.array([node_index[u] for u in labels if u in node_index],dtype=int)
    process_labels={u.upper() for u,k in matched.items() if k=='process'}
    process_positive=np.array([node_index[u] for u in process_labels if u in node_index],dtype=int)
    seeds=set(np.r_[d['src'][d['poi']],d['dst'][d['poi']]].tolist())
    nonseed=np.array([i for i in positive if i not in seeds],dtype=int)
    nonseed_total=len(labels-{u for u,i in node_index.items() if i in seeds})
    event_index={u.upper():i for i,u in enumerate(d['ids'])}
    core_index=np.array([event_index[e] for e in core if e in event_index],dtype=int)
    results={}
    for name,kept in masks.items():
        present=np.zeros(len(node_index),dtype=bool);present[d['src'][kept]]=True;present[d['dst'][kept]]=True
        tp=int(present[positive].sum());ep=int(kept[core_index].sum());pp=int(present[process_positive].sum())
        results[name]=dict(positive_entities=len(labels),retained_positive_entities=tp,entity_retention=ratio(tp,len(labels)),
            candidate_positive_entities=len(positive),positive_processes=len(process_labels),retained_positive_processes=pp,
            process_retention=ratio(pp,len(process_labels)),nonseed_positive_entities=nonseed_total,
            retained_nonseed_positive_entities=int(present[nonseed].sum()),nonseed_entity_retention=ratio(int(present[nonseed].sum()),nonseed_total),
            core_reference_events=len(core),candidate_core_events=len(core_index),retained_core_events=ep,core_event_retention=ratio(ep,len(core)),
            retained_nodes=int(present.sum()),missed_positive_entity_uuids=sorted(u for u in labels if u not in node_index or not present[node_index[u]]),
            classification_accuracy=None,precision=None,path_recall=None)
    # Confirm reproduced baseline with exact IDs, not just summary metrics.
    saved=json.loads(Path(spec['comparison']).read_text());primary=saved['primary_method']
    old=set()
    with gzip.open(spec['decisions'],'rt') as f:
        for line in f:
            r=json.loads(line)
            if r['decisions'][primary]:old.add(r['event_id'])
    current={e for e,k in zip(d['ids'],masks['rasp@0.2']) if k}
    if old!=current:raise AssertionError(f'baseline differs by {len(old^current)} IDs')
    return results,dict(csv_sha256=item['sha256'],archive_sha256=sha(archive),baseline_exact_match=True,
        reference_event_sha256=scope['protocol_internal_event_ids_sha256'],scope=scope['protocol_scope'],window_ns=[start,end])


def run(case,inputs,output,reserved=False):
    policy=json.loads((ROOT/'configs/benchmark-admission.json').read_text())
    if policy['cases'].get(case,{}).get('positive_node_retention') is not True:raise ValueError('case not admitted for positive retention')
    spec=json.loads(Path(inputs).read_text())['cases'][case]
    config=json.loads((ROOT/'configs/social_propagation_experiment.json').read_text())
    scoring=json.loads((ROOT/config['scoring_config']).read_text())
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    source_files=('tc_pruning/social_propagation.py','tc_pruning/rasp.py','tc_pruning/rasp_diverse.py','scripts/run_social_propagation.py')
    for file in source_files:
        target=output/'source'/file;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/file,target)
    started=time.perf_counter();d=load_candidates(Path(spec['ledger']));load_seconds=time.perf_counter()-started
    n=len(d['ids']);tick=time.perf_counter()
    score,_=propagate(d['src'],d['dst'],d['relation'],d['rarity'],d['poi'],d['process_nodes'],scoring)
    back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
    parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
    baseline_seconds=time.perf_counter()-tick
    families=event_families(d['src'],d['dst'],d['relation'])
    variants={'rasp':(score,back,parent,pivot,baseline_seconds)}
    for balanced in (False,True):
        tick=time.perf_counter()
        f,b=channel_weights(d['src'],d['dst'],d['relation'],d['rarity'],balanced,config['rarity_floor'])
        temporal,back2,parent2,pivot2=temporal_propagation(d['src'],d['dst'],d['timestamp'],d['poi'],f,b,d['tie'],config['survival'])
        seconds=time.perf_counter()-tick
        name='temporal_relation' if balanced else 'temporal_uniform'
        variants[name]=(temporal,back2,parent2,pivot2,seconds)
        if balanced:
            variants['temporal_relation_old_routes']=(temporal,back,parent,pivot,seconds+baseline_seconds)
            variants['hybrid_relation_temporal']=(np.sqrt(score*temporal),back2,parent2,pivot2,seconds+baseline_seconds)
    masks={};rows=[]
    for name,(rank,b,p,v,seconds) in variants.items():
        for budget_ratio in config['budgets']:
            budget=int(n*budget_ratio);tick=time.perf_counter()
            kept,anchors,_=select_diverse(rank,d['poi'],b,p,v,families,budget,d['tie'],config['quality_weight'])
            select_seconds=time.perf_counter()-tick
            assert kept.sum()<=budget and np.all(kept[d['poi']])
            verify_witnesses(d,b,p,v,kept,anchors)
            key=f'{name}@{budget_ratio:g}';masks[key]=kept
            rows.append(dict(method=name,budget_ratio=budget_ratio,budget=budget,candidate_events=n,retained_events=int(kept.sum()),
                retained_anchors=int(anchors.sum()),scoring_and_routes_seconds=seconds,selection_seconds=select_seconds,
                model_seconds=seconds+select_seconds,witness_valid=True,score_positive_events=int((rank>0).sum())))
            print(case,key,int(kept.sum()),flush=True)
    reserved_config=json.loads((ROOT/'configs/social_propagation_reserved.json').read_text()) if reserved else None
    if reserved:
        temporal,b2,p2,v2,temporal_seconds=variants['temporal_relation']
        for fraction in reserved_config['fractions']:
            for budget_ratio in config['budgets']:
                budget=int(n*budget_ratio);tick=time.perf_counter()
                kept,parts=select_reserved(score,temporal,d['poi'],(back,parent,pivot),(b2,p2,v2),families,budget,d['tie'],fraction)
                select_seconds=time.perf_counter()-tick
                verify_witnesses(d,back,parent,pivot,*parts[0]);verify_witnesses(d,b2,p2,v2,*parts[1])
                name=f'reserve_{fraction:g}';masks[f'{name}@{budget_ratio:g}']=kept
                rows.append(dict(method=name,budget_ratio=budget_ratio,budget=budget,candidate_events=n,retained_events=int(kept.sum()),
                    retained_anchors=int((parts[0][1]|parts[1][1]).sum()),scoring_and_routes_seconds=baseline_seconds+temporal_seconds,
                    selection_seconds=select_seconds,model_seconds=baseline_seconds+temporal_seconds+select_seconds,
                    witness_valid=True,score_positive_events=int(((score>0)|(temporal>0)).sum()),exploratory_followup=True))
                print(case,name,budget_ratio,int(kept.sum()),flush=True)
    # Save all choices before opening the ZIP, audit or annotation windows.
    mask_path=output/'frozen-decisions.npz'
    np.savez_compressed(mask_path,**masks,**{'score_'+k:v[0] for k,v in variants.items()})
    frozen_hash=sha(mask_path)
    freeze_seconds=time.perf_counter()-started
    metrics,truth_provenance=evaluate_frozen(d,masks,spec,case,policy)
    assert sha(mask_path)==frozen_hash
    for row in rows:row.update(metrics[f"{row['method']}@{row['budget_ratio']:g}"])
    report=dict(case=case,config=config,reserved_config=reserved_config,scoring_config=scoring,results=rows,input_ledger=str(spec['ledger']),
        input_ledger_sha256=sha(spec['ledger']),selection_input_sha256=d['input_sha256'],frozen_decisions_sha256=frozen_hash,
        implementation_sha256={p:sha(ROOT/p) for p in source_files},
        truth=truth_provenance,groundtruth_used_for_selection=False,poi_count=int(d['poi'].sum()),
        load_seconds=load_seconds,seconds_until_decisions_frozen=freeze_seconds,total_seconds=time.perf_counter()-started,
        peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
        scope='Frozen development candidates and analyst POIs; CSV positive entity retention, not attack-node classification or independently annotated attack paths.')
    dump(output/'results.json',report)
    print('COMPLETE',case,'seconds',report['total_seconds'],flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case',required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--reserved',action='store_true')
    a=p.parse_args();run(a.case,a.inputs,a.output,a.reserved)
