"""Run a registered case without opening references; freeze before evaluation.

python -m scripts.run_chain_workbench --case cadets13 --data-root /data/repo --output output/research/chain-workbench-v2/run/cadets13
"""
from __future__ import annotations
import argparse
import gc
import gzip
import json
from pathlib import Path
import resource
import time

from tc_pruning.chain_workbench import (ROOT,INPUT_FIELDS,prepare_evidence,run_variant,freeze_variant,validate_variant,write_json,digest)
from scripts.chain_workbench_inputs import expand_candidate_window
from scripts.chain_workbench_history import prepare_history,complete_missing_rarity


def load_ledger(path):
    rows=[]
    with gzip.open(path,'rt') as stream:
        for line in stream:
            r=json.loads(line)
            item={k:r.get(k) for k in INPUT_FIELDS if k!='rarity'}
            item['rarity']=r['components']['rarity'];item['timestamp_ns']=int(r['timestamp_ns'])
            item['is_declared_poi']=bool(r.get('is_declared_poi'));rows.append(item)
    return sorted(rows,key=lambda r:(r['timestamp_ns'],str(r['event_id'])))


def budgets_for(n,config,minimum):
    values=set(config['raw_budgets'])|{int(n*r) for r in config['ratio_budgets']}
    return sorted(b for b in values if minimum<=b<=n)


def run_case(spec,config,data_root,output):
    tick=time.perf_counter();output=Path(output);output.mkdir(parents=True,exist_ok=False)
    data_root=Path(data_root);ledger=data_root/spec['ledger'];database=data_root/spec['database']
    print(spec['id'],'load ledger',flush=True)
    rows=load_ledger(ledger);declared=[r['event_id'] for r in rows if r['is_declared_poi']]
    if not declared:raise ValueError('registered ledger has no declared anchors')
    lower=spec.get('start_ns',min(r['timestamp_ns'] for r in rows));upper=spec.get('end_ns',max(r['timestamp_ns'] for r in rows))
    tracks={'base':rows};candidate_diags={}
    if spec.get('expand_window'):
        print(spec['id'],'expand candidate window',flush=True)
        # Store flat rarity also under the compatibility key used by the reader;
        # the reader consumes no evaluation metadata.
        base=[dict(r,components={'rarity':r['rarity']}) for r in rows]
        expanded,diag=expand_candidate_window(database,base,start_ns=lower,end_ns=upper,poi_event_ids=declared,**config['expansion'])
        expanded,rarity_provenance=complete_missing_rarity(database,expanded,lower)
        for r in expanded:r['rarity']=r['components']['rarity']
        tracks['expanded']=expanded;candidate_diags['expanded']={**diag,'rarity_completion':rarity_provenance}
        del base
    union=tracks.get('expanded',rows)
    print(spec['id'],'load strict-past history',flush=True)
    history_source=data_root/spec['history_database'] if spec.get('history_database') else None
    history_cutoff=max(0,lower-int(config['expansion']['max_extension_seconds']*10**9)) if spec.get('expand_window') else lower
    history,hmeta=prepare_history(database,union,history_cutoff,history_database=history_source,max_recent_events=config['max_recent_history_events'])
    write_json(output/'registration.json',{'schema_version':'chain-workbench-case-registration-v2','case':spec,'config':config,
        'ledger_sha256':digest(ledger),'data_root':str(data_root.resolve()),'history':hmeta,'labels_opened':False})
    fixed_scope=len(union);variants=[]
    for track,candidates in tracks.items():
        print(spec['id'],track,'prepare evidence',len(candidates),'events',flush=True)
        evidence=prepare_evidence(candidates,history,history_cutoff)
        budgets=budgets_for(len(candidates),config,max(config['max_pois'],len(declared)))
        for policy in config['poi_policies']:
            start=time.perf_counter();print(spec['id'],track,policy,'start',flush=True)
            online=run_variant(candidates,evidence,policy,budgets,max_anchors=config['max_anchors'],max_hops=config['max_hops'],max_pois=config['max_pois'])
            folder=output/track/policy
            provenance={'ledger_sha256':digest(ledger),'initial_candidate_events':len(rows),'fixed_scope_events':fixed_scope,
                        'history':hmeta,'candidate_expansion':candidate_diags.get(track,{'policy':'original_frozen_candidates'}),
                        'config_sha256':__import__('hashlib').sha256(__import__('tc_pruning.chain_workbench',fromlist=['canonical']).canonical(config)).hexdigest(),
                        'original_declared_event_ids':declared,'poi_origin':'report_assisted_investigation_not_independent_detection',
                        'metadata_time_safety':'unverified_snapshot','legacy_rarity_source':'frozen_ledger; added rows use same completed-day legacy cache'}
            freeze_variant(folder,candidates,evidence,online,case_id=spec['id'],track=track,provenance=provenance)
            check=validate_variant(folder)
            variants.append({'track':track,'poi_policy':policy,'path':str(folder.relative_to(output)),
                             'manifest_sha256':digest(folder/'manifest.json'),**check})
            print(spec['id'],track,policy,'frozen',check['decision_points'],'points',round(time.perf_counter()-start,2),'seconds',flush=True)
            del online;gc.collect()
        del evidence;gc.collect()
    result={'schema_version':'chain-workbench-case-v2','id':spec['id'],'label':spec['label'],'provider':spec['provider'],
            'split':'development','labels_used':False,'variants':variants,'source_scope_events':fixed_scope,
            'registration_sha256':digest(output/'registration.json'),'elapsed_seconds':time.perf_counter()-tick,
            'peak_rss_mib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024}
    write_json(output/'case.json',result);print(spec['id'],'complete',round(result['elapsed_seconds'],2),'seconds',flush=True)
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,default=ROOT/'configs/chain_workbench_v2.json')
    p.add_argument('--case',required=True);p.add_argument('--data-root',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv);config=json.loads(args.config.read_text());spec=next((c for c in config['cases'] if c['id']==args.case),None)
    if spec is None:raise ValueError('case not registered')
    policy={k:v for k,v in config.items() if k not in ('cases','data_readiness')}
    run_case(spec,policy,args.data_root,args.output)


if __name__=='__main__':main()
