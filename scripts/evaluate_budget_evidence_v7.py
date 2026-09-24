"""Independently evaluate frozen v7 selections against local partial positives."""
import argparse,csv,gzip,hashlib,json
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.alternative_witnesses import Witness,validate_witness
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.evaluate_frequency_diffusion import metrics
from scripts.run_cross_domain_comparison import structure


def read_gzip(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def evaluate_selection(selected_ids,mandatory_ids,reference,candidates):
    if selected_ids is None:
        return dict(tp_known=None,recall_known=None,precision_proxy=None,f1_proxy=None,group_any=None,group_full=None,
                    recall_incremental=None,proxy_fp=None,proxy_fn=None,official_equivalent={k:None for k in ['fp','fn','precision','recall','f1']})
    selected=set(selected_ids);mandatory=set(mandatory_ids)
    if len(selected)!=len(selected_ids) or not mandatory<=selected:raise ValueError('invalid selection identity or missing mandatory')
    m=metrics(selected_ids,reference,candidates)
    pos=set(reference['critical_event_ids']);new_pos=pos-mandatory
    full=sum(set(ex['parallel_event_ids'])<=selected for ex in reference['exemplars'])
    return dict(tp_known=m['proxy_tp'],recall_known=m['proxy_recall'],precision_proxy=m['proxy_precision'],f1_proxy=m['proxy_f1'],
                proxy_fp=m['proxy_fp'],proxy_fn=m['proxy_fn'],proxy_tn=m['proxy_tn'],group_any=m['groups_hit']/m['groups_total'] if m['groups_total'] else None,
                group_full=full/len(reference['exemplars']) if reference['exemplars'] else None,groups_hit=m['groups_hit'],groups_total=m['groups_total'],
                group_full_hit=full,stages_hit=m['stages_hit'],stages_total=m['stages_total'],
                recall_incremental=len((selected-mandatory)&new_pos)/len(new_pos) if new_pos else None,
                mandatory_positive=len(mandatory&pos),official_equivalent=m['official_equivalent'])


def verify_pool_selection(decision,pool,data,id_to_index):
    actions={a['witness_id']:a for a in pool['actions']};chosen=decision['witness_ids'];anchors=decision['anchor_ids']
    if chosen is None or anchors is None or len(chosen)!=len(set(chosen)):raise ValueError('missing/duplicate certificates')
    if len(anchors)!=len(set(anchors)) or len(anchors)!=len(chosen):raise ValueError('anchor and witness count mismatch')
    closed=set(decision['mandatory_ids']);verified=0
    for anchor,wid in zip(anchors,chosen):
        if wid not in actions:raise ValueError('certificate outside frozen pool')
        a=actions[wid]
        if a['anchor_id']!=anchor:raise ValueError('anchor-certificate mismatch')
        closed.update(a['event_ids'])
        f=tuple(id_to_index[e] for e in a['forward_chain']);b=tuple(id_to_index[e] for e in a['backward_chain'])
        w=Witness(id_to_index[anchor],tuple(sorted(id_to_index[e] for e in a['event_ids'])),f,b,a['rule'],wid)
        if not validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']):raise ValueError('invalid temporal certificate')
        verified+=1
    if closed!=set(decision['selected_ids']):raise ValueError('selected IDs differ from witness union')
    return verified


def evaluate(input_dir,output):
    output=Path(output)
    if output.exists() or output.with_suffix('.csv').exists():raise FileExistsError(output)
    refpath=Path('docs/sparse-five-local-critical-reference.json');reference=json.loads(refpath.read_text())
    audit=json.loads(Path('docs/budget-evidence-v7/input_audit.json').read_text())
    rows=[];case_summaries=[]
    for i,ref in enumerate(reference['cases']):
        mpath=Path(input_dir)/f'case{i}'/'manifest.json.gz';manifest=read_gzip(mpath)
        if manifest['labels_used_for_selection'] or manifest['case_index']!=i:raise ValueError('invalid case manifest')
        if manifest['ledger_sha256']!=ref['ledger_sha256'] or manifest['ledger_sha256']!=audit['cases'][i]['inputs']['ledger']['sha256']:raise ValueError('ledger/reference mismatch')
        for source,h in manifest['source_sha256'].items():
            if sha256_file(Path(source))!=h:raise ValueError('executed source changed: '+source)
        ledger=Path(audit['cases'][i]['inputs']['ledger']['path']);d=load_ledger(ledger);universe=set(d['ids']);id_to_index={eid:j for j,eid in enumerate(d['ids'])}
        if len(universe)!=len(d['ids']):raise ValueError('duplicate ledger ID')
        old=read_gzip(audit['cases'][i]['inputs']['frozen_v6_decisions']['path'])
        cached={}
        for item in manifest['runs']:
            path=Path(item['path'])
            if sha256_file(path)!=item['sha256']:raise ValueError('decision hash mismatch')
            x=read_gzip(path)
            if x['ledger_sha256']!=manifest['ledger_sha256'] or x['config_sha256']!=manifest['config_sha256'] or x['source_sha256']!=manifest['source_sha256']:raise ValueError('decision inputs mismatch')
            if x['status']!='ok':
                if x['selected_ids'] is not None or x['objective_value'] is not None:raise ValueError('infeasible result has selection')
                met=evaluate_selection(None,x['mandatory_ids'],ref,len(universe));valid=None
            else:
                selected=x['selected_ids'];mand=set(x['mandatory_ids'])
                if len(selected)!=len(set(selected)) or not set(selected)<=universe or not mand<=set(selected) or len(selected)>x['budget']:raise ValueError('ID/mandatory/budget violation')
                if x['n_selected_ledger']!=len(selected) or x['n_selected_synthetic']!=sum(e.startswith('LINEAGE:') for e in selected) or x['n_selected_cdm']+x['n_selected_synthetic']!=len(selected):raise ValueError('raw/CDM/synthetic counts disagree')
                if x['pool_sha256']:
                    poolpath=Path(item['pool_path'])
                    if sha256_file(poolpath)!=x['pool_sha256']:raise ValueError('pool hash mismatch')
                    if poolpath not in cached:cached[poolpath]=read_gzip(poolpath)
                    verified=verify_pool_selection(x,cached[poolpath],d,id_to_index)
                    valid=1. if verified==len(x['witness_ids']) else None
                else:
                    if not x['matched_frozen_ids']:raise ValueError('unverified E0 reuse')
                    prior=next(r for r in old['results'] if r['scenario']=='all' and r['track']=='poi_only' and r['method']==x['method'] and r['raw_cap']==x['budget'])
                    if set(prior['selected_ids'])!=set(selected):raise ValueError('E0 source ID mismatch')
                    # The frozen portfolio has no saved per-anchor certificate.
                    # Its structural reachability fraction is not a validation pass rate.
                    valid=None
                met=evaluate_selection(selected,x['mandatory_ids'],ref,len(universe))
            pooldiag=x.get('candidate_diagnostics') or {}
            row=dict(run_id=x['run_id'],dataset='DARPA TC E3',campaign_id=ref['name'],case_id=i,split='development',method=x['method'],
                baseline_status='native_reproduced' if x['run_id'].startswith('e0') else 'native_new',track=x['track'],budget=x['budget'],seed=None,
                scoring_id='v4_original' if x['method']=='witness_rerank' else 'v6_history_channel',candidate_policy=pooldiag.get('representation'),
                pool_hash=x['pool_sha256'],path_contract_hash=hashlib.sha256(json.dumps({
                    key:manifest['source_sha256'][key] for key in ('tc_pruning/rasp.py','tc_pruning/alternative_witnesses.py')
                },sort_keys=True).encode()).hexdigest(),objective=x['objective'],
                n_group_refs=pooldiag.get('n_group_refs'),n_potential_members=pooldiag.get('n_potential_members'),
                n_materialized_events=pooldiag.get('n_materialized_events',pooldiag.get('materialized_events')),
                n_executable_anchors=pooldiag.get('n_executable_anchors',pooldiag.get('anchors')),n_witnesses=pooldiag.get('n_witnesses',pooldiag.get('witnesses')),
                n_selected_ledger=x['n_selected_ledger'],n_selected_cdm=x['n_selected_cdm'],n_selected_synthetic=x['n_selected_synthetic'],
                witness_complete=None,time_path_validity=valid,objective_value=x['objective_value'],solver_bound=None,solver_gap=None,
                history_fallback_rate=1-audit['cases'][i]['history_scope']['supported_events']/len(universe),
                cold_seconds=None,warm_seconds=None,selection_seconds=x['selection_seconds'],peak_rss_mib=manifest['peak_rss_mib'],
                status=x['status'],source_hash=manifest['source_sha256']['scripts/run_budget_evidence_v7.py'],config_hash=x['config_sha256'],input_hash=x['ledger_sha256'])
            if x['status']=='ok':
                mask=np.zeros(len(d['ids']),bool);mask[[id_to_index[e] for e in x['selected_ids']]]=True
                row.update(structure(d,mask));row['budget_utilization']=len(x['selected_ids'])/x['budget']
            else:row.update(components=None,poi_component_fraction=None,temporal_fork_fraction=None,budget_utilization=None)
            row.update(met);rows.append(row)
        case_summaries.append(dict(case_index=i,name=ref['name'],manifest_path=str(mpath),manifest_sha256=sha256_file(mpath),candidate_events=len(universe),runs=len(manifest['runs']),elapsed_seconds=manifest['elapsed_seconds'],peak_rss_mib=manifest['peak_rss_mib']))
        print('EVALUATED',i,len(manifest['runs']),flush=True)
    result=dict(protocol='budget-evidence-v7-local-partial-positive-proxy',reference_sha256=sha256_file(refpath),scope='five previously used development cases; official SPARSE-equivalent metrics unavailable',cases=case_summaries,results=rows)
    output.parent.mkdir(parents=True,exist_ok=True);tmp=output.with_suffix('.pending');tmp.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n');tmp.replace(output)
    csvpath=output.with_suffix('.csv');flat=[]
    for r in rows:
        flat.append({k:(json.dumps(v,ensure_ascii=False) if isinstance(v,dict) else v) for k,v in r.items()})
    with csvpath.open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0]),lineterminator='\n');w.writeheader();w.writerows(flat)
    print('SAVED',output,len(rows),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();evaluate(a.input_dir,a.output)


if __name__=='__main__':main()
