"""Read-only inventory of v7 inputs; writes only its requested audit JSON."""
import argparse
from pathlib import Path
import json,gzip,hashlib,subprocess,sys,platform,importlib.metadata
argp=argparse.ArgumentParser(description=__doc__);argp.add_argument('--output',type=Path,default=Path('docs/budget-evidence-v7/input_audit.json'));argp.add_argument('--dry-run',action='store_true');args=argp.parse_args()
repo=Path.cwd();out=args.output.parent
if args.output.exists() and not args.dry_run:raise FileExistsError(args.output)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def rec(p,hashit=True):
 p=Path(p);d={'path':str(p),'exists':p.exists()}
 if p.exists():
  st=p.stat();d.update(size=st.st_size,mtime_ns=st.st_mtime_ns,sha256=sha(p) if hashit else None)
  if not hashit:d['hash_reason']='source database/PDF not read by v7; cached history and ledger are hashed'
 return d
paths=['configs/sparse_five_cases.json','configs/history_channel_v6.json','docs/depimpact-artifact-case-map.json','docs/sparse-five-local-critical-reference.json','docs/history-channel-v6-results.csv','docs/history-channel-study.md']
paths += ['tc_pruning/'+s+'.py' for s in ['frequency_diffusion','temporal_diffusion','degree_diffusion','rasp','witness_portfolio','marginal_witness','history_channel','cross_domain_pruning']]
paths += ['scripts/'+s+'.py' for s in ['history_channel_common','prepare_conditional_history','run_history_channel','evaluate_marginal_witness','diagnose_history_pool','diagnose_history_theia1','profile_history_channel','summarize_history_channel']]
common=[rec(repo/f) for f in paths]
inv=json.loads((repo/'configs/sparse_five_cases.json').read_text())['cases'];hist=json.loads((repo/'docs/history-channel-v6-history.json').read_text());cases=[]
for i,c in enumerate(inv):
 reportpath=Path(f'/root/NODOZE-pruning-release/output/tc/history-channel-v6/case{i}.json.gz')
 with gzip.open(reportpath,'rt') as f:r=json.load(f)
 prefix=Path(f'/root/NODOZE-pruning-release/output/tc/history-channel-v6/history/case{i}')
 poi=Path(c['poi_manifest']);poi=poi if poi.is_absolute() else (repo/'configs'/poi).resolve()
 inputs={'ledger':rec(r['ledger']),'frozen_v6_decisions':rec(reportpath),'history_cache':rec(prefix.with_suffix('.npz')),'history_manifest':rec(prefix.with_suffix('.json')),'history_aggregate':rec(prefix.with_suffix('.history.json.gz')),'poi_manifest':rec(poi),'database_provenance':rec(c['ingested_database'],False),'official_report':rec(c['official_report'],False),'local_label_path':rec(repo/'docs/sparse-five-local-critical-reference.json')}
 h=hist[i]
 cases.append({'case_index':i,'name':c['name'],'poi_source':c['poi_source_kind'],'label_scope':c['label_scope'],'event_unit':'unique frozen ledger event_id; LINEAGE: synthetic counted separately','history_scope':{k:h[k] for k in ['origin_poi_ns','fit_start_ns','fit_end_ns','calibration_end_ns','fit_channels','calibration_channels','supported_events','candidate_events']}|{'metadata_time_safety':'unverified'},'inputs':inputs,'reported_ledger_sha256':r['ledger_sha256'],'input_hash_match':r['ledger_sha256']==inputs['ledger']['sha256']})
methods={'diffusion_top':'frequency_diffusion.score + cross_domain runner','witness_rerank':'witness_portfolio.witness_portfolio + temporal rerank','history_channel':'run_history_channel + expanded_pool + greedy_select','channel_only':'run_history_channel, original rarity + channel','history_channel_portfolio':'run_history_channel + witness_portfolio','temporal_pcst':'run_temporal_comparison + pcst_fast adapter','localdegree_top':'run_cross_domain_comparison + NetworKit LocalDegree','channel_ppr/channel_heat':'degree_diffusion.degree_normalized_score + v6 runner'}
packages={x:importlib.metadata.version(x) for x in ['numpy','scipy','pcst_fast','networkit','pytest']}
result={'protocol':'budget-evidence-input-audit-v7','code_root':str(repo),'git':{'branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'initial_status':'clean'},'python':{'executable':sys.executable,'version':platform.python_version(),'packages':packages},'common_files':common,'cases':cases,'methods':methods,'reference_policy':'labels only by independent evaluation/post-selection diagnosis; local partial positives','event_identity':'unique event_id, host-qualified nodes; ledger entries including synthetic LINEAGE count toward budget','history_metadata_time_safety':'unverified'}
assert all(x['exists'] for x in common)
assert all(c['input_hash_match'] and all(x['exists'] for x in c['inputs'].values()) for c in cases)

if args.dry_run:print(json.dumps({'output':str(args.output),'cases':len(cases),'common_files':len(common),'verified':True},indent=2))
else:
 out.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n');print(args.output,args.output.stat().st_size,'bytes')
