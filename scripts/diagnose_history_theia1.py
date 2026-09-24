import gzip,json
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups
from tc_pruning.marginal_witness import make_pool
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from scripts.history_channel_common import load_history,prepare_scores
from tc_pruning.sparse_edge_evaluation import sha256_file
with gzip.open('/root/NODOZE-pruning-release/output/tc/history-channel-v6/case2.json.gz','rt') as f:r=json.load(f)
for p,h in r['source_sha256'].items():assert sha256_file(Path(p))==h
cfg=r['config'];d=load_ledger(Path(r['ledger']));hist,_=load_history(2,cfg,d);g=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['channel_window_ns']);values,_,_=prepare_scores(d,cfg,hist,g,['history']);v=values['history_channel']
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
pool=make_pool(v,d['relation'],d['poi'],1024,d['tie'],(back,parent,pivot),cfg['marginal_pool_minimum']);candidate=np.isin(g,g[pool.anchors])&(pivot>=0)&(v>0)
# Only now read the local reference; none of this is used in selection.
refpath=Path('docs/sparse-five-local-critical-reference.json');ref=json.loads(refpath.read_text())['cases'][2];lookup={eid:i for i,eid in enumerate(d['ids'])};pos=np.array([lookup[e] for e in ref['critical_event_ids']]);records=[]
for ex in ref['exemplars']:
 ix=np.array([lookup[e] for e in ex['parallel_event_ids']]);records.append(dict(stage=ex['stage'],positive_events=len(ix),untruncated_channel_candidates=int(candidate[ix].sum()),group_count=len(set(g[ix])),minimum_score=float(v[ix].min()),maximum_score=float(v[ix].max()),minimum_raw_history_rarity=float(hist[ix].min()),maximum_raw_history_rarity=float(hist[ix].max())))
out=dict(scope='post-selection THEIA1 diagnostic; not selection/tuning input',reference_sha256=sha256_file(refpath),channel_candidates_before_cap=int(candidate.sum()),positive_anchors_before_cap=int(candidate[pos].sum()),total_positive=len(pos),groups=records)
Path('docs/history-channel-v6-theia1-diagnosis.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
