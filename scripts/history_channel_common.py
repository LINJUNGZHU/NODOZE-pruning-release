"""Shared label-free setup for the v6 runner and fresh-process profiler."""
import hashlib,json,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import score
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.degree_diffusion import degree_normalized_score
from tc_pruning.history_channel import share_channel_scores
from tc_pruning.sparse_edge_evaluation import sha256_file


def load_history(case,cfg,data):
 prefix=Path(f'/root/NODOZE-pruning-release/output/tc/history-channel-v6/history/case{case}')
 metadata=json.loads(prefix.with_suffix('.json').read_text())
 if metadata['config_sha256']!=sha256_file(Path('configs/history_channel_v6.json')):raise ValueError('history config mismatch')
 for p,h in metadata['source_sha256'].items():
  if sha256_file(Path(p))!=h:raise ValueError('history source changed')
 for ext,key in [('.npz','npz_sha256'),('.history.json.gz','history_sha256')]:
  if sha256_file(prefix.with_suffix(ext))!=metadata[key]:raise ValueError('history cache mismatch')
 with np.load(prefix.with_suffix('.npz'),allow_pickle=False) as cache:
  ids=hashlib.sha256()
  for eid in data['ids']:ids.update((eid+'\n').encode())
  if str(cache['ids_sha256'])!=ids.hexdigest():raise ValueError('history event ordering mismatch')
  rarity=cache['rarity'].copy()
 if len(rarity)!=len(data['ids']) or not np.isfinite(rarity).all() or np.any((rarity<0)|(rarity>1)):raise ValueError('invalid calibrated rarity')
 return rarity,metadata


def prepare_scores(data,cfg,history_rarity,groups,kinds=None):
 kinds=kinds or ['original','history','nofrequency','ppr','heat'];values={};times={};diags={}
 for kind in kinds:
  tick=time.perf_counter();local=data if kind!='history' else data|dict(rarity=history_rarity)
  if kind in ['ppr','heat']:v,diag=degree_normalized_score(local,cfg,kind)
  else:v,diag=score(local,cfg,frequency=kind!='nofrequency')
  v*=temporal_affinity(data['timestamp'],data['timestamp'][data['poi']],cfg['temporal_scale_ns'])
  unshared_seconds=time.perf_counter()-tick
  shared=share_channel_scores(v,groups)
  values[kind]=v;values[kind+'_channel']=shared
  times[kind]=unshared_seconds;times[kind+'_channel']=time.perf_counter()-tick;diags[kind]=diag
 return values,times,diags
