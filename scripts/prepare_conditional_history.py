"""Read-only historical split preparation, with explicit cold-start fallbacks."""
import argparse,gzip,hashlib,json,sqlite3,time
from pathlib import Path
import numpy as np
from tc_pruning.history_channel import ConditionalHistory,aggregate_history
from tc_pruning.sparse_edge_evaluation import sha256_file


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
 prefix=a.output_dir/f'case{a.case}';manifest=prefix.with_suffix('.json')
 if manifest.exists() or prefix.with_suffix('.npz').exists():raise ValueError('refuse overwrite')
 cfgpath=Path('configs/history_channel_v6.json');cfg=json.loads(cfgpath.read_text());ledger=Path(json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'][a.case]['ledger']);db=Path(cfg['history_databases'][a.case])
 start=time.perf_counter();key_index={};indices=[];keys=[];rarity=[];pois=[];ids=hashlib.sha256()
 with gzip.open(ledger,'rt') as stream:
  for line in stream:
   row=json.loads(line);key=(row['host'],row['relation'],row['src_type'],row['src_semantic'],row['dst_type'],row['dst_semantic'])
   if key not in key_index:key_index[key]=len(keys);keys.append(key)
   indices.append(key_index[key]);rarity.append(row['components']['rarity']);ids.update((row['event_id']+'\n').encode())
   if row.get('is_declared_poi'):pois.append(row['timestamp_ns'])
 origin=min(pois);fit_start=origin-int(cfg['history_fit_hours']*3600e9);fit_end=origin-int(cfg['history_fit_gap_minutes']*60e9);cal_end=origin-int(cfg['history_guard_minutes']*60e9)
 loaded=time.perf_counter()
 with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as connection:
  connection.execute('BEGIN')
  fit=aggregate_history(connection,fit_start,fit_end,cfg['history_bucket_ns']);cal=aggregate_history(connection,fit_end,cal_end,cfg['history_bucket_ns'])
 queried=time.perf_counter();model=ConditionalHistory(fit,cal,cfg['history_alpha'],cfg['history_minimum_support'])
 supported=np.array([model.supported(key) for key in keys]);percentile=np.array([model.percentile(key) if s else np.nan for key,s in zip(keys,supported)])
 ix=np.array(indices);original=np.array(rarity,float);mask=supported[ix];new=original.copy();new[mask]=(1-cfg['history_mix'])*original[mask]+cfg['history_mix']*percentile[ix[mask]]
 a.output_dir.mkdir(parents=True,exist_ok=True);tmp=prefix.with_suffix('.pending.npz');np.savez_compressed(tmp,rarity=new,ids_sha256=np.array(ids.hexdigest()),supported=mask);tmp.replace(prefix.with_suffix('.npz'))
 hist=prefix.with_suffix('.history.json.gz');tmp=hist.with_suffix('.pending')
 with gzip.open(tmp,'wt') as f:json.dump(dict(fit=[[list(k),v] for k,v in sorted(fit.items())],calibration=[[list(k),v] for k,v in sorted(cal.items())]),f)
 tmp.replace(hist)
 groups=sorted({key[:2] for key in keys});stats=[]
 for g in groups:
  dist=model.distributions.get(g);stats.append(dict(host=g[0],relation=g[1],fit_occupied_buckets=model.total[g],calibration_occupied_buckets=int(dist[1][-1]) if dist else 0,supported=bool(model.supported(next(k for k in keys if k[:2]==g)))))
 report=dict(case=a.case,ledger=str(ledger),ledger_sha256=sha256_file(ledger),database=str(db),database_size=db.stat().st_size,database_mtime_ns=db.stat().st_mtime_ns,
  origin_poi_ns=origin,fit_start_ns=fit_start,fit_end_ns=fit_end,calibration_end_ns=cal_end,fit_channels=len(fit),calibration_channels=len(cal),candidate_keys=len(keys),candidate_events=len(ix),supported_events=int(mask.sum()),groups=stats,
  npz_sha256=sha256_file(prefix.with_suffix('.npz')),history_sha256=sha256_file(hist),config_sha256=sha256_file(cfgpath),source_sha256={p:sha256_file(Path(p)) for p in ['tc_pruning/history_channel.py','scripts/prepare_conditional_history.py']},
  load_seconds=loaded-start,query_seconds=queried-loaded,total_seconds=time.perf_counter()-start,
  scope='historical edges with current node metadata snapshot, not certified benign or strictly online; logical aggregates stored, database provenance is size/mtime not whole-file hash')
 tmp=manifest.with_suffix('.pending');tmp.write_text(json.dumps(report,indent=2));tmp.replace(manifest)
 print(a.case,'supported',int(mask.sum()),'/',len(ix),'fit/cal',len(fit),len(cal),'seconds',round(report['total_seconds'],2),flush=True)

if __name__=='__main__':main()
