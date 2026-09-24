"""Export cross-domain budget curves from independently evaluated selections."""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--results',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
a=p.parse_args();data=json.loads(a.results.read_text());a.output_dir.mkdir(parents=True,exist_ok=True)
names=['FiveDirections 1','FiveDirections 3','THEIA 1','THEIA 3','TRACE 5 (inferred)']
methods={'old_score_top':'Original score','diffusion_top':'Frequency + diffusion top-K','episode':'Temporal episode',
         'coverage_semantic':'Complete-episode coverage (v2)','pcst_native':'Public PCST adapter','localdegree_top':'Public LocalDegree adapter'}
for track in ('poi_only','shared_context'):
 fig,axes=plt.subplots(2,5,figsize=(18,7),sharey=True)
 for j,case in enumerate(data['cases']):
  for method,label in methods.items():
   rows=sorted([r for r in case['results'] if r['scenario']=='all' and r['track']==track and r['method']==method and r['status']=='ok'],key=lambda r:r['raw_cap'])
   axes[0,j].plot([r['raw_events'] for r in rows],[r['proxy_recall'] for r in rows],marker='o',markersize=3,label=label)
   axes[1,j].plot([r['raw_events'] for r in rows],[r['groups_hit']/r['groups_total'] for r in rows],marker='o',markersize=3,label=label)
  random=[r for r in case['random_summary'] if r['track']==track]
  axes[0,j].errorbar([r['raw_cap'] for r in random],[r['proxy_recall_mean'] for r in random],
     yerr=[r['proxy_recall_std'] for r in random],color='gray',ls=':',label='Random: mean +/- SD (5 seeds)')
  axes[0,j].set_title(names[j]);axes[1,j].set_xlabel('Actual retained raw events')
  for ax in axes[:,j]:ax.set_xscale('log',base=2);ax.set_xlim(.85,5000);ax.set_xticks([1,16,256,4096],['1','16','256','4096']);ax.set_ylim(-.03,1.03);ax.grid(alpha=.2)
 axes[0,0].set_ylabel('Partial-positive event recall');axes[1,0].set_ylabel('Local critical-group coverage')
 handles,labels=axes[0,0].get_legend_handles_labels();fig.legend(handles,labels,loc='lower center',ncol=4,fontsize=9)
 fig.suptitle(f'{track}: development cases; report-derived POIs; partial local labels; not official SPARSE metrics')
 fig.tight_layout(rect=(0,.09,1,.95))
 for suffix in ['png','pdf']:fig.savefig(a.output_dir/f'cross-domain-v2-{track}.{suffix}',dpi=180)
 plt.close(fig)
