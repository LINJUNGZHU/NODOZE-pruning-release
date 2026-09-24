"""Export recall/budget curves for the frozen local development reference."""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

p=argparse.ArgumentParser();p.add_argument('--results',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();data=json.loads(a.results.read_text())
fig,axes=plt.subplots(2,5,figsize=(16,6),sharex=True,sharey=True)
names=['FiveDirections 1','FiveDirections 3','THEIA 1','THEIA 3','TRACE 5 (inferred)']
methods={'classic_hybrid':'Classic + existing rules','full_hybrid':'New + existing rules','burst_hybrid':'New + occupancy + rules','old_score_top':'Original score top-K'}
for j,case in enumerate(data['cases']):
    for method,label in methods.items():
        rows=sorted([r for r in case['results'] if r['method']==method],key=lambda r:r['raw_cap'])
        axes[0,j].plot([r['raw_events'] for r in rows],[r['proxy_recall'] for r in rows],marker='o',label=label)
        axes[1,j].plot([r['raw_events'] for r in rows],[r['groups_hit']/r['groups_total'] for r in rows],marker='o',label=label)
    axes[0,j].set_title(names[j]);axes[1,j].set_xlabel('Retained raw events')
    for ax in axes[:,j]:ax.set_xscale('log',base=2);ax.set_xticks([64,256,1024,4096],['64','256','1024','4096']);ax.set_ylim(-.03,1.03);ax.grid(alpha=.25)
axes[0,0].set_ylabel('Partial-positive event recall');axes[1,0].set_ylabel('Local critical-group coverage')
handles,labels=axes[0,0].get_legend_handles_labels();fig.legend(handles,labels,loc='lower center',ncol=4)
fig.suptitle('Development cases; frozen oracle POIs and partial local labels; not official SPARSE metrics')
fig.tight_layout(rect=(0,.06,1,.95));fig.savefig(a.output,dpi=180);fig.savefig(a.output.with_suffix('.pdf'))
