"""Fixed-cap materialization versus selection losses from measured partial labels."""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--results',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();report=json.loads(a.results.read_text())
    methods=['v7_group_edge','v8_group_edge','v8_expansion_edge'];labels=['V7','r3','r5'];colors=['#2c7a7b','#ed8936','#cbd5e0']
    fig,axes=plt.subplots(1,5,figsize=(14,3.8),sharey=True,layout='constrained')
    for i,ax in enumerate(axes):
        rows=[next(r for r in report['rows'] if r['case_index']==i and r['method']==m and r['budget']==1024) for m in methods]
        selected=[100*r['recall_known'] for r in rows];in_pool=[100*(r['pool_positive_recall']-r['recall_known']) for r in rows];outside=[100*(1-r['pool_positive_recall']) for r in rows]
        ax.bar(labels,selected,color=colors[0],label='Selected');ax.bar(labels,in_pool,bottom=selected,color=colors[1],label='In pool, omitted');ax.bar(labels,outside,bottom=[s+p for s,p in zip(selected,in_pool)],color=colors[2],label='Outside pool')
        ax.set_title(['FD1','FD3','THEIA1','THEIA3','TRACE5*'][i]);ax.set_ylim(0,100);ax.set_xlabel('Frozen revision')
    axes[0].set_ylabel('Known-positive events (%)');fig.legend(*axes[-1].get_legend_handles_labels(),fontsize=8,loc='lower center',bbox_to_anchor=(.5,-.08),ncol=3);fig.suptitle('B=1024; bounded pools cap=32768 raw ledger events; five development cases',fontsize=10)
    a.output.mkdir(parents=True,exist_ok=True)
    for ext in ('pdf','png'):fig.savefig(a.output/f'candidate-losses.{ext}',dpi=180,bbox_inches='tight')
    plt.close(fig)

if __name__=='__main__':main()
