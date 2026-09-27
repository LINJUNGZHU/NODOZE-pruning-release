"""Publication artifacts from executed V8 partial-positive results only."""
import argparse,json,statistics
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--results',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=json.loads(a.results.read_text());a.output.mkdir(parents=True,exist_ok=True)
    methods=sorted({r['method'] for r in report['summary']})
    fig,grid=plt.subplots(2,2,figsize=(11,8),layout='constrained');axes=grid.ravel()
    for method in methods:
        rows=sorted((r for r in report['summary'] if r['method']==method),key=lambda x:x['budget'])
        for ax,key in zip(axes,['macro_recall_known','macro_recall_incremental','group_any','group_full']):
            y=[100*r[key] if key.startswith('macro') else 100*statistics.mean(x[key] for x in report['rows'] if x['method']==method and x['budget']==r['budget']) for r in rows]
            ax.plot([r['budget'] for r in rows],y,marker='o',label=method)
    for ax,title in zip(axes,['Known-positive recall','Known-positive recall excluding POI','Reference group: any known member','Reference group: all known members']):
        ax.set_xscale('log',base=2);ax.set_xticks([64,256,1024,4096],labels=['64','256','1024','4096']);ax.set_ylim(0,101);ax.set_xlabel('Raw ledger-event budget');ax.set_ylabel('Macro recall (%)');ax.set_title(title);ax.grid(alpha=.2)
    axes[1].legend(fontsize=7,loc='lower right')
    fig.suptitle('Five development cases; partial positives; Case 5 uses inferred TRACE mapping',fontsize=9)
    for ext in ('pdf','png'):fig.savefig(a.output/f'budget-curves.{ext}',dpi=180)
    plt.close(fig)

if __name__=='__main__':main()
