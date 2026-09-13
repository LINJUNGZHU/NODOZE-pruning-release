"""Export measured comparison and its underlying CSV; no estimated gains."""
import csv
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[2]
report=json.loads((ROOT/'docs/multiview-evaluation.json').read_text())
rows=[]
for case in report['results']:
    for name,variant in case['variants'].items():
        rows.append(dict(case=case['id'],detector=name,public_recall=variant['public']['recall'],
            public_tp=variant['public']['tp'],public_fp=variant['public']['fp'],
            tapas_recall=variant['tapas']['recall'],seconds=variant['inference_seconds']))
with (ROOT/'docs/multiview-chart-data.csv').open('w') as f:
    writer=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator="\n");writer.writeheader();writer.writerows(rows)
names=['rules','neural','multiview'];labels=['Enhanced rules','Previous neural','Multi-view (experimental)']
fig,axes=plt.subplots(1,3,figsize=(12,3.6))
default=report['results'][0]['variants'];background=report['results'][-1]['variants']
for ax,title,values in zip(axes,['Default window: public recall','Default window: false positives','Background: false positives'],
    [[default[n]['public']['recall']*100 for n in names],[default[n]['public']['fp'] for n in names],[background[n]['public']['fp'] for n in names]]):
    ax.bar(range(3),values,color=['#596b7d','#b0b5bd','#b78649']);ax.set_xticks(range(3),labels,rotation=18,ha='right',fontsize=8)
    ax.set_title(title,fontsize=10);ax.spines[['top','right']].set_visible(False)
    ax.set_ylim(0,max(values)*1.2 if max(values)>0 else 1)
    for i,v in enumerate(values):ax.text(i,v,f'{v:g}',ha='center',va='bottom',fontsize=9)
fig.text(.5,.015,'Same-host development examples; anomaly fusion has not surpassed the rule baseline.',ha='center',fontsize=9)
fig.tight_layout(rect=(0,.07,1,1));folder=ROOT/'docs/figures';folder.mkdir(exist_ok=True)
for suffix in ('png','pdf'):fig.savefig(folder/f'multiview-results.{suffix}',dpi=180,bbox_inches='tight')
