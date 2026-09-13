"""Standalone measured figures and their source CSV."""
import csv,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[2]
r=json.loads((ROOT/'docs/pdf-groundtruth-evaluation.json').read_text());cases=r['results'][:3]
rows=[]
for c in cases:
    v=c['variants']['rules'];m=v['context'];p=v['pruning']
    rows.append(dict(case=c['id'],raw=c['events'],saved_pruning=p['selected_events'],evidence_events=m['selected_events'],bundles=m['bundle_count'],
        pdf_reference=m['pdf_events'],saved_pruning_pdf_matched=p['matched_events'],evidence_pdf_matched=m['pdf_matched']))
with (ROOT/'docs/pdf-context-chart-data.csv').open('w') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
fig,axes=plt.subplots(1,2,figsize=(11,4));x=list(range(3));labels=['10 min','30 min','60 min']
for j,(key,label,color) in enumerate([('raw','Raw graph','#b7bdc2'),('saved_pruning','Saved budget pruning','#617180'),('evidence_events','Evidence graph','#aa804f')]):
    axes[0].bar([i+(j-1)*.25 for i in x],[row[key] for row in rows],width=.24,label=label,color=color)
axes[0].set_yscale('log');axes[0].set_ylabel('Original event count (log scale)');axes[0].set_xticks(x,labels);axes[0].legend(fontsize=8);axes[0].set_title('Investigation scope')
for j,(key,label,color) in enumerate([('saved_pruning_pdf_matched','Saved budget pruning','#617180'),('evidence_pdf_matched','Evidence graph','#aa804f')]):
    vals=[100*row[key]/row['pdf_reference'] for row in rows];pos=[i+(j-.5)*.34 for i in x]
    axes[1].bar(pos,vals,width=.32,label=label,color=color)
    for a,b in zip(pos,vals):axes[1].text(a,b+1,f'{b:.2f}',ha='center',fontsize=8)
axes[1].set_ylim(0,110);axes[1].set_ylabel('PDF reference event retention (%)');axes[1].set_xticks(x,labels);axes[1].set_title('Partial reference, not complete attack recall')
for ax in axes:ax.spines[['top','right']].set_visible(False)
fig.text(.5,.015,'Same-host overlapping development windows; different output objectives; predictions unchanged.',ha='center',fontsize=9)
fig.tight_layout(rect=(0,.06,1,1));out=ROOT/'docs/figures';out.mkdir(exist_ok=True)
for ext in ('png','pdf'):fig.savefig(out/f'pdf-context-results.{ext}',dpi=180,bbox_inches='tight')
