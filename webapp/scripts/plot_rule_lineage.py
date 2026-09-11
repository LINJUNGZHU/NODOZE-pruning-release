"""Plot saved node/activity results without conflating label definitions."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
ROOT=Path(__file__).resolve().parents[2]
report=json.loads((ROOT/'docs/rule-lineage-evaluation.json').read_text())
rows=[next(r for r in report['results'] if r['id']==id and r['poi'].startswith('a6da')) for id in ['optc-0201','optc-0201-30m','optc-0201-60m']]
bg=next(r for r in report['results'] if r['id'].endswith('background'))
plt.rcParams.update({'axes.spines.top':False,'axes.spines.right':False,'font.size':10})
fig,axs=plt.subplots(2,2,figsize=(12,7.5),layout='constrained');x=np.arange(3);width=.35
for axis,key,title in [(axs[0,0],'public','Process recall: published attack labels'),(axs[0,1],'tapas','Process recall: TAPAS static list'),(axs[1,0],'activity_events','Activity-event recall: published labels')]:
 for j,(method,name,color) in enumerate([('legacy','Old rules','#93a8af'),('enhanced','Enhanced rules','#218776')]):
  values=[r[method][key]['recall']*100 for r in rows];bars=axis.bar(x+(j-.5)*width,values,width,label=name,color=color)
  axis.bar_label(bars,fmt='%.1f',padding=3,fontsize=9)
 axis.axhline(90,color='#bd7250',ls='--',lw=1,label='90% target');axis.set_ylim(0,115);axis.set_xticks(x,['10 min','30 min','60 min']);axis.set_ylabel('%');axis.set_title(title,loc='left',fontsize=11);axis.grid(axis='y',alpha=.12);axis.set_axisbelow(True)
axs[0,0].legend(fontsize=8,frameon=False,loc='lower right')
values=[bg[k]['public']['fp'] for k in ['legacy','enhanced']];bars=axs[1,1].bar(['Old rules','Enhanced rules'],values,color=['#93a8af','#218776'],width=.5);axs[1,1].bar_label(bars,padding=4);axs[1,1].set_title('Background window: false-positive processes',loc='left',fontsize=11);axs[1,1].set_ylim(0,max(values)+2)
fig.suptitle('Rule optimization: useful gains, different ground-truth scopes',fontsize=15,fontweight='bold')
fig.supxlabel('Same-host overlapping development windows. High published-label recall is not 90% TAPAS node recall or complete-path recovery.',fontsize=9)
for ext in ['png','pdf']:fig.savefig(ROOT/f'docs/figures/rule-lineage-results.{ext}',dpi=180)
