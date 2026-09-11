"""Standalone figures from the saved measurements; no hand-written scores."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
evaluation=json.loads((ROOT/'docs/deep-graph-evaluation.json').read_text())
training=json.loads((ROOT/'docs/deep-graph-training.json').read_text())
plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,'axes.titleweight':'bold'})
fig,axs=plt.subplots(1,3,figsize=(14,4.5),layout='constrained')
x=np.arange(3);w=.34
for j,(key,label,color) in enumerate([('rules','Rule baseline','#238b78'),('neural','Masked GNN + kNN','#c87855')]):
 rows=evaluation['examples'][:3]
 values=[r[key]['nodes']['recall']*100 for r in rows];bars=axs[0].bar(x+(j-.5)*w,values,w,label=label,color=color)
 axs[0].bar_label(bars,fmt='%.1f%%',padding=3,fontsize=9)
 values=[r[key]['nodes']['fp'] for r in rows];bars=axs[1].bar(x+(j-.5)*w,values,w,label=label,color=color)
 axs[1].bar_label(bars,padding=3,fontsize=9)
for a,title in zip(axs[:2],['Attack-process recall','False-positive processes']):
 a.set_title(title,loc='left');a.set_xticks(x,['10 min','30 min','60 min']);a.set_axisbelow(True);a.grid(axis='y',alpha=.15)
axs[0].set_ylim(0,60);axs[0].set_ylabel('%');axs[0].legend(loc='upper right',frameon=False,fontsize=8);axs[1].set_ylim(0,45)
for row in training['training']:
 curve=row['loss_history'];axs[2].plot([x['epoch'] for x in curve],[x['validation_loss'] for x in curve],label=f'Seed {row["seed"]}')
axs[2].set_title('Self-supervised validation loss',loc='left');axs[2].set_xlabel('Training epoch');axs[2].set_ylabel('Masked-feature MSE');axs[2].legend(frameon=False,fontsize=8)
fig.suptitle('OpTC exploratory evaluation — learned detector does not beat rules',fontsize=14,fontweight='bold')
fig.supxlabel('Same host; overlapping attack windows; 8 labeled attack processes. Frozen earlier calibration. No claim of generalization.',fontsize=9)
folder=ROOT/'docs/figures';folder.mkdir(exist_ok=True)
for suffix in ['png','pdf']:fig.savefig(folder/f'deep-graph-results.{suffix}',dpi=180)
