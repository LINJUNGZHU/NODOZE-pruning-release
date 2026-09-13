"""Collect every fixed-protocol and exploratory row, with standalone plots."""
import argparse
import csv
import json
import statistics
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

NAMES={'cadets06':'CADETS 06','cadets12':'CADETS 12','cadets13':'CADETS 13','theia3':'THEIA 3'}

def main(source,output):
    reports=[];rows=[]
    for directory,label in NAMES.items():
        d=json.loads((source/directory/'results.json').read_text());assert d['truth']['baseline_exact_match']
        reports.append(d)
        rows.extend(dict(case=label,**r) for r in d['results'])
    assert len({json.dumps(d['implementation_sha256'],sort_keys=True) for d in reports})==1
    summary=[]
    for budget in reports[0]['config']['budgets']:
        for method in dict.fromkeys(r['method'] for r in rows):
            selected=[r for r in rows if r['budget_ratio']==budget and r['method']==method]
            assert len(selected)==4
            summary.append(dict(method=method,budget_ratio=budget,
                macro_entity_retention=statistics.mean(r['entity_retention'] for r in selected),
                micro_entity_retention=sum(r['retained_positive_entities'] for r in selected)/sum(r['positive_entities'] for r in selected),
                retained_positive_entities=sum(r['retained_positive_entities'] for r in selected),positive_entities=sum(r['positive_entities'] for r in selected),
                macro_core_event_retention=statistics.mean(r['core_event_retention'] for r in selected),
                micro_core_event_retention=sum(r['retained_core_events'] for r in selected)/sum(r['core_reference_events'] for r in selected),
                retained_positive_processes=sum(r['retained_positive_processes'] for r in selected),
                positive_processes=sum(r['positive_processes'] for r in selected),
                macro_process_retention=statistics.mean(r['process_retention'] for r in selected),
                macro_nonseed_entity_retention=statistics.mean(r['nonseed_entity_retention'] for r in selected),
                total_model_seconds=sum(r['model_seconds'] for r in selected)))
    output.mkdir(parents=True,exist_ok=True)
    result=dict(protocol='Same frozen candidates and edge caps; CSV positive retention only. Reserve variants are exploratory after first CADETS results.',
                rows=rows,summary=summary,reports=reports)
    (output/'social-propagation-results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    for filename,values in [('social-propagation-results.csv',rows),('social-propagation-summary.csv',summary)]:
        keys=list(dict.fromkeys(k for row in values for k in row))
        with (output/filename).open('w') as f:
            w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(values)
    plotted=[('rasp','RASP-D baseline','#6c757d'),('hybrid_relation_temporal','Temporal hybrid (primary)','#2166ac'),('reserve_0.25','25% reserve (exploratory)','#d97706')]
    fig,axes=plt.subplots(1,2,figsize=(12,4.6),layout='constrained')
    for ax,field,title in zip(axes,['entity_retention','core_event_retention'],['Labeled entity retention','Derived reference event retention']):
        for j,(method,label,color) in enumerate(plotted):
            vals=[next(r[field] for r in rows if r['case']==case and r['method']==method and r['budget_ratio']==.2)*100 for case in NAMES.values()]
            ax.bar([i+(j-1)*.25 for i in range(4)],vals,width=.24,label=label,color=color)
        ax.set_xticks(range(4),NAMES.values());ax.set_ylim(0,108);ax.set_ylabel('Retention (%)');ax.set_title(title)
        ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
    axes[0].legend(loc='lower left',fontsize=8)
    fig.suptitle('Same 20% edge cap · Development cases · Not classifier accuracy',fontsize=12)
    folder=output/'figures';folder.mkdir(exist_ok=True)
    fig.savefig(folder/'social-propagation-results.png',dpi=180)
    fig.savefig(folder/'social-propagation-results.pdf')
    plt.close(fig)
    for r in summary:
        if r['budget_ratio']==.2:print(r)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,default=Path('docs'))
    a=p.parse_args();main(a.source,a.output)
