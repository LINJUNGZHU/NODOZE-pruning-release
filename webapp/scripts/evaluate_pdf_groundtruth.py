"""Independent PDF-reference evaluation; prepares isolated browser caches too."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack
from tc_pruning.pdf_groundtruth import load_reference
from tc_pruning.context_graph import build_context,verify_context


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic', action='store_true',
                        help='Explicitly replay partial PDF labels; never a formal benchmark.')
    args=parser.parse_args()
    entries=json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text())
    policy_path=ROOT/'configs/benchmark-admission.json'
    policy=json.loads(policy_path.read_text()) if policy_path.is_file() else {'cases':{}}
    eligible=[];skipped=[]
    for entry in entries:
        review=policy['cases'].get(entry['id'], {})
        if review.get('formal_evaluation') is True:
            eligible.append(entry)
        else:
            reason=review.get('reason', 'Dataset has not passed ground-truth review.')
            skipped.append(dict(id=entry['id'],reason=reason))
            print('SKIP formal benchmark:',entry['id'],reason,flush=True)
    (ROOT/'docs').mkdir(parents=True,exist_ok=True)
    admission=dict(eligible=[e['id'] for e in eligible],skipped=skipped,
                   mode='diagnostic_only' if args.diagnostic else 'formal',
                   policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest() if policy_path.is_file() else None)
    (ROOT/'docs/benchmark-admission.json').write_text(json.dumps(admission,ensure_ascii=False,indent=2)+'\n')
    if not args.diagnostic and not eligible:
        print('No eligible PDF datasets; historical metrics and caches were not overwritten.')
        return
    selected=entries if args.diagnostic else eligible
    output_dir=ROOT/'docs/pdf-diagnostics' if args.diagnostic else ROOT/'docs'
    output_dir.mkdir(parents=True,exist_ok=True)
    reference=load_reference();results=[];catalog=[]
    folder=ROOT/'webapp/runtime/pdf-context-diagnostic' if args.diagnostic else ROOT/'webapp/runtime/pdf-context-browser'
    folder.mkdir(parents=True,exist_ok=True)
    for entry in selected:
        data=json.loads(Path(entry['cache_path']).read_text());edges=data['edges'];variants={}
        for detector in ('rules','neural','multiview'):
            started=time.monotonic();report=infer_attack(edges,data['poi']['event_id'],detector=detector)
            report['evaluation']=evaluate_attack(report,edges);pdf=report['evaluation']['pdf_benchmark']
            assert 'tapas_benchmark' not in report['evaluation']
            c=build_context(report,edges);assert verify_context(c,report,edges)
            ref_ids=set(pdf['reference_event_ids'])
            def coverage(context):
                ids=set(context['event_ids']);return dict(**context['summary'],pdf_events=len(ref_ids),pdf_matched=len(ids&ref_ids),
                    pdf_event_retention=len(ids&ref_ids)/len(ref_ids) if ref_ids else None)
            variants[detector]=dict(node_metrics=pdf['node_metrics'],pruning=pdf['pruning'],activity=pdf['activity'],paths=pdf['paths'],
                context=coverage(c),seconds=time.monotonic()-started,confirmed_nodes=pdf['labels'],
                predictions=[dict(id=n['id'],pids=n['pids'],label=n['label'],pdf_confirmed=n['id'] in pdf['labels']) for n in report['nodes'] if n['predicted_attack']])
            if detector=='rules':
                variants[detector]['ablations']={str(t):coverage(build_context(report,edges,{'boundary_processes':t})) for t in (2,10,1000000)}
                data['attack']=report;data['context_graph']=c;data['truth']['primary_evaluation']='PDF narrative with unknown nodes preserved'
                path=folder/(entry['id']+'.json');path.write_text(json.dumps(data,ensure_ascii=False,allow_nan=False))
                catalog.append(dict(entry,cache_path=str(path.resolve())))
                variants[detector]['resolved_agents']=pdf['agents'];variants[detector]['resources']=pdf['resources']
            print(entry['id'],detector,pdf['node_metrics']['tp'],pdf['node_metrics']['known_positive'],coverage(c),flush=True)
        results.append(dict(id=entry['id'],events=len(edges),variants=variants))
        output=dict(evaluation_mode=admission['mode'],admission=admission,pdf_source=reference['source'],pdf_sha256=reference['sha256'],protocol='Frozen detectors; PDF explicit positives only, other nodes unknown; same-host development windows, not independent held-out tests.',
            sources={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('tc_pruning/pdf_groundtruth.py','tc_pruning/context_graph.py','poi/optc-pdf-reference.json')},results=results)
        (output_dir/'pdf-groundtruth-evaluation.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
        (folder/'catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n')
    rows=[]
    for case in results:
        for detector,v in case['variants'].items():
            m=v['node_metrics'];c=v['context']
            rows.append(dict(case=case['id'],detector=detector,pdf_tp=m['tp'],pdf_positives=m['known_positive'],known_positive_recall=m['known_positive_recall'],unknown_predictions=m['unreviewed_predictions'],
                raw_events=case['events'],context_events=c['selected_events'],bundles=c['bundle_count'],pdf_reference_events=c['pdf_events'],pdf_context_matched=c['pdf_matched'],seconds=v['seconds']))
    with (output_dir/'pdf-groundtruth-evaluation.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)


if __name__=='__main__':main()
