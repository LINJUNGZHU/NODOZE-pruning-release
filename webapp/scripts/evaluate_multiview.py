"""Frozen-model comparisons; test labels are read only after inference."""
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tc_pruning.attack_inference import infer_attack
from tc_pruning.attack_evaluation import evaluate_attack,node_metrics
from tc_pruning.multiview import score_nodes,DEFAULT_MODEL,VIEWS
from webapp.scripts.verify_attack_report import verify


def main():
    results=[]
    manifest=json.loads((DEFAULT_MODEL/'manifest.json').read_text())
    for entry in json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text()):
        data=json.loads(Path(entry['cache_path']).read_text());edges=data['edges'];poi=data['poi']['event_id']
        started=time.monotonic();scores=score_nodes(edges);scoring_seconds=time.monotonic()-started
        variants={}
        for detector in ('rules','neural','multiview'):
            report=infer_attack(edges,poi,detector=detector,neural_scores=scores if detector=='multiview' else None)
            evaluation=evaluate_attack(report,edges,include_tapas=True);report['evaluation']=evaluation
            variants[detector]=dict(public=evaluation['published_benchmark']['node_metrics'],
                tapas=evaluation['tapas_benchmark']['node_metrics'],
                activity={k:v for k,v in evaluation['published_benchmark']['activity_event_metrics'].items() if not k.endswith('_event_ids')},
                summary=report['summary'],inference_seconds=report['runtime_seconds']+(scoring_seconds if detector=='multiview' else 0),
                predictions=[dict(id=n['id'],pids=n['pids'],label=n['label'],
                    views={k:dict(score=v['score'],percentile=v['percentile'],observations=len(v['evidence_event_ids'])) for k,v in n.get('multiview',{}).get('views',{}).items()},
                    votes=n.get('multiview',{}).get('votes'),
                    public=evaluation['published_benchmark']['labels'].get(n['id']),tapas=evaluation['tapas_benchmark']['labels'].get(n['id']))
                    for n in report['nodes'] if n['predicted_attack']])
            exported=set(report['path_event_ids'])|set(report['evidence_event_ids'])|set(report['activity_event_ids'])|set(report.get('context_event_ids',[]))
            variants[detector]['verification']=verify(dict(attack=report,events=[e for e in edges if e['id'] in exported]))
            if detector=='multiview':
                (ROOT/'webapp/runtime/examples'/f'{entry["id"]}-multiview-report.json').write_text(json.dumps(report,ensure_ascii=False))
        ablations={}
        for i,name in enumerate(VIEWS):
            predicted={nid for nid,row in scores['nodes'].items() if row['flags'][i]}
            ablations[name]={key:node_metrics(set(evaluation[key]['labels']),predicted,evaluation[key]['labels'])
                            for key in ('published_benchmark','tapas_benchmark')}
        results.append(dict(id=entry['id'],events=len(edges),variants=variants,ablations=ablations))
        print(entry['id'],{name:dict(public=v['public'],tapas=v['tapas']) for name,v in variants.items()},flush=True)
        output=dict(model=manifest,protocol='Same-host overlapping development windows; no attack-label threshold tuning. Rules remain default unless new results justify replacement.',
                    sources={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                             ('tc_pruning/multiview.py','tc_pruning/attack_story.py','tc_pruning/attack_inference.py')},results=results)
        (ROOT/'docs/multiview-evaluation.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
