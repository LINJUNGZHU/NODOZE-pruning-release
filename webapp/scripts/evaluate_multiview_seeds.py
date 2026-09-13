"""Evaluate declared additional seeds without selecting a replacement model."""
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tc_pruning.multiview import score_nodes
from tc_pruning.attack_evaluation import node_metrics


def main():
    results=[]
    for seed in (914,915):
        folder=ROOT/f'webapp/runtime/models/multiview-seed{seed}';cases=[]
        for entry in json.loads((ROOT/'webapp/runtime/examples/catalog.json').read_text()):
            data=json.loads(Path(entry['cache_path']).read_text());started=time.monotonic()
            scores=score_nodes(data['edges'],folder)
            predicted={nid for nid,row in scores['nodes'].items() if row['predicted']}
            labels=data['attack']['evaluation']
            cases.append(dict(id=entry['id'],seconds=time.monotonic()-started,
                **{k:node_metrics(set(labels[k]['labels']),predicted,labels[k]['labels']) for k in ('published_benchmark','tapas_benchmark')}))
            print(seed,entry['id'],cases[-1]['published_benchmark']['tp'],cases[-1]['published_benchmark']['fp'],flush=True)
        results.append(dict(seed=seed,weights_sha256=scores['weights_sha256'],cases=cases))
    (ROOT/'docs/multiview-seed-stability.json').write_text(json.dumps(dict(
        note='Seeds declared before evaluation; seed913 remains default rather than selecting the best test seed.',results=results),indent=2)+'\n')


if __name__=='__main__':main()
