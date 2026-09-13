"""Train the paper-inspired model without reading attack ground truth."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT))
from tc_pruning.multiview import fit_model, DEFAULT_MODEL
from webapp.scripts.train_deep_graph import read_edges, SPLIT


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--epochs',type=int,default=60)
    parser.add_argument('--seed',type=int,default=913)
    parser.add_argument('--corpus',type=Path,default=ROOT/'webapp/runtime/optc-corpus.sqlite')
    parser.add_argument('--output',type=Path,default=DEFAULT_MODEL)
    args=parser.parse_args()
    splits=[read_edges(args.corpus,*SPLIT[name]) for name in ('train','validation','calibration')]
    print('Temporal split events:',[len(s) for s in splits],flush=True)
    report=fit_model(*splits,args.output,epochs=args.epochs,seed=args.seed)
    (args.output/'training.json').write_text(json.dumps(report,indent=2)+'\n')
    if args.output.resolve()==DEFAULT_MODEL.resolve():
        (ROOT/'docs/multiview-training.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['manifest'],indent=2),flush=True)
