"""Paired focal-node / anchor-endpoint product feasibility benchmark, not attack evaluation."""
import argparse
import copy
import hashlib
import json
import platform
import resource
import time
from pathlib import Path

from tc_pruning.optc_investigation import rescore


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--catalog',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('docs/product/benchmark.json'))
    args=parser.parse_args();results=[]
    for entry in json.loads(args.catalog.read_text()):
        if entry.get('background'):continue
        path=Path(entry['cache_path']);file_digest=hashlib.sha256(path.read_bytes()).hexdigest()
        data=json.loads(path.read_text());anchor=data['poi']['event_id']
        edge=next(e for e in data['edges'] if e['id']==anchor)
        # Prefer the process endpoint of existing explicit anchor, never select using retained labels.
        node=edge['source'] if edge['source_type']=='process' else edge['target']
        budget=max(1,int(len(data['edges'])*.05));sets={}
        for mode in ('anchor_endpoints','node_focus'):
            t=time.monotonic();candidate=copy.deepcopy(data)
            for field in ('truth','attack','context_graph','poi_presets'):candidate.pop(field,None)
            rescore(candidate,anchor,budget/len(data['edges']),'evidence',
                    focal_node_id=node if mode=='node_focus' else None,pruning_only=True,budget_edges=budget)
            kept={e['id'] for e in candidate['edges'] if e['retained']};sets[mode]=kept
            cert=candidate['decision_certificate']
            valid=all(cert[k] for k in ('budget_valid','poi_preserved','temporal_links_valid','complete_witnesses','ledger_replayed'))
            assert valid and len(kept)<=budget
            results.append(dict(dataset_id=entry['id'],mode=mode,candidate_edges=len(data['edges']),
                candidate_nodes=candidate['metrics']['candidate_nodes'],budget_edges=budget,retained_edges=len(kept),
                event_reduction_ratio=1-len(kept)/len(data['edges']),
                retained_incident_to_focus=sum(e['retained'] and node in (e['source'],e['target']) for e in candidate['edges']),
                elapsed_seconds=round(time.monotonic()-t,4),certificate_valid=valid,
                node_id=node,anchor_event_id=anchor,source_cache_sha256=file_digest,
                process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
            del candidate
        overlap=len(sets['node_focus']&sets['anchor_endpoints'])/max(1,len(sets['node_focus']|sets['anchor_endpoints']))
        for row in results[-2:]:row['paired_retained_jaccard']=overlap
        assert hashlib.sha256(path.read_bytes()).hexdigest()==file_digest
        print(entry['id'],[(r['mode'],r['retained_edges'],r['elapsed_seconds']) for r in results[-2:]],flush=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(dict(platform=platform.platform(),python=platform.python_version(),
        protocol='single-process paired feasibility; 5% raw-event budget; existing explicit anchor; no truth evaluation',
        limitations=['One measured repetition; no p95/SLA','Peak RSS cumulative process high-water mark, not isolated method memory',
            'Existing anchors originate from historical demo presets; not evidence of automatic discovery',
            'No full event ground truth and no SPARSE reproduction'],results=results),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
