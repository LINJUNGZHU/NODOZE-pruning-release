"""Offline verification of a downloaded decision audit, no truth needed."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.evidence_selection import audit_selection, validate_routes, select_evidence, witness_bundle
from tc_pruning.rasp_diverse import select_diverse


def verify(data, replay_ranking=True):
    x=data['decision_inputs'];cert=data['decision_certificate']
    digest=hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if digest!=cert['inputs_sha256']:raise ValueError('Input digest mismatch')
    ids={s:i for i,s in enumerate(x['event_ids'])}
    arrays={k:np.array(v) for k,v in x.items() if isinstance(v,list) and k!='event_ids'}
    validate_routes(arrays['src'],arrays['dst'],arrays['timestamp_ns'],arrays['poi'],arrays['backward'],arrays['parent'],arrays['pivot'])
    trace=[dict(r,anchor=ids[r['anchor']],new_edges=[ids[e] for e in r['new_edges']]) for r in data['decision_trace']]
    if data['decision_contract']['mode']=='context':
        selected,anchors,expected=select_diverse(arrays['propagation_score'],arrays['poi'],arrays['backward'],arrays['parent'],arrays['pivot'],arrays['legacy_family'],x['budget'],arrays['tie_order'],x['quality'],record_audit=True)
        if not np.array_equal(selected,arrays['retained']) or expected['trace']!=trace:
            raise ValueError('Legacy context ranking replay mismatch')
        kept=set(np.flatnonzero(arrays['poi']))
        for row in trace:
            added=set(witness_bundle(row['anchor'],arrays['backward'],arrays['parent'],arrays['pivot']))-kept
            if added!=set(row['new_edges']) or row['used_before']!=len(kept) or row['used_after']!=len(kept|added) or row['used_after']>x['budget']:
                raise ValueError('Legacy context bundle/budget mismatch')
            kept|=added
        if kept!=set(np.flatnonzero(selected)):raise ValueError('Legacy final result mismatch')
        for i in kept:
            owner=int(arrays['owner'][i])
            if owner<0 or not anchors[owner] or i not in witness_bundle(owner,arrays['backward'],arrays['parent'],arrays['pivot']) or not set(witness_bundle(owner,arrays['backward'],arrays['parent'],arrays['pivot']))<=kept:
                raise ValueError('Legacy owner witness mismatch')
        return dict(budget_valid=True,poi_preserved=bool(np.all(selected[arrays['poi']])),
                    complete_witnesses=True,ledger_replayed=True,greedy_ranking_replayed=True)
    audit=dict(eligible=arrays['eligible'],owner=arrays['owner'],trace=trace)
    result=audit_selection(arrays['retained'],arrays['poi'],arrays['backward'],arrays['parent'],arrays['pivot'],audit,arrays['evidence'],arrays['family'],x['budget'],x['quality'])
    if replay_ranking:
        cutoff=arrays['timestamp_ns'][np.flatnonzero(arrays['poi'])[0]]
        ties=[(abs(int(t)-int(cutoff)),int(t),id) for t,id in zip(arrays['timestamp_ns'],x['event_ids'])]
        selected,expected=select_evidence(arrays['evidence'],arrays['poi'],arrays['backward'],arrays['parent'],arrays['pivot'],arrays['family'],x['budget'],ties,x['quality'],arrays['certified'])
        if not np.array_equal(selected,arrays['retained']) or expected['trace']!=trace:
            raise ValueError('Greedy ranking replay mismatch')
        if not np.isclose(expected['objective'],cert['objective']) or not np.isclose(expected['objective_upper_bound'],cert['objective_upper_bound']):
            raise ValueError('Objective certificate mismatch')
        result['greedy_ranking_replayed']=True
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('audit',type=Path);args=p.parse_args()
    print(json.dumps(verify(json.loads(args.audit.read_text())),indent=2))

if __name__=='__main__':main()
