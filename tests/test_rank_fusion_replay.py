import gzip
import json
from scripts.run_rank_fusion import run


def test_truth_and_old_decisions_do_not_change_ranking(tmp_path):
    outputs=[]
    for revision in (0,1):
        ledger=tmp_path/f'ledger-{revision}.gz'
        with gzip.open(ledger,'wt') as stream:
            for i in range(40):
                stream.write(json.dumps(dict(event_id=str(i),src=str(i),dst=str(i+1),
                    src_type='process',dst_type='process',relation='EVENT_WRITE',timestamp_ns=i,
                    components={'rarity':.2},is_declared_poi=i==20,score=i if revision else 40-i,
                    decisions=[{'budget_key':'0.2','kept':bool(revision)}]))+'\n')
        truth=tmp_path/f'truth-{revision}.json'
        truth.write_text(json.dumps({'attack_event_ids':[str(revision)],'attack_paths':[[str(revision)]]}))
        output=tmp_path/f'output-{revision}';run(ledger,truth,output)
        with gzip.open(output/'edge-ranks.jsonl.gz','rt') as stream:outputs.append(list(map(json.loads,stream)))
    assert outputs[0]==outputs[1]
