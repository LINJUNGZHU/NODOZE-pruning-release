import pytest
from tc_pruning.history_archive import HistoryArchive


def row(i, a, b, t):
    return dict(event_id=str(i),src=a,dst=b,relation='R',timestamp_ns=t,rarity=.5,attack=True)


def test_reopen_hops_and_no_future(tmp_path):
    a = HistoryArchive(tmp_path, 2)
    for r in [row(0,'a','b',1),row(1,'b','c',2),row(2,'c','d',3),row(3,'a','z',99)]: a.append(r)
    a.flush(); a = HistoryArchive(tmp_path)
    one, _ = a.retrieve(['a'], 3, 1)
    two, _ = a.retrieve(['a'], 3, 2)
    assert {r['event_id'] for r in one} == {'0'}
    assert {r['event_id'] for r in two} == {'0','1'}
    assert all('attack' not in r for r in two)


def test_checksum_and_unflushed(tmp_path):
    a=HistoryArchive(tmp_path); a.append(row(0,'a','b',1))
    with pytest.raises(ValueError): a.retrieve(['a'], 2)
    a.flush()
    (tmp_path/a.shards[0]['file']).write_bytes(b'bad')
    with pytest.raises(ValueError): a.retrieve(['a'],2)
