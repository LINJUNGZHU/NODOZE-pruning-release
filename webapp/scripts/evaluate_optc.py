"""Report every declared POI at the same budget; never select a winner by truth."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tc_pruning.optc_investigation import rescore


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,default=ROOT/'webapp/runtime/optc-demo.json')
    parser.add_argument('--output',type=Path,default=ROOT/'docs/optc-poi-evaluation.json')
    args=parser.parse_args()
    data=json.loads(args.cache.read_text())
    results=[]
    for p in data['poi_presets']:
        run=rescore(copy.deepcopy(data),p['event_id'])
        result=dict(poi=run['poi'],history=run['history'],metrics=run['metrics'],truth=run['truth'],
                    display_retained=sum(e['retained'] for e in run['edges'] if e['id'] in run['display_event_ids']))
        results.append(result)
        print(p['label'],run['metrics']['history_edges'],run['truth']['retained_events'],flush=True)
    report=dict(dataset=dict(id=data['dataset']['id'],sources=[Path(p).name for p in data['dataset']['sources']],window=data['dataset']['description']),
                algorithm=data['algorithm'],results=results,
                limitations=['单主机十分钟调查窗口，非完整 OPTC 泛化评估',
                             'PDF 指标匹配包含相关正常读写，不是逐边恶意真值；未匹配不能视为正常',
                             'POI 是已知真值支持的人工调查起点，非独立检测评估',
                             '历史覆盖仅限提供的两个分片；按事件时间统计，不保证涵盖所有原始数据',
                             '固定候选窗口包含 POI 之后事件；其频率不使用 POI 之后日志'],
                implementation_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                    [ROOT/'tc_pruning/optc.py',ROOT/'tc_pruning/optc_investigation.py',ROOT/'tc_pruning/rasp.py',ROOT/'tc_pruning/rasp_diverse.py']})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,allow_nan=False)+'\n')

if __name__=='__main__':main()
