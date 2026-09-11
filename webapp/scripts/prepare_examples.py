"""Prepare four real full-size windows; never duplicate edges for visual effect."""
import copy
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tc_pruning.optc import parse_event,timestamp_ns
from tc_pruning.optc_investigation import rescore
from webapp.scripts.prepare_attack_reference import build as build_labels,ids_hash

EXAMPLES=[
    ('optc-0201','入侵起点','11:20','11:30','10 分钟 · 下载与代理上线'),
    ('optc-0201-30m','扩大调查','11:20','11:50','30 分钟 · 观察后续活动'),
    ('optc-0201-60m','大图对照','11:20','12:20','60 分钟 · 完整上下文'),
    ('optc-0201-background','背景对照','10:50','11:10','20 分钟 · 攻击前的保留时段'),
]


def main():
    root=ROOT/'webapp/runtime';corpus=json.loads((root/'optc-corpus.json').read_text())
    base=json.loads((root/'optc-demo.json').read_text());folder=root/'examples';folder.mkdir(exist_ok=True)
    label_folder=ROOT/'poi/example-labels';label_folder.mkdir(exist_ok=True)
    entries=[]
    for id,name,start,end,description in EXAMPLES:
        start='2019-09-23T'+start+':00-04:00';end='2019-09-23T'+end+':00-04:00'
        edges=[]
        with sqlite3.connect(corpus['path']) as c:
            for raw,file,line in c.execute('SELECT payload,source_file,source_line FROM records JOIN events USING(event_id) WHERE timestamp_ns>=? AND timestamp_ns<? ORDER BY timestamp_ns,event_id',(timestamp_ns(start),timestamp_ns(end))):
                e=parse_event(json.loads(raw));e.update(source_file=file,source_line=line);edges.append(e)
        ids={e['id'] for e in edges};presets=[p for p in base['poi_presets'] if p['event_id'] in ids]
        if not presets:
            presets=[dict(event_id=edges[0]['id'],label='背景调查起点',timestamp=edges[0]['timestamp'],groundtruth_backed=False,
                          evidence='明确选择的背景事件，不是 Ground Truth 攻击种子')]
        data=dict(schema_version=2,dataset=dict(id=id,name=name,description=description,source=base['dataset']['source'],
                    sources=base['dataset']['sources'],window_start=start,window_end=end,host=corpus['host']),
                  edges=edges,history_index=dict(path=corpus['path'],id=corpus['id']),poi_presets=presets,
                  truth=dict(source=base['truth']['source']),algorithm=copy.deepcopy(base['algorithm']))
        data['algorithm']['selection_mode']='context'
        labels=build_labels(data,root/'research/optc-labels')
        if id!='optc-0201':(label_folder/f'{ids_hash(ids)}.json').write_text(json.dumps(labels,ensure_ascii=False,indent=2)+'\n')
        poi=next((p['event_id'] for p in presets if p['event_id']=='a6da9327-470e-4bd0-b390-470ae80d8189'),presets[0]['event_id'])
        print('Preparing',id,len(edges),'events',flush=True)
        rescore(data,poi,.2,'context',.9,detector='rules')
        target=root/'optc-demo.json' if id=='optc-0201' else folder/f'{id}.json'
        tmp=target.with_suffix('.tmp');tmp.write_text(json.dumps(data,ensure_ascii=False,allow_nan=False));tmp.replace(target)
        entries.append(dict(id=id,name=name,description=description,metrics=data['metrics'],cache_path=str(target),
                            window_start=start,window_end=end,background=id.endswith('background')))
        (folder/'catalog.json').write_text(json.dumps(entries,ensure_ascii=False,indent=2)+'\n')
        print('Ready',id,data['metrics'],flush=True)
    (ROOT/'docs/example-catalog.json').write_text(json.dumps([{k:v for k,v in e.items() if k!='cache_path'} for e in entries],ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
