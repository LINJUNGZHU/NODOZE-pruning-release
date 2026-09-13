"""Evidence-bound summaries inspired by staged investigation, with no LLM call."""
from collections import defaultdict


KINDS = {
    'PROCESS': ('process_execution', '进程启动与访问', '观察到候选进程相关的创建、访问或终止记录；不单凭创建关系证明提权。'),
    'FILE': ('file_activity', '文件活动', '观察到候选进程访问文件；读写记录不能单独证明载荷内容、持久化或数据窃取。'),
    'FLOW': ('network_activity', '网络通信', '观察到候选进程相关的网络流；连接本身不能证明命令控制或数据外传。'),
}


def build_story(report, edges):
    activity = set(report.get('activity_event_ids', []))
    selected = [e for e in edges if e['id'] in activity]
    if {e['id'] for e in selected} != activity:
        raise ValueError('story activity evidence missing')
    grouped = defaultdict(list)
    for edge in sorted(selected, key=lambda e: (e['timestamp_ns'], e['id'])):
        grouped[edge['raw']['object']].append(edge)
    stages = []
    for obj, events in grouped.items():
        kind, title, limitation = KINDS.get(obj, ('other_activity', '其他活动', '仅确认日志记录，不推断未观测的攻击阶段。'))
        stages.append(dict(kind=kind, title=title, start=events[0]['timestamp'], end=events[-1]['timestamp'],
            event_count=len(events), event_ids=[e['id'] for e in events],
            actor_node_ids=sorted({e['raw']['actorID'] for e in events}),
            relations=sorted({e['relation'] for e in events}),
            evidence_status='observed', maliciousness_proven=False, limitation=limitation))
    return dict(generator='deterministic_evidence_summary', stages=stages,
                observed_event_count=len(selected),
                contract='按观察到的活动类型汇总，时间段可以重叠；不是完整 APT 阶段归因或单条攻击链。每项事实可回查原始事件。',
                unsupported_claims=['初始入侵方式', '提权是否成功', '持久化是否建立', '是否完成数据外传'])


def verify_story(report, edges):
    if report.get('story') != build_story(report, edges):
        raise ValueError('story facts or evidence do not match raw events')
    return True
