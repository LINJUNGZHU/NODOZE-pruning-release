"""Render actual V8 development results without hand-entering metric cells."""
import argparse,json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--results',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=json.loads(a.results.read_text());methods=sorted({x['method'] for x in r['summary']});budgets=sorted({x['budget'] for x in r['summary']})
    def s(method,budget):return next(x for x in r['summary'] if x['method']==method and x['budget']==budget)
    lines=['# V8：完整事件组与精确路径成本的实际实验结果','','## 执行与口径','',
        '冻结选择源码：`aabf675`。五案 × 六方法 × 四预算 = 120 组质量决策；另有 25 个新进程完成五次整轮资源重复。每进程线程设置为 1，最多五个案例进程并发。',
        '全部质量输出经独立时间见证、事件并集、预算及 V8 逐步边际收益回放。质量标签由独立评测者读取，选择器不读取标签。',
        '五案为反复使用过的开发案例；最后一案使用未证实等价于 THEIA Case 5 的 TRACE 工件映射。known-positive recall 仅针对本地部分正例，官方等价 FP/FN/Precision/Recall/F1 均为 NA。','','## 宏平均已知正例覆盖率','',
        '| 方法 | '+' | '.join(f'B={b}' for b in budgets)+' |','|---|'+'---:|'*len(budgets)]
    for method in methods:lines.append('| '+method+' | '+' | '.join(f"{100*s(method,b)['macro_recall_known']:.2f}%" for b in budgets)+' |')
    lines+=['','## 主预算 B=1024：逐案例','', '| 案例 | 已知正例 | 原强基线命中 | V7 命中 | V8 单边目标命中 | V8 组目标命中 | V8 候选正例进入率 |','|---|---:|---:|---:|---:|---:|---:|']
    def row(i,m):return next(x for x in r['rows'] if x['case_index']==i and x['method']==m and x['budget']==1024)
    for i in range(5):
        x=row(i,'v8_group_concave');name=x['name'] if i!=4 else 'Case 5（TRACE 推断映射）'
        lines.append(f"| {name} | {x['positive_events']} | {row(i,'history_portfolio')['tp_known']} | {row(i,'v7_group_edge')['tp_known']} | {row(i,'v8_group_edge')['tp_known']} | {x['tp_known']} | {100*x['pool_positive_recall']:.2f}% |")
    lines+=['','## 结论与失败记录','']
    for baseline in ('v7_group_edge','v8_group_edge','history_portfolio'):
        delta=100*(s('v8_group_concave',1024)['macro_recall_known']-s(baseline,1024)['macro_recall_known'])
        lines.append(f'- B=1024，相比 `{baseline}` 的宏平均已知正例覆盖率差为 **{delta:+.2f} 个百分点**。')
    regressions=[f"{x['name']} / B={x['budget']}" for x in r['rows'] if x['method']=='v8_group_concave' and x['recall_known']<next(y['recall_known'] for y in r['rows'] if y['method']=='history_portfolio' and y['case_index']==x['case_index'] and y['budget']==x['budget'])]
    lines.append('- 相对完整账本强基线退化条件：'+('；'.join(regressions) if regressions else '本轮所测条件未发生；不能据此推断未见数据。'))
    lines+=['- V8 单边目标与组目标共享同一冻结候选池，可以隔离目标函数；代表/去频率消融的候选身份不同，是流程消融。',
        '- history_portfolio 使用完整账本，V7/V8 的真实候选容量为 32768；它们的比较不能声称候选资源相同。V7 与 V8 还同时改变检索顺序和动作结构。',
        '- 本轮没有重跑作者版 SPARSE，也没有新的作者 PCST 系统复现。不把既有跨领域实验的数字拼成同池胜负。原开源内核实验保留在[跨领域报告](../cross-domain-study.md)。',
        '- V8 保持研究版本；产品继续使用已经验收的节点频率/传播与路径合同，不能仅因目标值更大而切换默认。','','## 排除输入 POI 的覆盖率','',
        '| 方法 | '+' | '.join(f'B={b}' for b in budgets)+' |','|---|'+'---:|'*len(budgets)]
    for method in methods:lines.append('| '+method+' | '+' | '.join(f"{100*s(method,b)['macro_recall_incremental']:.2f}%" for b in budgets)+' |')
    lines+=['','## 资源重复','', '| 案例 | 重复次数 | 整轮用时中位数 (s) | 整轮累计峰值 RSS 中位数 (MiB) | V8 B=1024 选择中位数 (s) |','|---|---:|---:|---:|---:|']
    for x in r['profiles']:
        t=next(y['median_seconds'] for y in x['selection'] if y['method']=='v8_group_concave' and y['budget']==1024)
        lines.append(f"| {x['case_index']} | {x['repeats']} | {x['whole_matrix_elapsed_median']:.2f} | {x['whole_matrix_peak_rss_median']:.1f} | {t:.3f} |")
    lines+=['','选择时间和证书构建分开；RSS 属于整轮矩阵，不能写成单方法内存。并发、缓存及系统负载影响计时；这些记录不是独占机器 SLA。五次重复不是五个新攻击，也不支持泛化显著性宣称。',
        '','## 文件与下一步','', '[完整 JSON](results.json) · [120 行 CSV](results.csv) · [预算曲线 PDF](figures/budget-curves.pdf) · [实验协议与投稿补齐项](paper-protocol.md) · [执行审计](artifacts/audit.json)。',
        '发布的 artifacts 包含原始决策证书和 30 份执行 manifest；较大的候选证书池保留本机，路径及哈希在审计中。manifest 使用原执行路径；跨机器复放需恢复输入及目录或按脚本重新生成。',
        '','下一轮确认实验需要新的主机/时间段、独立关键事件标注、与图检索/稀疏化基线的同池同证据预算适配，以及分析员任务用时。详细方法和借鉴来源已写入协议；未执行项目不列为已有成果。','']
    a.output.write_text('\n'.join(lines))

if __name__=='__main__':main()
