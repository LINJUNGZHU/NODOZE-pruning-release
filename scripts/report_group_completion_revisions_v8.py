"""Compare complete frozen development revisions, retaining all negative results."""
import argparse,csv,json,statistics
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--original',type=Path,required=True);p.add_argument('--rrf',type=Path,required=True);p.add_argument('--expansion',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    reports=[json.loads(x.read_text()) for x in (a.original,a.rrf,a.expansion)];r=dict(reports[0]);r['rows']=sum((x['rows'] for x in reports),[]);r['summary']=sum((x['summary'] for x in reports),[]);r['profiles_by_revision']={x['protocol']:x['profiles'] for x in reports};r['profiles']=[];r['scope']='three development revisions, same fixed partial-positive reference; report all attempted variants, no per-cell picking'
    a.output.mkdir(parents=True,exist_ok=True);(a.output/'comparison.json').write_text(json.dumps(r,indent=2)+'\n')
    with (a.output/'comparison.csv').open('w') as f:
        fields=[k for k in r['rows'][0] if k!='official_equivalent'];extra=['non_synthetic_selected','official_fp','official_fn','official_precision','official_recall','official_f1'];writer=csv.DictWriter(f,fieldnames=fields+extra);writer.writeheader();writer.writerows(dict({k:x[k] for k in fields},non_synthetic_selected=x['selected_events']-x['lineage_selected'],**{k:'NA' for k in extra[1:]}) for x in r['rows'])
    methods=['history_portfolio','v7_group_edge','v8_group_edge','v8_group_concave','v8_representative_concave','v8_no_frequency_concave','v8_rrf_group_edge','v8_rrf_group_concave','v8_expansion_edge','v8_expansion_concave'];budgets=[64,256,1024,4096]
    def s(m,b):return next(x for x in r['summary'] if x['method']==m and x['budget']==b)
    def row(i,m,b=1024):return next(x for x in r['rows'] if x['method']==m and x['case_index']==i and x['budget']==b)
    lines=['# 三轮开发实验：节点调查算法的修订、对比与论文边界','','## 已实际执行','',
        'r3（aabf675）：六方法、120 项质量决策；r4（4e6c1a3）：RRF 换序、40 项；r5（2455f00）：展开准入修正、40 项。每轮五案和四预算，另各做 25 个新进程资源重复，共 **200 项质量决策、75 次资源重复**。',
        '所有质量输出通过独立时间见证、真实事件并集、预算和新选择器逐步收益回放。选边不读标签；r4/r5 是看过开发结果后修订，不能当作未见测试或预注册实验。',
        '保留自有频率统计与图扩散。本轮没有训练 GNN，没有作者版 SPARSE 等价复现；新版本的名字不等于质量更好。','','## 已知正例宏覆盖率','',
        '| 方法 | B=64 | B=256 | B=1024 | B=4096 |','|---|---:|---:|---:|---:|']
    for m in methods:lines.append('| '+m+' | '+' | '.join(f"{100*s(m,b)['macro_recall_known']:.2f}%" for b in budgets)+' |')
    lines+=['','## 主预算逐案与物化损失','', '| 案例 | 正例总数 | 原强基线命中 | V7 命中 | r3 组目标命中 | r5 单边目标命中 | r5 组目标命中 | r5 候选池正例 |','|---|---:|---:|---:|---:|---:|---:|---:|']
    for i in range(5):
        x=row(i,'v8_expansion_edge');name=x['name'] if i!=4 else 'Case 5（TRACE 推断映射）'
        lines.append(f"| {name} | {x['positive_events']} | {row(i,'history_portfolio')['tp_known']} | {row(i,'v7_group_edge')['tp_known']} | {row(i,'v8_group_concave')['tp_known']} | {x['tp_known']} | {row(i,'v8_expansion_concave')['tp_known']} | {round(x['pool_positive_recall']*x['positive_events'])} |")
    lines+=['','## 实验回答了什么','']
    delta=100*(s('v8_expansion_edge',1024)['macro_recall_known']-s('v8_group_edge',1024)['macro_recall_known']);gap=100*(s('v8_expansion_edge',1024)['macro_recall_known']-s('history_portfolio',1024)['macro_recall_known'])
    lines +=[f'- **H1／检索与准入：** r5 单边目标相对 r3 单边目标在 B=1024 提高 {delta:.2f} 个百分点；相对原强基线差 {gap:+.2f} 个百分点。变化来自候选准入流程，不能归功于图学习或频率模型的新能力。',
        '- **H2／目标价值：** 在 r5 同一候选池中，凹组目标比线性事件目标退化；它倾向跨组分散预算，未证明更完整地保存参考事件细节。目标值变大不保证关键事件覆盖变大。没有新备选路径实验，仍 k=1。',
        '- **H3／频率和传播：** 原六方法中的去频率为整流程消融，候选也变化；不能据此称固定池频率模块有独立收益。三轮没有重新设计传播内核。',
        '- **H4／泛化：** 没有冻结后的未见攻击。五次进程重复只测资源与确定性，不增加独立攻击数。',
        '- r4 单独换成三视图 RRF 未解决主要物化损失。r5 将剩余容量用于已探索组的继续展开，改善了部分案例；其他案例仍明显不足。所有预算和失败保留，不按格子挑版本。',
        '- 产品默认继续使用已验收的节点频率/扩散与路径约束；本轮研究版没有全面超过原强基线，因此不作为更准的默认算法发布。',
        '- 完整账本 history_portfolio 与 32768 事件容量的研究池资源不同。V7、r3、r5 的差异包含检索/表示/准入，不能写成严格单组件消融；每轮 edge/concave 才共享同池。',
        '','## 排除输入 POI 的覆盖率','', '| 方法 | B=64 | B=256 | B=1024 | B=4096 |','|---|---:|---:|---:|---:|']
    for m in methods:lines.append('| '+m+' | '+' | '.join(f"{100*s(m,b)['macro_recall_incremental']:.2f}%" for b in budgets)+' |')
    lines+=['','## 资源：各自工作量下的中位数','', '| 轮次 | 案例 | 五次整轮用时中位数 (s) | 五次整轮峰值 RSS 中位数 (MiB) | 主方法 B=1024 选择中位数 (s) |','|---|---:|---:|---:|---:|']
    for label,report,main_method in [('r3',reports[0],'v8_group_concave'),('r4',reports[1],'v8_rrf_group_concave'),('r5',reports[2],'v8_expansion_edge')]:
        for x in report['profiles']:
            t=next(y['median_seconds'] for y in x['selection'] if y['method']==main_method and y['budget']==1024)
            lines.append(f"| {label} | {x['case_index']} | {x['whole_matrix_elapsed_median']:.2f} | {x['whole_matrix_peak_rss_median']:.1f} | {t:.3f} |")
    lines+=['','r3 六方法、r4/r5 两方法，整轮工作量不同，不能直接宣称速度或内存提升倍数。选择与证书构建分开；每轮最多五个案例进程并发，且独立评测也可能并发，不是独占机器 SLA。r4/r5 JSON 提供样本和四分位数。',
        '','## 完整性与投稿仍缺什么','',
        '- 参考只有部分正例；官方等价 FP/FN/Precision/Recall/F1 全为 **NA**。未知事件不计为误报。报告派生 POI 是 oracle 起点，不是自动检测成果。',
        '- 事件数使用账本 ID；LINEAGE 合成边统一计费，CSV 分别记录合成事件和总事件。时间合法性是实现合同，不是真实因果证明。',
        '- 最后一案实际上是 TRACE Case 5 的推断映射，尚未证实等价于论文 THEIA Case 5；不能伪装同数据集系统胜负。',
        '- 历史不保证良性，元数据发生时可知性仍未验证；不宣称严格在线无未来信息影响。',
        '- 投稿确认需新的主机/时间/攻击、独立关键边和完整证据标注、作者系统或透明组件适配的公平比较、分析员任务正确率/用时。现有五案只能支持开发发现。',
        '','## 交付与复现','',
        '[全部 200 项 CSV](comparison.csv) · [JSON](comparison.json) · [预算曲线 PDF](comparison-figures/budget-curves.pdf) · [物化与选择损失 PDF](comparison-figures/candidate-losses.pdf) · [原轮报告](report.md) · [RRF 修订](rrf-revision.md) · [展开修正](expansion-fix.md) · [方法与借鉴协议](paper-protocol.md)。',
        '原始决策证书与 manifest 在 artifacts、rrf-artifacts、expansion-artifacts，较大的候选证书池留本机，路径及哈希在各 audit.json。仓库不包含大型原始日志；跨机器完整回放需恢复数据或按脚本重新生成。',
        '[产品 HTML 和节点调查交付评审](../product/README.md) 与离线研究分开。跨领域 PCST/LocalDegree 等实际内核实验见[既有报告](../cross-domain-study.md)，本轮不把不同评分/候选的历史数字拼成同池胜负。','']
    (a.output/'comparison.md').write_text('\n'.join(lines))

if __name__=='__main__':main()
