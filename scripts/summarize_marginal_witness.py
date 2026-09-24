"""Generate auditable tables and solver/profile summaries from frozen outputs."""
import csv,gzip,json,statistics
from collections import Counter
from pathlib import Path
from tc_pruning.sparse_edge_evaluation import sha256_file

root=Path('/root/NODOZE-pruning-release/output/tc/marginal-witness-v5-matched')
data=json.loads(Path('docs/marginal-witness-v5-results.json').read_text())
cases=data['cases'];labels=['FD1','FD3','THEIA1','THEIA3','TRACE5*']
new=lambda r:r['method'].startswith('marginal_')
rows=[r for c in cases for r in c['results']]
newrows=[r for r in rows if new(r)];ok=[r for r in newrows if r['status']=='ok']
profiles=[]
for p in sorted(root.glob('profile-*.json')):
 r=json.loads(p.read_text());r.pop('selected_ids');profiles.append(r)
if len(profiles)!=15:raise ValueError('incomplete profiles')
Path('docs/marginal-witness-v5-profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
flat=[{k:v for k,v in p.items() if k!='optimizer'} for p in profiles]
with Path('docs/marginal-witness-v5-profiles.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=list(flat[0]),lineterminator='\n');w.writeheader();w.writerows(flat)
solver=[]
for c in cases:
 for r in c['results']:
  if r['method']!='marginal_milp' or r['status']!='ok':continue
  greedy=next(x for x in c['results'] if x['method']=='marginal_linear' and all(x[k]==r[k] for k in ['scenario','track','raw_cap']))
  assert greedy['pool']==r['pool']
  g=greedy['optimizer']['objective'];upper=r['optimizer']['objective_upper_bound']
  if upper is not None and g>upper+1e-5:raise ValueError('greedy exceeds solver bound')
  solver.append(dict(case=c['name'],track=r['track'],raw_cap=r['raw_cap'],**r['optimizer'],greedy_objective=g,
                     greedy_fraction_of_upper_bound=g/upper if upper else None,greedy_proxy_tp=greedy['proxy_tp'],milp_proxy_tp=r['proxy_tp']))
allwalks=[]
for c in cases:
 for s in c['scenarios']:
  for key in ('marginal_walk_diagnostics','matched_walk_diagnostics'):
   for diag in s[key].values():allwalks.extend(w['converged'] for w in diag['walks'])
for path,h in data['source_sha256'].items():assert sha256_file(Path(path))==h
# Scope of v5: new methods only. Historical decisions remain clearly separated.
audit=dict(code_freeze='1447a39',matched_freeze='071e22a',new_decisions=len(newrows),new_status=dict(Counter(r['status'] for r in newrows)),
 cumulative_decisions=len(rows),cumulative_status=dict(Counter(r['status'] for r in rows)),new_method_count=len({r['method'] for r in newrows}),
 new_all_walks_converged=all(allwalks),walks=len(allwalks),source_hashes_match=True,
 new_poi_only_min_temporal_fork_fraction=min(r['temporal_fork_fraction'] for r in ok if r['track']=='poi_only'),
 new_profiles=len(profiles),profile_sets_matched=sum(p['selection_matches_main'] for p in profiles),solver=solver,
 limitation='closed-world partial-positive development proxy; matched score-dependent pool rule; solver bound applies only to fixed pool and linear utility')
Path('docs/marginal-witness-v5-audit.json').write_text(json.dumps(audit,indent=2)+'\n')

def row(c,m,b=1024,t='poi_only',s='all'):
 return next((r for r in c['results'] if r['method']==m and r['raw_cap']==b and r['track']==t and r['scenario']==s),None)
def tp(r):return str(r['proxy_tp']) if r and r['status']=='ok' else 'NA'
def pct(x):return f'{x*100:.2f}' if x is not None else 'NA'
def table(header,body):return '\n'.join(['| '+' | '.join(header)+' |','|'+'|'.join(['---']*len(header))+'|']+['| '+' | '.join(map(str,r))+' |' for r in body])
methods={'old_score_top':'原缓存评分 top-K','diffusion_top':'原频率扩散 top-K','witness_rerank':'v4 固定配额＋路径',
 'witness_global':'v4 全局排序＋路径','marginal_rerank':'v5 边际效用（λ=1，预定主方法）','marginal_linear':'v5 线性贪心（λ=0）',
 'marginal_diverse4':'v5 多样性敏感性（λ=4）','marginal_static':'v5 去掉时间重排','marginal_nofrequency':'v5 去掉频率统计',
 'marginal_ppr':'PPR 公式适配＋相同选择规则','marginal_heat':'热核公式适配＋相同选择规则','marginal_milp':'HiGHS 线性 MILP（相同候选池）',
 'degree_heat':'热核公式适配 top-K','pcst_native':'公开 PCST＋静态频率扩散奖赏','temporal_pcst':'公开 PCST＋时间扩散奖赏','localdegree_top':'NetworKit LocalDegree'}
lines=['# 边际收益与路径成本：第五轮优化和对照实验','',
 '## 本轮结论','',
 '保持自建的频率统计与图扩散评分引擎，完成新的路径成本选择器及同条件对照。结果支持低预算修复，但不支持把 v5 直接替换为所有预算下的默认算法，更不支持已经超过 SPARSE 或达到顶会水平的结论。','',
 '1. THEIA3@256：原扩散 top-K 为 223，v4 为 118，新主方法为 225；线性贪心为 227。v5 修复了大部分固定配额导致的损失，但相对原扩散的提升只有 2 条，不能仅与退化的 v4 比较。',
 '2. 主预算1024：v4 命中总数309，新主方法302；FD1/FD3/THEIA1/TRACE5分别21→20、14→13、16→14、29→26，THEIA3保持229。主预算回归明确存在，λ=4敏感性也不作为事后更换主方法的理由。',
 '3. 线性优化基线用于隔离优化器与评分问题。即使在相同有限池内获得接近求解器上界的分数，也不意味着攻击事件召回更高；THEIA1还有严重的候选池截断问题。',
 '4. 新主方法与同选择规则的 PPR、热核、去频率版本逐项比较如下；没有逐案例挑选赢家组成一个声称泛化的新方法。所有案例已用于开发，尚无独立测试集证据。','',
 '5. 图解释完整性没有同步改善：主预算关键组覆盖由 v4 的37/45降至30/45，阶段覆盖21/23降至16/23；256预算下也由27/45、17/23降至25/45、16/23。因此只能说密集事件召回的退化得到修复，不能说攻击链恢复全面改善。',
 '6. 去掉频率模块后，主预算宏召回66.09%略高于完整方法65.81%；256预算完整方法63.31%略高于去频率62.89%。频率模块的普遍独立收益尚未建立，不能以本轮证据作强创新主张。','',
 '## 评测范围','',
 '仅使用原来的五个开发案例。TRACE5* 是第五案例的推断映射，并非已经证实的 THEIA Case 5。POI 来自既有报告和本地定位，不依赖外接检测告警；这也不是端到端自动发现 POI 的评测。', '',
 '所有 TP/FP/FN/Precision/Recall/F1 都是冻结本地部分正例的闭世界 proxy。表中未标注的事件不一定无害；官方 SPARSE 等价指标仍为 NA。各方法先选边、保存 ID，之后评测器才读取参考标签。', '',
 '主预算保持 1024 条原始事件；256 是事先声明的低预算退化检查，64 和 4096 为完整预算曲线。共享语义上下文轨道单独列出，其先验收益不能归于新算法。', '',
 '## 实现与复现层级','',
 '保留频率统计、背景对比图扩散、时间重排。新选择器将每个候选事件及其固定时间路径视为一个集合，以新增证据收益除以新增原始事件数选择，重叠路径只计费一次。收益由线性证据和按关系类型求平方根的软多样性奖励组成，λ=1；λ=0/4 为固定对照。', '',
 '候选池由全局前 max(4096,2B) 和各类型前 ceil(max(4096,2B)/R) 的并集组成，只看分数。它限制了搜索空间，不能声称优化了整张百万事件图的全局最优解。MILP 与线性贪心共享完全相同的候选池；PPR/热核使用相同池生成规则，各自分数形成的实际池可能不同。','',
 table(['方法来源','本实验真正实现的内容'],[
 ['[预算最大覆盖，1999](https://thibaut.horel.org/submodularity/papers/khuller1999.pdf)','借鉴边际收益/成本思想；原论文是集合成本相加，本实验是原始路径事件并集成本，不移植其近似保证'],
 ['[连接最大覆盖，AAMAS 2025](https://www.ifaamas.org/Proceedings/aamas2025/pdfs/p538.pdf)','学习预算与连接约束联合建模；未实现其理论算法'],
 ['[热核社区检测，KDD 2014](https://www.cs.purdue.edu/homes/dgleich/publications/Kloster%202014%20-%20hkrelax.pdf)','自行实现全量矩阵乘法热核/PPR和度归一化；不包含作者的局部松弛或 conductance sweep'],
 ['[SciPy 1.14.1 milp](https://docs.scipy.org/doc/scipy-1.14.1/reference/generated/scipy.optimize.milp.html)','自行建立二元选锚点/原始事件模型，调用公开 HiGHS 求解器，20秒限制、1%相对gap'],
 ['[G-Retriever，NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/file/efaf1c9726648c8ba363a5c927440529-Paper-Conference.pdf)','沿用上轮 pcst_fast 公开内核及本任务适配结果，并非整个论文系统'],
 ['[图稀疏化评测，VLDB 2024](https://www.vldb.org/pvldb/vol17/p427-chen.pdf)','沿用上轮 NetworKit LocalDegree；同时报告预算与图结构指标']]),'',
 '## POI-only 主预算：命中本地正例的原始事件数','',
 '分母分别为 38、15、239、229、31。大多数预算法保留 1024 条事件；PCST 实际边数见完整 CSV，不补齐到预算。','',
 table(['方法']+labels,[[label]+[tp(row(c,m)) for c in cases] for m,label in methods.items()]),'',
 '## POI-only 低预算 256：全部关键对照','',
 table(['方法']+labels,[[label]+[tp(row(c,m,256)) for c in cases] for m,label in methods.items()]),'',
 '## 新主方法：逐案例 proxy 指标（预算 1024）','',
 table(['案例','实际 #E','TP','FP proxy','FN proxy','Precision %','Recall %','F1 %','关键组','阶段','时间路径可达 %'],[
 [labels[i],r['raw_events'],r['proxy_tp'],r['proxy_fp'],r['proxy_fn'],pct(r['proxy_precision']),pct(r['proxy_recall']),pct(r['proxy_f1']),f"{r['groups_hit']}/{r['groups_total']}",f"{r['stages_hit']}/{r['stages_total']}",pct(r['temporal_fork_fraction'])]
 for i,c in enumerate(cases) for r in [row(c,'marginal_rerank')]]),'',
 '时间路径可达率是实现约束的检查，不是攻击因果正确率。','',
 '## 宏平均与总命中（每案例等权，POI-only）','',
 table(['预算','方法','TP 总和','宏 Precision %','宏 Recall %','宏 F1 %'],[
 [b,methods[m],sum(r['proxy_tp'] for r in rs),pct(statistics.mean(r['proxy_precision'] for r in rs)),pct(statistics.mean(r['proxy_recall'] for r in rs)),pct(statistics.mean(r['proxy_f1'] for r in rs))]
 for b in [256,1024] for m in ['diffusion_top','witness_rerank','marginal_rerank','marginal_linear','marginal_nofrequency','marginal_ppr','marginal_heat','marginal_milp']
 for rs in [[row(c,m,b) for c in cases]] if all(r and r['status']=='ok' for r in rs)]),'',
 '## 原始预算曲线：64 / 256 / 1024 / 4096 的 TP','',
 table(['方法']+labels,[[methods[m]]+[' / '.join(tp(row(c,m,b)) for b in [64,256,1024,4096]) for c in cases] for m in ['diffusion_top','witness_rerank','marginal_rerank','marginal_linear','marginal_diverse4','marginal_static','marginal_nofrequency','marginal_ppr','marginal_heat']]),'',
 '## 共享语义上下文轨道（预算 1024）','',
 table(['方法']+labels,[[methods[m]]+[tp(row(c,m,t='shared_context')) for c in cases] for m in ['diffusion_top','witness_rerank','marginal_rerank','marginal_linear','marginal_nofrequency','marginal_ppr','marginal_heat','marginal_milp']]),'',
 '## POI 删除敏感性（POI-only，预算 1024）','',
 table(['案例','删除场景','原扩散','v4','v5 主方法','线性贪心','去频率','PPR','热核'],[
 [labels[i],s['scenario']]+[tp(row(c,m,s=s['scenario'])) for m in ['diffusion_top','witness_rerank','marginal_rerank','marginal_linear','marginal_nofrequency','marginal_ppr','marginal_heat']]
 for i,c in enumerate(cases) for s in c['scenarios'] if s['scenario']!='all']),'',
 '## 候选池诊断（主预算，选边结束后审计）','',
 table(['案例','本地正例总数','可达且正分','池内正例（含路径）','最终命中'],[[labels[r['case']],r['positive_events'],r['eligible_positive_events'],r['pool_union_positive_events'],r['selected_positive_events']] for r in json.loads(Path('docs/marginal-witness-v5-pool-audit.json').read_text())]),'',
 'THEIA1 的全部 239 条本地正例均可达且有正分，但池内仅有 17 条，最终命中 14 条。有限池是实质限制：线性 MILP 优化充分也不能证明整图排序正确。FD1 池内有 34 条但只命中 20 条，反映还有预算/评分目标层面的损失。该诊断未参与选边或调参。','',
 '## MILP 验证：分数目标是否被充分优化','',
 '求解器上界仅约束同一有限候选池的线性分数目标；与正例召回最优无关。以下包含两个预算和两个轨道。相对 gap 来自 HiGHS；status=0 也可能在 1% 容差下停止。','',
 table(['案例','轨道','预算','求解状态','gap %','贪心/上界 %','贪心 TP','MILP TP'],[
 [s['case'],s['track'],s['raw_cap'],s['solver_status'],pct(s['mip_gap']),pct(s['greedy_fraction_of_upper_bound']),s['greedy_proxy_tp'],s['milp_proxy_tp']] for s in solver]),'',
 '## 新进程开销（预算 1024，POI-only）','',
 '每方法/案例一个独立进程样本，案例并行；BLAS/OMP 环境设为 1，HiGHS 内部线程使用默认值。时间包括已构建候选账本的加载、评分、路径、候选池和选择，排除原始 CDM 导入、历史频率模型构建、评测、导出。不能据此声称严格的单线程加速比。','',
 table(['方法','案例','加载后评分 s','路径 s','候选池 s','优化 s','完整候选流程 s','峰值 RSS MiB','选择集合复现'],[
 [p['method'],labels[p['case']],f"{p['scoring_seconds']:.2f}",f"{p['route_seconds']:.2f}",f"{p['pool_seconds']:.2f}",f"{p['optimization_seconds']:.2f}",f"{p['frozen_candidate_pipeline_seconds']:.2f}",f"{p['peak_rss_mib']:.1f}",p['selection_matches_main']] for p in profiles]),'',
 '窄口径字段 kernel_plus_selection_seconds 不包含 route_seconds 和 pool_seconds；跨方法成本比较应使用上表的完整候选流程。旧 baseline 计时见 temporal-diffusion-study.md，属于此前测量，不能当作本轮同时重新计时。','',
 '## 审计与复现','',
 f"本轮新增 {len(newrows)} 项决策，状态 {audit['new_status']}；含 {audit['new_method_count']} 个新方法/变体。累计 {len(rows)} 项，旧轮次决策和时间按源码/输入哈希验证后复用，并非本轮重新运行。配置组合不是独立攻击样本。",'',
 '实现验证：完整测试套件656项通过；独立代码审查另核对60个随机小图MILP穷举结果和180组greedy/慢速选择一致性。最终审查核对105行报告表及2484行CSV/JSON，未发现Critical或Important问题。MILP表保留参考文件中的历史案例名 Theia Case 5，含义仍是本文披露的 TRACE5* 推断映射。','',
 f"新方法全部 {len(allwalks)} 个扩散诊断收敛；POI-only 时间路径可达率最低 {pct(audit['new_poi_only_min_temporal_fork_fraction'])}%；15 次新进程 profile 中 {audit['profile_sets_matched']} 次选择集合一致。预算、POI、ID、账本和源码哈希检查通过。",'',
 '```bash\n# 工作目录：本研究 worktree；使用 .venv-cross-domain 的 Python\nexport PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1\n# 每个 CASE 取 0..4；输出不允许覆盖\npython scripts/run_marginal_comparison.py --case "$CASE" --output "$V5/case$CASE.json.gz"\npython scripts/run_matched_kernel_comparison.py --case "$CASE" --output "$MATCHED/case$CASE.json.gz"\npython scripts/evaluate_marginal_witness.py --input "$MATCHED" --output docs/marginal-witness-v5-results.json\npython scripts/profile_marginal_witness.py --case "$CASE" --method marginal_rerank --output "$PROFILE"\npython scripts/summarize_marginal_witness.py\npython scripts/plot_marginal_witness.py --results docs/marginal-witness-v5-results.json --output-dir docs/figures\n```','',
 '执行中一次 matched 子进程在父 gzip 尚未写完时读入，产生 EOFError，未输出决策。等待父进程成功完成后，用原封不动的冻结代码重跑该子任务，并在写完后原子重命名；失败日志保留。此后账本、源码和最终报告哈希全部核验。','',
 'runner 的父轮次输入路径固定在 /root/NODOZE-pruning-release/output/tc；迁移机器须同步冻结账本和父报告，并调整路径。汇总脚本要求 15 个 profile 文件；方法依次为 marginal_rerank/marginal_linear/marginal_milp。', '',
 '后续优先级：先用独立历史背景窗口做关系类型内的分数校准，并扩大/分层检索入口事件候选；再固定参数做未参与开发的攻击测试。不能继续仅靠增加多样性权重解决 THEIA1，也不能把本地部分正例扩展当作 SPARSE 完整真值。以上为下一阶段设计判断，本轮没有声称完成这些验证。','',
 '完整数据：[结果 CSV](marginal-witness-v5-results.csv)、[结果 JSON](marginal-witness-v5-results.json)、[审计 JSON](marginal-witness-v5-audit.json)、[性能 JSON](marginal-witness-v5-profiles.json)。', '',
 '![POI-only 预算曲线](figures/marginal-witness-v5-poi_only.png)','',
 '![共享上下文预算曲线](figures/marginal-witness-v5-shared_context.png)','']
Path('docs/marginal-witness-study.md').write_text('\n'.join(lines))
print(json.dumps({k:v for k,v in audit.items() if k!='solver'},indent=2))
