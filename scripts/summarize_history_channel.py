"""Produce v6 comparison tables and audit from frozen post-selection evaluation."""
import csv,gzip,json,statistics
from collections import Counter
from pathlib import Path
from tc_pruning.sparse_edge_evaluation import sha256_file
root=Path('/root/NODOZE-pruning-release/output/tc/history-channel-v6')
data=json.loads(Path('docs/history-channel-v6-results.json').read_text());cases=data['cases'];labels=['FD1','FD3','THEIA1','THEIA3','TRACE5*']
methods={'entry_pool':'仅扩展通道候选池','history_only':'仅历史条件频率校准','channel_only':'通道共享＋扩展（无新校准）',
 'history_channel':'v6 校准＋通道共享＋扩展（主方法）','history_channel_linear':'v6 同池线性贪心','history_channel_milp':'v6 同池线性 MILP',
 'history_channel_portfolio':'v6 分数＋v4 全候选选择器','channel_nofrequency':'通道流程＋去频率','channel_ppr':'通道流程＋PPR适配','channel_heat':'通道流程＋热核适配'}
baselines={'diffusion_top':'原频率扩散 top-K','witness_rerank':'v4 固定配额＋路径','marginal_rerank':'v5 边际效用','temporal_pcst':'公开 PCST＋时间扩散奖赏','localdegree_top':'NetworKit LocalDegree'}
allmethods=baselines|methods
rows=[r for c in cases for r in c['results']];new=[r for r in rows if r['method'] in methods];ok=[r for r in new if r['status']=='ok']
profiles=[json.loads(p.read_text()) for p in sorted(root.glob('profile-*.json'))]
pools=[json.loads((root/f'pool-{i}.json').read_text()) for i in range(5)]
if len(profiles)!=15:raise ValueError('incomplete profile set')
history=[];cold_checks=[]
for i,c in enumerate(cases):
 with gzip.open(root/f'case{i}.json.gz','rt') as f:raw=json.load(f)
 history.append(raw['history_preparation'])
 if history[-1]['supported_events']==0:
  for r in raw['results']:
   if r['method']!='history_channel' or r['status']!='ok':continue
   other=next(x for x in raw['results'] if x['method']=='channel_only' and all(x[k]==r[k] for k in ['scenario','track','raw_cap']))
   assert set(r['selected_ids'])==set(other['selected_ids'])
   cold_checks.append(dict(case=i,scenario=r['scenario'],track=r['track'],budget=r['raw_cap'],identical=True))
for path,h in data['source_sha256'].items():assert sha256_file(Path(path))==h
walks=[w['converged'] for c in cases for s in c['scenarios'] for d in s['history_channel_walk_diagnostics'].values() for w in d['walks']]
solver=[]
for c in cases:
 for r in c['results']:
  if r['method']!='history_channel_milp':continue
  record=dict(case=c['name'],track=r['track'],raw_cap=r['raw_cap'],**r['optimizer'])
  if r['status']=='ok':
   g=next(x for x in c['results'] if x['method']=='history_channel_linear' and all(x[k]==r[k] for k in ['scenario','track','raw_cap']))
   assert g['pool']==r['pool'];upper=r['optimizer']['objective_upper_bound'];value=g['optimizer']['objective']
   if upper is not None:assert value<=upper+1e-5
   record.update(greedy_objective=value,greedy_fraction_of_upper_bound=value/upper if upper else None,greedy_tp=g['proxy_tp'],milp_tp=r['proxy_tp'])
  solver.append(record)
audit=dict(frequency_freeze='4dabc14',runner_freeze='1fb9e98',new_decisions=len(new),new_status=dict(Counter(r['status'] for r in new)),
 cumulative_decisions=len(rows),cumulative_status=dict(Counter(r['status'] for r in rows)),new_methods=len(methods),source_hashes_match=True,
 new_walks=len(walks),all_new_walks_converged=all(walks),poi_only_min_temporal_fork_fraction=min(r['temporal_fork_fraction'] for r in ok if r['track']=='poi_only'),
 profiles=len(profiles),profile_sets_match=sum(p['selection_matches_main'] for p in profiles),cold_start_equal_selection_checks=cold_checks,solver=solver)
for name,content in [('profiles',profiles),('pool-audit',pools),('history',history),('audit',audit)]:Path(f'docs/history-channel-v6-{name}.json').write_text(json.dumps(content,indent=2)+'\n')
flat=[{k:v for k,v in p.items() if k!='pool'} for p in profiles]
with Path('docs/history-channel-v6-profiles.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=list(flat[0]),lineterminator='\n');w.writeheader();w.writerows(flat)
def row(c,m,b=1024,t='poi_only',s='all'):
 return next((r for r in c['results'] if r['method']==m and r['raw_cap']==b and r['track']==t and r['scenario']==s),None)
def tp(r):return str(r['proxy_tp']) if r and r['status']=='ok' else 'NA'
def pct(v):return f'{v*100:.2f}' if v is not None else 'NA'
def table(h,rows):return '\n'.join(['| '+' | '.join(h)+' |','|'+'|'.join(['---']*len(h))+'|']+['| '+' | '.join(map(str,r))+' |' for r in rows])
def macro(m,b):
 rs=[row(c,m,b) for c in cases]
 if not all(r and r['status']=='ok' for r in rs):return [m,b,'NA','NA','NA','NA','NA','NA']
 return [allmethods[m],b,sum(r['proxy_tp'] for r in rs),pct(statistics.mean(r['proxy_precision'] for r in rs)),pct(statistics.mean(r['proxy_recall'] for r in rs)),pct(statistics.mean(r['proxy_f1'] for r in rs)),f"{sum(r['groups_hit'] for r in rs)}/45",f"{sum(r['stages_hit'] for r in rs)}/23"]
oldpools=json.loads(Path('docs/marginal-witness-v5-pool-audit.json').read_text())
lines=['# 历史条件频率与通道检索：第六轮实现和实验','',
 '## 本轮结果判断','',
 '代码已经实现并完成五案例对照，但预先指定的v6主方案没有达到全面替换目标。主预算TP为301、宏F1为9.97%、关键组30/45；v4对应309、10.25%、37/45，主方案的负结果保留。','',
 '有收益的是预先列入对照的“新分数＋v4全候选选择器”：1024预算总TP从309增至321，宏Recall从69.77%增至76.96%，宏F1从10.25%增至10.71%，关键组37/45增至38/45，阶段仍为21/23。逐案例为35/14/16/227/29；其中FD1为21→35，THEIA3为229→227，因此不是逐案例全面胜出，也未将它事后改写为预定主方法。','',
 '256预算下，“通道共享＋扩展、不加新校准”宏F1为27.97%（v5为27.50%，原扩散27.07%），关键组28/45（v5为25/45）。完整新校准方案为27.56%、25/45，不能把这部分收益归于历史校准。带v4配额的复合版本低预算F1只有20.47%，不宜当作统一预算策略。','',
 'THEIA1入口漏选没有解决：1024预算新主方案仍为14/239，复合版本为16/239。选边后诊断发现通道检索截断前覆盖239/239，但截断后的池内仍只有17条。扩展上限32768被更高分的其他候选事件占用，历史校准提高了局部rarity，但最终分数仍不足以通过候选截断。这个具体失败点已记录，未按标签增加特例或宣称检索成功。','',
 '保留两个有用的开发候选：256预算的纯通道版本，以及主预算的新分数＋原全候选选择器；未进行按案例挑选赢家的组合，也未替换网页/CLI默认算法。下一轮需解决组级候选预算与最终评分目标的一致性，并在独立数据上验证，不能从本轮开发结果宣称超过SPARSE。','',
 '## 任务与评测范围','',
 '已实现历史条件频率校准与通道候选检索，并以相同 POI、候选账本、原始事件预算进行对照。频率统计与图扩散仍为评分中心；未接入外部告警。POI 沿用报告定位，不属于自动发现 POI 的端到端评测。', '',
 '五案例均为反复查看过的开发数据。TRACE5* 是第五案例的推断映射，尚未确认对应论文 THEIA Case 5。所有事件分类指标是冻结本地部分正例的闭世界 proxy；未标注不等于良性，官方 SPARSE 等价 FP/FN/Precision/Recall/F1 仍为 NA。没有顶会水平或跨数据集泛化结论。','',
 '## 已实现的算法','',
 '1. 固定原始最早 POI，拟合窗口为前24小时至前60分钟，校准窗口为前60至前30分钟。按 host、源实体语义/类型、关系、目标语义/类型统计通道占用分钟，重复原始日志不会在同一分钟重复计数。POI 删除对照保持历史切分不变。',
 '2. 用目标语义在同 host/关系下的频率作先验，对源语义条件频率平滑，强度10；计算负对数频率。对独立校准时段的分数作加权 midrank ECDF，含 +1/+2 平滑。拟合和校准各至少32个通道占用分钟单位：这是各通道之和，并非32个不同分钟。',
 '3. 校准值与原频率分数各占50%，输入原有扩散引擎和300秒时间重排。历史不足则原样保留旧频率分数。历史边不保证良性，节点语义来自数据库当前快照，可能含后续更新，因此不能声称严格在线、完全无未来元数据影响。',
 '4. 将同一实际端点对在总跨度不超过10秒内的事件分组，允许不同方向和关系；组内共享最高分。v5候选池再检索同组可达正分事件，锚点上限max(32768,8B)，原有锚点保留。共享分数不产生新POI，新增原始事件和路径全部计费。',
 '5. 主方法仍用lambda=1边际效用。线性贪心/MILP使用同一实际候选池；PPR/热核/去频率使用相同规则但分数生成的池不同。history_channel_portfolio同时换成v4的全候选搜索与配额选择，是复合对照，不能将差异全部归于选择器。','',
 '具体公式：q(o|h,r)=(C(h,r,o)+1)/(N(h,r)+V(h,r)+1)，p(o|h,r,s)=(C(h,r,s,o)+10q)/(C(h,r,s)+10)，z=-log(p)。校准优先级=(较低分权重+0.5×同分权重+1)/(校准总权重+2)。V仅计拟合期目标类别，另保留一个未知目标类别；这些量不被解释为恶意概率。','',
 'ECDF 思路参考 [ECOD](https://arxiv.org/abs/2201.00382)，并非复现完整ECOD；PPR/热核为既有公式适配，涉及 [Diffusion Improves Graph Learning](https://proceedings.neurips.cc/paper/2019/hash/23c894276a2c5a16470e6a31f4618d73-Abstract.html) 使用的扩散核，但未复现其整个学习系统。PCST/NetworKit沿用此前公开内核实验。','',
 '## 历史可用性与冷启动','',
 table(['案例','拟合语义通道','校准语义通道','成功校准事件/候选事件','历史构建 s'],[[labels[i],h['fit_channels'],h['calibration_channels'],f"{h['supported_events']}/{h['candidate_events']}",f"{h['total_seconds']:.2f}"] for i,h in enumerate(history)]),'',
 'FD3 与 TRACE5 没有足够的历史支持，频率校准完全回退，不能把这两例的新收益算成历史校准的贡献。SQLite只读；保留实际拟合/校准聚合数据及哈希。原数据库记录路径、大小和mtime，没有声称完整数据库文件SHA256。','',
 '## 主预算1024：本地正例事件命中数','',
 '本地正例总数依次38、15、239、229、31；PCST可能保留少于预算的事件，实际边数见CSV。','',
 table(['方法']+labels,[[label]+[tp(row(c,m)) for c in cases] for m,label in allmethods.items()]),'',
 '## 低预算256：本地正例事件命中数','',
 table(['方法']+labels,[[label]+[tp(row(c,m,256)) for c in cases] for m,label in allmethods.items() if m!='history_channel_milp']), '',
 '## 宏平均与攻击过程覆盖（POI-only）','',
 table(['方法','预算','总TP','宏Precision %','宏Recall %','宏F1 %','关键组','阶段'],[macro(m,b) for b in [256,1024] for m in ['diffusion_top','witness_rerank','marginal_rerank',*methods] if b==1024 or m!='history_channel_milp']), '',
 '## 新主方法逐案例指标（1024，POI-only）','',
 table(['案例','#E','TP','FP proxy','FN proxy','Precision %','Recall %','F1 %','关键组','阶段','时间路径可达 %'],[[labels[i],r['raw_events'],r['proxy_tp'],r['proxy_fp'],r['proxy_fn'],pct(r['proxy_precision']),pct(r['proxy_recall']),pct(r['proxy_f1']),f"{r['groups_hit']}/{r['groups_total']}",f"{r['stages_hit']}/{r['stages_total']}",pct(r['temporal_fork_fraction'])] for i,c in enumerate(cases) for r in [row(c,'history_channel')]]),'',
 '时间路径可达率是程序约束检查，不是攻击因果正确率。','',
 '## 预算曲线：64 / 256 / 1024 / 4096 的 TP','',
 table(['方法']+labels,[[allmethods[m]]+[' / '.join(tp(row(c,m,b)) for b in [64,256,1024,4096]) for c in cases] for m in ['witness_rerank','marginal_rerank',*methods] if m!='history_channel_milp']), '',
 '## 共享语义上下文（1024）：单独列出的先验收益','',
 table(['方法']+labels,[[allmethods[m]]+[tp(row(c,m,t='shared_context')) for c in cases] for m in ['witness_rerank','marginal_rerank',*methods]]),'',
 '## 删除一个 POI（1024，POI-only）','',
 table(['案例','场景','v4','v5','v6主方法','仅通道','新校准＋v4选择器','PPR','热核'],[[labels[i],s['scenario']]+[tp(row(c,m,s=s['scenario'])) for m in ['witness_rerank','marginal_rerank','history_channel','channel_only','history_channel_portfolio','channel_ppr','channel_heat']] for i,c in enumerate(cases) for s in c['scenarios'] if s['scenario']!='all']),'',
 '## 选边后候选池诊断（主预算）','',
 table(['案例','本地正例','v5池内正例','v6池内正例','v6最终命中','v6锚点数量'],[[labels[i],p['positive_events'],oldpools[i]['pool_union_positive_events'],p['pool_positive_events'],p['selected_positive_events'],p['pool']['pool_anchors']] for i,p in enumerate(pools)]),'',
 'THEIA1进一步诊断：未截断的通道候选共161450条，含239条本地正例；32,768锚点截断后连同路径仅含17条。入口组223条RECV的混合rarity约0.4285，但最终共享扩散分数仅0.01573。详见[逐组诊断](history-channel-v6-theia1-diagnosis.json)，生成脚本为scripts/diagnose_history_theia1.py。','',
 '这是选边结束后读取参考标签得到的诊断，没有用于筛选候选或本轮调参。扩大池仍有分数门槛与容量限制，不保证覆盖所有可达事件。','',
 '## MILP 同池线性目标对照（1024）','',
 table(['案例','轨道','status','gap %','贪心/上界 %','贪心TP','MILP TP'],[[labels[next(i for i,c in enumerate(cases) if c['name']==s['case'])],s['track'],s['status'],pct(s.get('mip_gap')),pct(s.get('greedy_fraction_of_upper_bound')),s.get('greedy_tp','NA'),s.get('milp_tp','NA')] for s in solver]),'',
 'MILP受20秒、1%相对gap限制；status=ok仅表示有通过预算、整数性和路径闭包检查的incumbent。求解器上界只适用于有限池的线性分数目标，不是攻击召回的上界，也不适用于lambda=1目标。超时/无解情况保留状态，不伪造最优结果。','',
 '## 新进程开销（主预算、POI-only）','',
 table(['方法','案例','暖缓存流程 s','缓存加载核验 s','分组 s','评分 s','路径 s','候选池 s','选择 s','峰值RSS MiB'],[[p['method'],labels[p['case']],f"{p['warm_candidate_pipeline_seconds']:.2f}",f"{p['cache_load_verify_seconds']:.2f}",f"{p['group_seconds']:.2f}",f"{p['score_seconds']:.2f}",f"{p['route_seconds']:.2f}",f"{p['pool_seconds']:.2f}",f"{p['select_seconds']:.2f}",f"{p['peak_rss_mib']:.1f}"] for p in profiles]),'',
 '每个方法/案例一个新进程样本，案例并行，BLAS/OMP环境为1。全部三方法均加载核验同一历史缓存（其中原分数/热核不使用新rarity），含候选账本加载、分组、评分、路径、候选池与选择；排除原始CDM导入、评测、导出。冷历史构建耗时另列，不当作免费。旧baseline是历史测量，不能从这些单样本声称精确加速比。kernel_plus_selection_seconds为窄口径，不含路径/分组/候选池。','',
 '## 审计和复现','',
 f"新增{len(new)}项配置：{audit['new_status']}；共{len(methods)}个新方法/变体。累计{len(rows)}项（含历史轮次复用），配置组合不是独立攻击样本。{len(walks)}个新增扩散诊断全部收敛={all(walks)}，POI-only最低时间路径可达率{pct(audit['poi_only_min_temporal_fork_fraction'])}%。",'',
 f"15个profile中{audit['profile_sets_match']}个选择集合与主实验一致；冷启动回退的{len(cold_checks)}个有效配置逐一验证与仅通道方案的选择集合一致。账本、源码、缓存及原始预算检查通过。",'',
 '```bash\n# 在研究worktree，使用 .venv-cross-domain Python，CASE=0..4\nexport PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1\npython scripts/prepare_conditional_history.py --case "$CASE" --output-dir "$V6/history"\n# 历史JSON manifest在所有缓存文件写完后才发布\npython scripts/run_history_channel.py --case "$CASE" --output "$V6/case$CASE.json.gz"\n# 全部案例完成后\npython scripts/evaluate_marginal_witness.py --input "$V6" --output docs/history-channel-v6-results.json\npython scripts/profile_history_channel.py --case "$CASE" --method history_channel --output "$V6/profile-$CASE-history_channel.json"\npython scripts/diagnose_history_pool.py --case "$CASE" --output "$V6/pool-$CASE.json"\npython scripts/summarize_history_channel.py\npython scripts/plot_history_channel.py --results docs/history-channel-v6-results.json --output-dir docs/figures\n```','',
 'V6固定为/root/NODOZE-pruning-release/output/tc/history-channel-v6；还需channel_only/channel_heat两组profile。拒绝覆盖已有输出；迁移复现需同步冻结父报告/账本与SQLite，按配置调整路径。所有新决策和缓存用临时文件写完后原子发布。','',
 '完整数据：[CSV](history-channel-v6-results.csv)、[JSON](history-channel-v6-results.json)、[历史构建](history-channel-v6-history.json)、[审计](history-channel-v6-audit.json)、[候选池](history-channel-v6-pool-audit.json)、[运行时间](history-channel-v6-profiles.json)。','',
 '![POI-only](figures/history-channel-v6-poi_only.png)','',
 '![共享上下文](figures/history-channel-v6-shared_context.png)','']
Path('docs/history-channel-study.md').write_text('\n'.join(lines))
print(json.dumps({k:v for k,v in audit.items() if k not in ['solver','cold_start_equal_selection_checks']},indent=2))
