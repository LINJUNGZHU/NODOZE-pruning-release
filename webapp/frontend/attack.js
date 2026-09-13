/* Hypotheses and external labels are deliberately displayed separately. */
function attackPercent(v){return v==null?'—':`${(v*100).toFixed(1)}%`;}
function renderAttack(){
 const a=state.data.attack;if(!a)return;const s=a.summary,b=a.evaluation?.pdf_benchmark,m=b?.node_metrics;
 $('#attack-badge').textContent=s.inferred_attack_nodes;$('#download-attack').href=base()+'/attack-report';
 $('#attack-summary').textContent=`${a.detector==='multiview'?'多视角学习 · 实验':a.detector==='neural'?'深度学习 · 实验':a.detector==='rules_legacy'?'旧规则 · 对照':'增强规则 · 进程链'}：分析 ${fmt(s.evaluated_process_nodes)} 个进程，选出 ${s.inferred_attack_nodes} 个候选。点击进程查看依据和原始事件。橙色节点为推断结果，仍需核验。`;
 $('#attack-metrics').innerHTML=(m?[['PDF 确认代理 · 找回率',attackPercent(m.known_positive_recall)],['命中 / 已知代理',`${m.tp} / ${m.known_positive}`],['尚待判定的预测',String(m.unreviewed_predictions)],['排除 POI · 找回率',attackPercent(m.excluding_seed_nodes?.known_positive_recall)]]:[['PDF 参考','待生成']]).map(([k,v])=>`<div>${esc(k)}<strong>${esc(v)}</strong></div>`).join('');
 $('#attack-evaluation').textContent=m?`依据用户提供的 PDF：${b.source} 原文，而非 TAPAS 名单。${m.known_positive} 个代理能由主机、时段、PID 和 C2 通信绑定到唯一 UUID；${b.ambiguous_count} 项有歧义。其他 ${m.unknown_nodes} 个进程尚未判定，因此完整精确率、正确率和 F1 暂无可靠数值。${m.known_positive===0?'本窗口没有可确认代理，不把零告警解读为已确认安全。':''}`:'尚未生成 PDF 对应节点。';
 const activity=b?.activity;$('#activity-evaluation').textContent=activity?`PDF 可观测参考事件（代理 C2 与命名文件）：候选活动覆盖 ${activity.matched_events} / ${activity.reference_events}（${attackPercent(activity.reference_event_retention)}）。这不是全部攻击事件召回率，也不是完整攻击链正确率。`:'';
 $('#pdf-reference').innerHTML=b?`<details><summary>查看 PDF 节点及原文依据</summary>${b.agents.filter(x=>!['outside_dataset','outside_window'].includes(x.status)).map(x=>`<p><strong>${esc(x.id)} · PID ${esc(x.pid)} · ${esc(x.status==='resolved'?'已绑定':x.status==='ambiguous'?'多个身份，待判定':'未观测到')}</strong><br>第 ${x.page} 页：${esc(x.excerpt)}<br><code>${esc(x.node_ids.join(', ')||x.candidate_node_ids.join(', ')||'未绑定 UUID')}</code></p>`).join('')||'<p>当前主机或时间窗口没有匹配的已确认代理。</p>'}<p class="hint">节点身份查找允许红队时间记录前后各 ${b.resolution_tolerance_seconds} 秒偏差。注入失败不代表目标进程失陷。全文哈希 ${esc(b.sha256)}</p></details>`:'';
 $('#attack-rule').textContent=a.detector==='multiview'?'分别学习属性新颖度、结构变化与事件意外程度，用攻击前数据固定七个融合判定线，至少四票产生候选。各视角百分位不是恶意概率；此适配实现不是论文复现，实测结果见上方。':a.detector==='neural'?`真实训练的掩码图编码器，使用学习到的表示与历史近邻距离判定。固定校准线 ${score(a.threshold.value)}；规则不参与神经模型的节点判定。该实验模型目前未在默认攻击窗口取得有效召回，不能当作已验证的检测器。`:a.detector==='rules'?`规则分三步：组合执行行为作为起点；识别直接启动它的近期脚本解释器；沿真实创建事件扩展最多 ${a.config.lineage_depth} 代、${a.config.lineage_seconds} 秒的子进程。仅有分位异常的进程单列复核，不自动判攻击。无通用节点攻击分数线。`:`编码隐藏命令与后续活动的组合证据，或超过当前窗口 ${Math.round(a.threshold.quantile*100)}% 分位线的历史异常交互。异常线 ${score(a.threshold.value)}，这是经验规则，不保证误报率。`;
 $('#model-info').textContent=JSON.stringify(a.model||{判定:a.contract.classification,阈值:a.threshold,标签参与推断:a.contract.truth_used},null,2);
 $('#attack-path-select').innerHTML=a.paths.length?a.paths.map((p,i)=>`<option value="${esc(p.id)}">路径 ${i+1} · ${p.support_level==='dependency_only'?'共享文件依赖 · 待核验':'进程启动 / 通信'} · ${p.event_ids.length} 条事件</option>`).join(''):'<option value="">暂无满足条件的路径</option>';
 renderAttackNodes();renderAttackPath();renderAttackStory();
}
function renderAttackNodes(){
 const a=state.data?.attack;if(!a)return;const q=$('#attack-search').value.trim().toLowerCase(),filter=$('#attack-filter').value,all=filter==='all',labels=a.evaluation?.pdf_benchmark?.labels||{};
 const nodes=a.nodes.filter(n=>(all||(filter==='review'?n.review_candidate:n.predicted_attack))&&(!q||`${n.id} ${n.label} ${n.pids.join(' ')} ${n.images.join(' ')}`.toLowerCase().includes(q)));
 $('#attack-nodes').innerHTML=nodes.map(n=>`<tr><td><button class="row-link" data-node="${esc(n.id)}">${esc(n.label.split('\\').pop())}<span class="secondary">PID ${esc(n.pids.join(', ')||'未知')}${n.seed_node?' · 起点端点':''}</span><span class="secondary">${esc(n.id.slice(0,8))}… · 查看证据 ↗</span></button></td><td>${esc(n.reasons.join('；'))}<span class="secondary">${n.predicted_attack?'推断攻击进程':'尚未判为攻击，不等于确认正常'}</span></td><td class="score-number">${score(n.anomaly_score)}<span class="secondary">${a.detector==='rules'?({corroborated_behavior:'组合行为',observed_launcher:'直接启动器',execution_descendant:'创建链后代',anomaly_review_only:'仅待复核'}[n.decision_kind]||'未判定'):a.detector==='multiview'?'票数 ≥ 4 / 7':'判定线 '+score(a.threshold.value)}</span></td><td><span class="pill ${labels[n.id]===true?'attack':labels[n.id]===false?'keep':'unknown'}">${labels[n.id]===true?'PDF：确认代理':labels[n.id]===false?'PDF：确认正常':'PDF：尚未判定'}</span></td></tr>`).join('')||'<tr><td colspan="4" class="empty">当前筛选下没有候选进程。没有告警不代表已确认安全。</td></tr>';
 $('#attack-nodes').querySelectorAll('[data-node]').forEach(b=>b.onclick=()=>showAttackNode(b.dataset.node));
}
function showAttackNode(id){
 const n=state.data.attack.nodes.find(n=>n.id===id);if(!n)return;
 showDialog('进程判定与支持证据',`<h3>${esc(n.label)}</h3><p class="hint">PID ${esc(n.pids.join(', '))} · ${esc(n.id)}</p><p>${esc(n.reasons.join('；'))}</p><div class="detail-facts"><div><small>节点异常分</small>${score(n.anomaly_score)}</div><div><small>${state.data.attack.detector==='rules'?'判定方式':state.data.attack.detector==='multiview'?'票数 · 至少达到':'判定线 · 严格大于'}</small>${state.data.attack.detector==='rules'?esc(n.reasons[0]):score(state.data.attack.threshold.value)}</div></div>${renderViewEvidence(n)}<p class="hint">以下显示前 ${Math.min(n.evidence_event_ids.length,20)} / ${fmt(n.evidence_event_ids.length)} 条支持事件。完整事件 ID 见下载报告。${n.neural?'特征重构误差仅供观察，不是近邻距离的因果解释。':''}</p><div class="path-events">${n.evidence_event_ids.slice(0,20).map(id=>`<button data-event="${esc(id)}">事件 ${esc(id.slice(0,8))} ↗</button>`).join('')}</div><pre>${esc(JSON.stringify({节点:n.id,映像:n.images,判定:n.status,异常分:n.anomaly_score,阈值:state.data.attack.threshold,人工起点端点:n.seed_node,规则创建链证据:n.rule_witness,多视角观测:n.multiview,神经模型观测:n.neural?{分钟:n.neural.minute,重构误差分量:n.neural.feature_errors,说明:n.neural.explanation}:undefined,命令特征:state.data.attack.detector==='rules'?n.command_signals:undefined},null,2))}</pre>`);bindEventButtons($('#detail-content'));
}
function renderAttackPath(){
 const a=state.data?.attack;if(!a)return;const p=a.paths.find(p=>p.id===$('#attack-path-select').value);
 if(!p){$('#attack-path').innerHTML='<p class="empty">当前没有可输出的活动路径，不自动补齐缺失事件。</p>';$('#attack-path-note').textContent='';$('#attack-path-events').innerHTML='';return;}
 $('#attack-path-note').textContent=`${localTime(p.start)} → ${localTime(p.end)} · ${p.event_ids.length} 条真实、严格时序有向事件。${p.interpretation}。${a.summary.untraced_predictions?`为控制大图搜索成本，仅为排名前 ${a.summary.path_anchor_nodes} 个候选展开路径；另 ${a.summary.untraced_predictions} 个预测仍完整列出。`:''}${p.lineage_truncated?'此路径的祖先搜索已达到深度上限。':''}`;
 const known=new Map(a.nodes.map(n=>[n.id,n]));
 $('#attack-path').innerHTML=p.node_ids.map((id,i)=>{const n=known.get(id),r=state.nodes.get(id);return `${i?'<span class="path-arrow" aria-hidden="true">→</span>':''}<button class="path-node ${n?.predicted_attack?'suspect':''}" data-path-node="${esc(id)}">${esc(short((n?.label||r?.label||id).split('\\').pop(),40))}<small>${n?`PID ${esc(n.pids.join('/'))} · ${n.predicted_attack?'推断攻击':'上下文进程'}`:'文件或网络资源 · 不自动判恶意'}</small></button>`;}).join('');
 $('#attack-path').querySelectorAll('[data-path-node]').forEach(b=>b.onclick=()=>{if(known.has(b.dataset.pathNode))showAttackNode(b.dataset.pathNode);else{const idx=p.node_ids.indexOf(b.dataset.pathNode);showEvent(p.event_ids[Math.max(0,idx-1)]);}});
 $('#attack-path-events').innerHTML=p.event_ids.map((id,i)=>`<button data-event="${esc(id)}">${i+1} · 事件 ${esc(id.slice(0,8))} ↗</button>`).join('');bindEventButtons($('#attack-path-events'));
}
document.addEventListener('DOMContentLoaded',()=>{for(const id of ['#attack-search','#attack-filter'])$(id).addEventListener('input',renderAttackNodes);$('#attack-path-select').onchange=renderAttackPath;$('#view-activity').onclick=()=>{$('#edge-search').value='';$('#edge-decision').value='activity';state.page=0;selectTab('events');};});

function renderViewEvidence(node){
 const m=node.multiview;if(!m)return '';
 const names={attribute:'属性新颖度',structural:'结构变化',causal:'事件意外程度'};
 return `<div class="view-evidence">${Object.entries(m.views).map(([key,v])=>`<div><strong>${esc(names[key]||key)}</strong><span>历史百分位 ${attackPercent(v.percentile)} · 原始分 ${score(v.score)}</span><meter min="0" max="1" value="${Number(v.percentile)}" aria-label="${esc(names[key]||key)}历史百分位"></meter></div>`).join('')}</div><p class="hint">${m.votes} / 7 票；百分位表示相对校准历史的新颖程度，不是攻击概率。三个分量可以相关，七票并非七份独立证据。</p>`;
}
function renderAttackStory(){
 const story=state.data?.attack?.story,el=$('#attack-story');if(!el)return;
 if(!story){el.innerHTML='<p class="hint">重新分析后可查看带原始事件引用的活动摘要。</p>';return;}
 el.innerHTML=`<h3>从日志看发生了什么</h3><p class="hint">${esc(story.contract)}</p><div class="story-grid">${story.stages.map(stage=>`<article><h4>${esc(stage.title)}</h4><p>${fmt(stage.event_count)} 条事件 · ${esc(localTime(stage.start))} → ${esc(localTime(stage.end))}</p><p class="hint">${esc(stage.limitation)}</p><div class="path-events">${stage.event_ids.slice(0,3).map(id=>`<button data-event="${esc(id)}">原始事件 ${esc(id.slice(0,8))} ↗</button>`).join('')}</div></article>`).join('')||'<p class="empty">当前没有预测进程的活动可供汇总。</p>'}</div><p class="hint">尚不能据此确认：${story.unsupported_claims.map(esc).join('、')}。摘要由本地证据生成，未调用 LLM。</p>`;
 bindEventButtons(el);
}
