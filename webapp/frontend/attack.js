/* Hypotheses and external labels are deliberately displayed separately. */
function attackPercent(v){return v==null?'—':`${(v*100).toFixed(1)}%`;}
function renderAttack(){
 const a=state.data.attack;if(!a)return;const s=a.summary,b=a.evaluation?.published_benchmark,m=b?.node_metrics;
 $('#attack-badge').textContent=s.inferred_attack_nodes;$('#download-attack').href=base()+'/attack-report';
 $('#attack-summary').textContent=`${a.detector==='neural'?'深度学习 · 实验':'规则对照'}：分析 ${fmt(s.evaluated_process_nodes)} 个进程，选出 ${s.inferred_attack_nodes} 个候选。点击进程查看依据和原始事件。橙色节点为推断结果，仍需核验。`;
 $('#attack-metrics').innerHTML=(m?[['命中比例 · Precision',attackPercent(m.precision)],['找回比例 · Recall',attackPercent(m.recall)],['综合指标 · F1',attackPercent(m.f1)],['命中 / 误报 / 漏报',`${m.tp} / ${m.fp} / ${m.fn}`]]:[['已知攻击命中',String(a.evaluation?.node_metrics.tp??'—')],['完整精确率','标签不足'],['完整召回率','标签不足'],['完整 F1','标签不足']]).map(([k,v])=>`<div>${esc(k)}<strong>${esc(v)}</strong></div>`).join('');
 $('#attack-evaluation').textContent=m?`本例参考标签：${m.known_positive} 个攻击进程、${m.known_negative} 个正常进程。Accuracy ${attackPercent(m.accuracy)}；未预测到的攻击同样计入漏报。公开标注将未列入攻击清单的进程按正常计数，这是其标注约定，不代表逐个经过人工核验。`:'没有覆盖本例的完整参考标签，不能据此计算整体正确率。';
 $('#attack-rule').textContent=a.detector==='neural'?`真实训练的掩码图编码器，使用学习到的表示与历史近邻距离判定。固定校准线 ${score(a.threshold.value)}；规则不参与神经模型的节点判定。该实验模型目前未在默认攻击窗口取得有效召回，不能当作已验证的检测器。`:`编码隐藏命令与后续活动的组合证据，或超过当前窗口 ${Math.round(a.threshold.quantile*100)}% 分位线的历史异常交互。异常线 ${score(a.threshold.value)}，这是经验规则，不保证误报率。`;
 $('#model-info').textContent=JSON.stringify(a.model||{判定:a.contract.classification,阈值:a.threshold,标签参与推断:a.contract.truth_used},null,2);
 $('#attack-path-select').innerHTML=a.paths.length?a.paths.map((p,i)=>`<option value="${esc(p.id)}">路径 ${i+1} · ${p.support_level==='dependency_only'?'共享文件依赖 · 待核验':'进程启动 / 通信'} · ${p.event_ids.length} 条事件</option>`).join(''):'<option value="">暂无满足条件的路径</option>';
 renderAttackNodes();renderAttackPath();
}
function renderAttackNodes(){
 const a=state.data?.attack;if(!a)return;const q=$('#attack-search').value.trim().toLowerCase(),all=$('#attack-filter').value==='all',labels=a.evaluation?.published_benchmark?.labels||{};
 const nodes=a.nodes.filter(n=>(all||n.predicted_attack)&&(!q||`${n.id} ${n.label} ${n.pids.join(' ')} ${n.images.join(' ')}`.toLowerCase().includes(q)));
 $('#attack-nodes').innerHTML=nodes.map(n=>`<tr><td><button class="row-link" data-node="${esc(n.id)}">${esc(n.label.split('\\').pop())}<span class="secondary">PID ${esc(n.pids.join(', ')||'未知')}${n.seed_node?' · 起点端点':''}</span><span class="secondary">${esc(n.id.slice(0,8))}… · 查看证据 ↗</span></button></td><td>${esc(n.reasons.join('；'))}<span class="secondary">${n.predicted_attack?'推断攻击进程':'尚未判为攻击，不等于确认正常'}</span></td><td class="score-number">${score(n.anomaly_score)}<span class="secondary">判定线 ${score(a.threshold.value)}</span></td><td><span class="pill ${labels[n.id]===true?'attack':labels[n.id]===false?'keep':'unknown'}">${labels[n.id]===true?'参考：攻击':labels[n.id]===false?'参考：正常':'尚未标注'}</span></td></tr>`).join('')||'<tr><td colspan="4" class="empty">当前筛选下没有候选进程。没有告警不代表已确认安全。</td></tr>';
 $('#attack-nodes').querySelectorAll('[data-node]').forEach(b=>b.onclick=()=>showAttackNode(b.dataset.node));
}
function showAttackNode(id){
 const n=state.data.attack.nodes.find(n=>n.id===id);if(!n)return;
 showDialog('进程判定与支持证据',`<h3>${esc(n.label)}</h3><p class="hint">PID ${esc(n.pids.join(', '))} · ${esc(n.id)}</p><p>${esc(n.reasons.join('；'))}</p><div class="detail-facts"><div><small>节点异常分</small>${score(n.anomaly_score)}</div><div><small>判定线 · 严格大于</small>${score(state.data.attack.threshold.value)}</div></div><p class="hint">以下显示前 ${Math.min(n.evidence_event_ids.length,20)} / ${fmt(n.evidence_event_ids.length)} 条支持事件。完整事件 ID 见下载报告。${n.neural?'特征重构误差仅供观察，不是近邻距离的因果解释。':''}</p><div class="path-events">${n.evidence_event_ids.slice(0,20).map(id=>`<button data-event="${esc(id)}">事件 ${esc(id.slice(0,8))} ↗</button>`).join('')}</div><pre>${esc(JSON.stringify({节点:n.id,映像:n.images,判定:n.status,异常分:n.anomaly_score,阈值:state.data.attack.threshold,人工起点端点:n.seed_node,神经模型观测:n.neural?{分钟:n.neural.minute,重构误差分量:n.neural.feature_errors,说明:n.neural.explanation}:undefined,命令特征:state.data.attack.detector==='rules'?n.command_signals:undefined},null,2))}</pre>`);bindEventButtons($('#detail-content'));
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
document.addEventListener('DOMContentLoaded',()=>{for(const id of ['#attack-search','#attack-filter'])$(id).addEventListener('input',renderAttackNodes);$('#attack-path-select').onchange=renderAttackPath;});
