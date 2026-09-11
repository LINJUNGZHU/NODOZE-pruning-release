/* Compact node hypotheses and actual directed event paths. Truth is an overlay. */
function renderAttack(){
 const a=state.data.attack;
 if(!a){$('#attack-summary').textContent='应用 POI 后生成攻击节点与路径。';return;}
 $('#attack-quantile').value=String(a.config.anomaly_quantile);
 const m=a.evaluation.node_metrics,p=a.evaluation.path_metrics,s=a.summary;
 $('#attack-summary').textContent=`从全部 ${fmt(s.evaluated_process_nodes)} 个进程对象推断 ${s.inferred_attack_nodes} 个攻击候选，输出 ${s.execution_paths} 条启动/通信路径、${s.dependency_only_paths} 条待确认依赖关联，共 ${s.path_edges} 条路径事件。识别独立于剪枝预算；人工 POI 不会自动计作识别成功。`;
 $('#download-attack').href=`/api/datasets/${encodeURIComponent(state.data.dataset.id)}/attack-report`;
 $('#attack-metrics').innerHTML=[['推断攻击进程',s.inferred_attack_nodes,'尚需证据复核'],['PDF 已知代理找回',`${m.tp} / ${m.known_positive}`,`排除 POI 节点：${m.excluding_seed_nodes.tp} / ${m.excluding_seed_nodes.known_positive}`],['C2 参考片段找回',`${p.recovered_reference_segments} / ${p.observable_reference_segments}`,'仅可观测通信片段，非完整攻击链']].map(([k,v,n])=>`<div><span>${esc(k)}</span><strong>${esc(v)}</strong><small>${esc(n)}</small></div>`).join('');
 const b=a.evaluation.published_benchmark;
 $('#attack-evaluation').textContent=b?`公开标注基准（${b.node_metrics.known_positive} 个攻击进程对象 / ${b.node_metrics.known_negative} 个正常对象，按该标注方案）：精确率 ${attackPercent(b.node_metrics.precision)}，召回率 ${attackPercent(b.node_metrics.recall)}，F1 ${attackPercent(b.node_metrics.f1)}，Accuracy ${attackPercent(b.node_metrics.accuracy)}。`:`PDF 未提供完整正常标签：${m.unreviewed_predictions} 个预测尚未标注，整体 Accuracy、F1 无法可靠计算。`;
 $('#attack-rule').textContent=`两条判定通道：① PowerShell 编码命令与隐藏窗口同时出现，创建后有出站连接或子进程，且处于 POI 调查关联范围；② 至少 ${a.config.min_families} 个不同历史异常交互，聚合分严格超过当前窗口 ${a.threshold.quantile*100}% 分位线（${a.threshold.value==null?'无可用样本':score(a.threshold.value)}，${a.threshold.population_size} 个样本）。同分不强行拆开。`;
 $('#attack-limits').textContent=`${b?'公开基准将未列入恶意清单的节点按正常计数；这是其标注约定，含继承标签与已知数据问题。':''}${a.evaluation.limitation} 分位线是调查启发式，不是误报率或恶意概率。当前为 POI 前后完整窗口的回溯调查。路径仅由严格递增时间的真实有向事件构成，连接进程与资源不自动视为恶意。`;
 $('#attack-gaps').textContent=a.evaluation.narrative_gaps.map(g=>`${g.label}：${g.observable_in_window?(g.recovered?'已输出遥测关联，攻击机制未证实':'窗口内有路径，但当前推断未输出'):'当前日志未观察到连续有向路径'}。`).join(' ')||'当前参考不足以核验跨阶段攻击链。';
 const previous=$('#attack-path-select').value;
 $('#attack-path-select').innerHTML=a.paths.map((p,i)=>`<option value="${esc(p.id)}">路径 ${i+1} · ${p.support_level==='dependency_only'?'共享文件依赖 · 待确认':p.kind==='execution_lineage'?'进程启动与通信':'进程创建关联'} · ${p.event_ids.length} 条事件</option>`).join('');
 if(a.paths.some(p=>p.id===previous))$('#attack-path-select').value=previous;
 $('#attack-node-detail').open=false;
 renderAttackNodes();renderAttackPath();
}
function attackPercent(v){return v==null?'无法计算':`${(v*100).toFixed(2)}%`;}
function renderAttackNodes(){
 const a=state.data?.attack;if(!a)return;
 const q=$('#attack-search').value.trim().toLowerCase(),all=$('#attack-filter').value==='all';
 const known=new Set(a.evaluation.resolved_processes.filter(n=>n.resolved).flatMap(n=>n.node_ids));
 const external=a.evaluation.published_benchmark?.labels||{};
 const nodes=a.nodes.filter(n=>(all||n.predicted_attack)&&(!q||`${n.id} ${n.pids.join(' ')} ${n.images.join(' ')}`.toLowerCase().includes(q)));
 $('#attack-nodes').innerHTML=nodes.map(n=>`<tr tabindex="0" data-node="${esc(n.id)}"><td><span class="${n.predicted_attack?'attack-red':''}">${esc(n.label.split('\\').pop())}</span><small>PID ${esc(n.pids.join(', ')||'未知')}${n.seed_node?' · 人工 POI 端点':''}</small><small>${esc(n.id)}</small></td><td>${esc(n.reasons.join('；'))}<small>${n.predicted_attack?'推断攻击进程':'未判定为攻击（非正常标签）'}</small></td><td>${score(n.anomaly_score)}<small>${n.family_count} 个历史异常交互类型</small></td><td>${known.has(n.id)?'PDF 已知代理':external[n.id]===true?'公开标注：攻击':external[n.id]===false?'公开标注：正常':'未标注'}<small>标签不参与推断</small></td></tr>`).join('')||'<tr><td colspan="4">没有符合条件的进程。</td></tr>';
 $('#attack-nodes').querySelectorAll('[data-node]').forEach(el=>{el.onclick=()=>showAttackNode(el.dataset.node);el.onkeydown=e=>{if(e.key==='Enter')el.click();};});
}
function attackEventButton(id){const e=state.byId.get(id);return `<button type="button" data-event="${esc(id)}">${esc(localTime(e.timestamp))} · ${esc(e.relation)} · ${esc(e.id.slice(0,8))}</button>`;}
function bindAttackEvents(container){container.querySelectorAll('[data-event]').forEach(b=>b.onclick=()=>{details(state.byId.get(b.dataset.event));$('#event-detail').scrollIntoView({behavior:'smooth',block:'center'});});}
function showAttackNode(id){
 const n=state.data.attack.nodes.find(n=>n.id===id);
 if(!n)return;
 $('#attack-node-detail').open=true;
 $('#attack-node-json').textContent=JSON.stringify({节点:n.id,PID:n.pids,映像:n.images,判定:n.status,依据:n.reasons,命令行特征:n.command_signals,异常聚合分:n.anomaly_score,分位线:state.data.attack.threshold,人工POI端点:n.seed_node},null,2);
 $('#attack-node-events').innerHTML=n.evidence_event_ids.map(attackEventButton).join('');bindAttackEvents($('#attack-node-events'));
}
function renderAttackPath(){
 const a=state.data?.attack;if(!a)return;
 const p=a.paths.find(p=>p.id===$('#attack-path-select').value),svg=$('#attack-graph');
 if(!p){svg.innerHTML='';$('#attack-path-note').textContent='当前没有满足条件的攻击路径。';$('#attack-path-events').innerHTML='';return;}
 $('#attack-path-note').textContent=`${p.start} → ${p.end} · ${p.event_ids.length} 条真实事件，逐步方向与严格时间顺序已校验${p.lineage_truncated?'；启动祖先达到深度上限，显示的是路径片段':''}。${p.interpretation}。此图展示完整选中路径，不是剪枝抽样图。`;
 const width=Math.max(640,p.node_ids.length*200),known=new Map(a.nodes.map(n=>[n.id,n]));
 svg.setAttribute('viewBox',`0 0 ${width} 170`);svg.style.width=`${width}px`;svg.style.height='170px';
 svg.innerHTML='<defs><marker id="attack-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8" fill="#738477"/></marker></defs>'+p.event_ids.map((id,i)=>{const e=state.byId.get(id);return `<g data-event="${esc(id)}" class="attack-path-edge"><title>${esc(e.relation)} · ${esc(e.timestamp)} · ${esc(id)}</title><path d="M${i*200+118} 75H${(i+1)*200+82}" stroke="#87988c" stroke-width="2" marker-end="url(#attack-arrow)"/><text x="${i*200+200}" y="43" text-anchor="middle">${esc(e.relation)}</text><text x="${i*200+200}" y="58" text-anchor="middle">${esc(localTime(e.timestamp))}</text></g>`;}).join('')+p.node_ids.map((id,i)=>{const n=known.get(id),fallback=state.nodes.get(id),x=i*200+100,color=n?.predicted_attack?'#b5473a':n?'#657a6b':'#c17a36',label=n?`${n.label.split('\\').pop()} · ${n.pids.join('/')}`:fallback?.label||id;return `<g data-node="${esc(id)}" tabindex="0" role="button" aria-label="${esc(label)}"><title>${esc(label)} · ${esc(id)}</title><circle cx="${x}" cy="75" r="16" fill="${color}"/><text x="${x}" y="114" text-anchor="middle">${esc(short(label))}</text><text x="${x}" y="135" text-anchor="middle">${n?.predicted_attack?'推断攻击':n?'路径连接进程':'关联资源'}</text></g>`;}).join('');
 svg.querySelectorAll('[data-node]').forEach(g=>{g.onclick=()=>{if(known.has(g.dataset.node))showAttackNode(g.dataset.node);else{const id=p.event_ids.find(id=>{const e=state.byId.get(id);return e.source===g.dataset.node||e.target===g.dataset.node;});details(state.byId.get(id));$('#event-detail').scrollIntoView({behavior:'smooth',block:'center'});}};g.onkeydown=e=>{if(e.key==='Enter')g.click();};});
 bindAttackEvents(svg);
 $('#attack-path-events').innerHTML=p.event_ids.map(attackEventButton).join('');bindAttackEvents($('#attack-path-events'));
}
document.addEventListener('DOMContentLoaded',()=>{
 for(const id of ['#attack-search','#attack-filter'])$(id).addEventListener('input',renderAttackNodes);
 $('#attack-path-select').addEventListener('change',renderAttackPath);
});
