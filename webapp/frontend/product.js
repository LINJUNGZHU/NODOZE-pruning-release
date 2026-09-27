'use strict';
const $=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num=v=>Number(v).toLocaleString('zh-CN');
const pct=v=>(v*100).toFixed(1)+'%';
const short=(v,n=48)=>String(v??'').length>n?String(v).slice(0,n-1)+'…':String(v??'');
const state={datasets:[],dataset:null,node:null,anchor:null,run:null,busy:false,nodeVersion:0,anchorVersion:0,eventVersion:0,anchorPage:0,eventPage:0,history:[],historyPage:0,offline:false};
const typeLabel=t=>({process:'进程',file:'文件',flow:'网络流',registry:'注册表'}[t]||t);
async function api(path,options={}){
 const response=await fetch(path,options);let body;
 try{body=await response.json();}catch{throw Error(`服务暂不可用 (${response.status})。`);}
 if(!response.ok){if(response.status===401){$('#login-panel').hidden=false;$('#app-content').hidden=true;$('#access-token').focus();}throw Error(body.error||`请求失败 (${response.status})`);}
 return body;
}
function report(error){$('#error').textContent=error.message;$('#error').hidden=false;}
function clearError(){$('#error').hidden=true;}
function datasetBase(){return '/api/datasets/'+encodeURIComponent(state.dataset.id);}
function runBase(){return '/api/investigations/'+state.run.run.id;}
function pending(){return !!state.node&&!!state.anchor&&!state.busy&&!state.offline;}
function updateRunButton(){$('#run-button').disabled=!pending();}
function setBusy(value){
 state.busy=value;$('#run-button').innerHTML=value?'正在统计与核验…':'开始节点调查 <span>→</span>';
 document.querySelectorAll('#workspace-panel input,#workspace-panel select,#workspace-panel button,#history-nav,#workspace-nav').forEach(e=>e.disabled=value);
 updateRunButton();
}
function switchPanel(name){
 if(state.busy)return;
 for(const key of ['workspace','history','method']){$('#'+key+'-panel').hidden=key!==name;$('#'+key+'-nav').classList.toggle('active',key===name);}
 $('#section-name').textContent={workspace:'节点调查',history:'调查记录',method:'方法与交付边界'}[name];
 if(name==='history')loadHistory().catch(report);
}
async function selectDataset(id,preserveRun=false){
 state.offline=false;
 state.dataset=state.datasets.find(d=>d.id===id);state.node=null;state.anchor=null;state.anchorVersion++;state.eventVersion++;if(!preserveRun)state.run=null;
 $('#anchor-settings').hidden=true;if(!preserveRun){$('#result').hidden=true;$('#empty-state').hidden=false;}
 $('#node-search').value='';$('#node-type').value='all';$('#candidate-count').textContent=num(state.dataset.metrics.candidate_edges);
 const start=state.dataset.window_start,end=state.dataset.window_end;
 $('#window-label').textContent=start&&end?`${start.slice(11,16)} – ${end.slice(11,16)} ${start.slice(-6)}`:'已索引的事件窗口';
 $('#dataset-description').textContent=state.dataset.description;
 $('#budget').max=state.dataset.metrics.candidate_edges;$('#budget').value=Math.max(1,Math.floor(state.dataset.metrics.candidate_edges*.05));
 $('#run-status').textContent='';updateBudget();updateRunButton();clearError();await loadNodes();
}
async function loadNodes(){
 const version=++state.nodeVersion;
 $('#node-count').textContent='正在查找…';
 const data=await api(datasetBase()+'/nodes?q='+encodeURIComponent($('#node-search').value)+'&type='+encodeURIComponent($('#node-type').value));
 if(version!==state.nodeVersion)return;
 $('#node-count').textContent=`${num(data.total)} 个匹配节点${data.total>60?' · 显示前 60 个，请输入名称缩小范围':''}`;
 $('#node-list').innerHTML=data.nodes.map(n=>`<button type="button" class="node-item ${state.node?.id===n.id?'selected':''}" data-node="${esc(n.id)}" title="${esc(n.label)} · ${esc(n.id)}" aria-pressed="${state.node?.id===n.id}"><span class="type-icon ${esc(n.type)}">${n.type==='process'?'▣':n.type==='file'?'▤':'◇'}</span><span class="node-text"><strong>${esc(n.label)}</strong><small>${esc(typeLabel(n.type))} · ${num(n.event_count)} 条关联事件</small></span></button>`).join('')||'<p class="empty-message">没有匹配节点，试试名称片段或完整 UUID。</p>';
 $('#node-list').querySelectorAll('button').forEach(b=>b.onclick=()=>selectNode(data.nodes.find(n=>n.id===b.dataset.node)).catch(report));
}
async function selectNode(node){
 if(state.busy||state.offline)return;
 state.node=node;state.anchor=null;state.anchorPage=0;$('#anchor-search').value='';$('#anchor-settings').hidden=false;
 $('#selected-node-label').textContent=node.label;$('#selected-node-id').textContent=node.id;
 $('#run-status').textContent=state.run?'新的起点尚未运行；右侧仍为上次冻结结果。':'请选择直接关联事件作为时间锚。';
 $('#node-list').querySelectorAll('button').forEach(b=>{b.classList.toggle('selected',b.dataset.node===node.id);b.setAttribute('aria-pressed',b.dataset.node===node.id);});
 updateRunButton();await loadAnchors();
}
async function loadAnchors(){
 if(!state.node)return;
 const version=++state.anchorVersion;
 $('#anchor-list').innerHTML='<p class="small">读取关联事件…</p>';
 const data=await api(datasetBase()+'/nodes/'+encodeURIComponent(state.node.id)+'/events?page='+state.anchorPage+'&q='+encodeURIComponent($('#anchor-search').value));
 if(version!==state.anchorVersion)return;
 $('#anchor-list').innerHTML=data.events.map(e=>`<button type="button" class="anchor-item ${state.anchor?.id===e.id?'selected':''}" data-event="${esc(e.id)}" aria-pressed="${state.anchor?.id===e.id}"><span class="radio"></span><span>${esc(e.timestamp)}<small>${esc(e.relation)} · ${esc(short(e.source_label,22))} → ${esc(short(e.target_label,22))}</small><small>${esc(short(e.id,29))}</small></span></button>`).join('')||'<p class="empty-message">没有匹配事件。</p>';
 $('#anchor-list').querySelectorAll('button').forEach(b=>b.onclick=()=>{
  state.anchor=data.events.find(e=>e.id===b.dataset.event);
  $('#anchor-list').querySelectorAll('button').forEach(x=>{x.classList.toggle('selected',x===b);x.setAttribute('aria-pressed',x===b);});
  $('#run-status').textContent='已选时间锚，点击开始调查。';updateRunButton();
 });
 $('#anchor-page').textContent=`${state.anchorPage+1} / ${Math.max(1,Math.ceil(data.total/40))} · ${num(data.total)} 条`;
 $('#anchor-prev').disabled=state.anchorPage===0;$('#anchor-next').disabled=(state.anchorPage+1)*40>=data.total;
}
function updateBudget(){if(state.dataset){const budget=Number($('#budget').value);$('#budget-ratio').textContent=Number.isFinite(budget)?pct(budget/state.dataset.metrics.candidate_edges):'—';}}
function renderRun(data){
 state.run=data;state.eventPage=0;state.eventVersion++;$('#result').hidden=false;$('#empty-state').hidden=true;
 const m=data.metrics,r=data.run;
 $('#result-title').textContent=r.node_label;
 $('#run-meta').textContent=`${r.id.slice(0,10)} · ${new Date(r.created_at).toLocaleString('zh-CN')} · 锚事件 ${data.poi.timestamp}`;
 $('#export-json').href=runBase()+'/export';$('#export-csv').href=runBase()+'/export.csv';
 $('#metrics').innerHTML=[['候选事件',num(m.candidate_edges),`${num(m.candidate_nodes)} 个节点`],['保留事件',num(m.retained_edges),`${num(m.retained_nodes)} 个节点`],['事件缩减',pct(data.summary.event_reduction_ratio),'精确事件数量比例'],['预算使用',pct(data.summary.budget_utilization),`预算上限 ${num(m.budget_edges)} 条`]].map(([label,value,note],i)=>`<div class="metric ${i===2?'highlight':''}"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(note)}</small></div>`).join('');
 $('#certificate-label').textContent=data.summary.certificate_valid?'✓ 预算、起点、时间路径与账本核验通过':'核验未通过';
 $('#unused-label').textContent=`未用预算 ${num(data.summary.unused_budget)} 条`;
 $('#elapsed-label').textContent=`算法与输入核验 ${Number(r.elapsed_seconds).toFixed(2)} 秒`;
 $('#preview-note').textContent=`独立预览 ${num(data.graph.shown_events)} / ${num(data.graph.incident_events)} 条直接关联事件；全量指标按 ${num(m.candidate_edges)} 条计算。`;
 $('#before-count').textContent=num(data.graph.shown_events)+' 条预览';$('#after-count').textContent=num(data.graph.edges.filter(e=>e.retained).length)+' 条预览';
 $('#event-search').value='';$('#event-filter').value='retained';renderGraphs();loadEvents().catch(report);
}
function renderGraphs(){
 const data=state.run,focus=data.poi.node_id,neighbors=data.graph.nodes.filter(n=>n.id!==focus).sort((a,b)=>a.id.localeCompare(b.id));
 const positions=new Map([[focus,[325,177]]]);
 neighbors.forEach((n,i)=>{const angle=i*2*Math.PI/Math.max(1,neighbors.length)-Math.PI/2;const radius=neighbors.length>36?(i%2?145:110):135;positions.set(n.id,[325+Math.cos(angle)*radius*1.7,177+Math.sin(angle)*radius]);});
 const colors={process:'#61998e',file:'#a18bbd',flow:'#c09d69'};
 for(const [selector,after] of [['#before-graph',false],['#after-graph',true]]){
  const visible=data.graph.edges.filter(e=>!after||e.retained),nodeIds=new Set(visible.flatMap(e=>[e.source,e.target]));nodeIds.add(focus);
  const marker=after?'arrow-after':'arrow-before';
  let html=`<defs><marker id="${marker}" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L7 3.5L0 7" fill="${after?'#7893d9':'#a2b1c4'}"/></marker></defs>`;
  for(const e of visible){const a=positions.get(e.source),b=positions.get(e.target);if(!a||!b)continue;
   const len=Math.hypot(b[0]-a[0],b[1]-a[1]);
   if(len<1){html+=`<path d="M${a[0]-7} ${a[1]}c-26 -36 40 -36 14 0" fill="none" stroke="#95a9cb" marker-end="url(#${marker})"/>`;continue;}
   const ra=e.source===focus?19:5,rb=e.target===focus?21:7;
   html+=`<line x1="${a[0]+(b[0]-a[0])*ra/len}" y1="${a[1]+(b[1]-a[1])*ra/len}" x2="${b[0]-(b[0]-a[0])*rb/len}" y2="${b[1]-(b[1]-a[1])*rb/len}" stroke="${after?'#7d9bdb':'#bdc9d8'}" stroke-width="${after?'1.1':'.7'}" stroke-opacity="${after?'.55':'.35'}" marker-end="url(#${marker})"><title>${esc(e.relation)} · ${esc(e.timestamp)} · ${esc(e.id)}</title></line>`;
  }
  for(const n of data.graph.nodes){if(!nodeIds.has(n.id))continue;const p=positions.get(n.id),isFocus=n.id===focus;
   html+=`<g tabindex="0" role="button" aria-label="调查节点 ${esc(n.label)}" data-node="${esc(n.id)}"><title>${esc(n.label)} · ${esc(n.id)}</title>${isFocus?`<circle cx="${p[0]}" cy="${p[1]}" r="28" fill="#335cde" opacity=".07"/>`:''}<circle cx="${p[0]}" cy="${p[1]}" r="${isFocus?16:4.5}" fill="${isFocus?'#335cde':colors[n.type]||'#c09d69'}" stroke="white" stroke-width="2"/>${isFocus?`<text x="${p[0]}" y="${p[1]+4}" text-anchor="middle" fill="white" font-size="12">◎</text><text x="${p[0]}" y="${p[1]+45}" text-anchor="middle" fill="#335cde" font-size="12" font-weight="600">${esc(short(n.label,34))}</text><text x="${p[0]}" y="${p[1]+61}" text-anchor="middle" fill="#8799b8" font-size="9">调查焦点</text>`:neighbors.length<24?`<text x="${p[0]}" y="${p[1]+16}" text-anchor="middle" font-size="8" fill="#8f9eb2">${esc(short(n.label,23))}</text>`:''}</g>`;
  }
  $(selector).innerHTML=html;
  $(selector).querySelectorAll('[data-node]').forEach(g=>{
   const activate=()=>selectNode(data.graph.nodes.find(n=>n.id===g.dataset.node)).catch(report);
   g.onclick=activate;g.onkeydown=e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();activate();}};
  });
 }
}
async function loadEvents(){
 if(!state.run)return;
 const version=++state.eventVersion;
 const data=await api(runBase()+'/events?page='+state.eventPage+'&decision='+$('#event-filter').value+'&q='+encodeURIComponent($('#event-search').value));
 if(version!==state.eventVersion)return;
 $('#evidence-count').textContent=num(data.total)+' 条事件';
 $('#event-rows').innerHTML=data.events.map(e=>`<tr><td>${esc(e.timestamp)}<small>${esc(short(e.id,18))}</small></td><td>${esc(short(e.source_label,28))}<small>→ ${esc(short(e.target_label,28))}</small></td><td>${esc(e.relation)}</td><td>${num(e.historical_count)}</td><td><span class="decision-tag ${e.retained?'':'removed'}">${e.retained?'● 保留':'○ 剪去'}</span><small>${esc(e.reason)}</small></td><td><button data-detail="${esc(e.id)}" aria-label="查看事件 ${esc(e.id)}">详情 ↗</button></td></tr>`).join('')||'<tr><td colspan="6" class="empty-message">当前筛选没有事件。</td></tr>';
 $('#event-rows').querySelectorAll('button').forEach(b=>b.onclick=()=>showEvent(b.dataset.detail).catch(report));
 $('#events-page').textContent=`第 ${state.eventPage+1} / ${Math.max(1,Math.ceil(data.total/30))} 页 · 共 ${num(data.total)} 条`;
 $('#events-prev').disabled=state.eventPage===0;$('#events-next').disabled=(state.eventPage+1)*30>=data.total;
}
async function showEvent(id){
 const runId=state.run.run.id;
 const data=await api(runBase()+'/events/'+encodeURIComponent(id));
 if(runId!==state.run.run.id)return;
 const e=data.event;
 $('#event-detail').innerHTML=`<p><code>${esc(e.id)}</code></p><div class="detail-facts"><div><small>调查相关性分数</small>${Number(e.score).toPrecision(6)}</div><div><small>严格早于时间锚的频次</small>${num(e.historical_count)}</div><div><small>本次决策</small>${e.retained?'保留':'剪去'}</div></div><p>${esc(e.reason)}</p><section class="detail-section"><h3>见证子图 · ${num(data.witness.length)} 条事件</h3><p class="small">按时间升序展示；见证子图可包含来路与分支，不是单条线性路径。</p>${data.witness.map(w=>`<div class="witness-row">${esc(w.source_label)} → ${esc(w.target_label)}<br><small>${esc(w.timestamp)} · ${esc(w.relation)} · ${w.retained?'已保留':'未保留'}<br>${esc(w.id)}</small></div>`).join('')||'<p class="small">该事件没有被分配到已保留的见证路径。剪去事件不声称安全。</p>'}</section><section class="detail-section"><h3>原始日志与决策</h3><pre>${esc(JSON.stringify({timestamp:e.timestamp,source_file:e.source_file,source_line:e.source_line,raw:e.raw,components:e.components,decision:e.decision},null,2))}</pre></section>`;
 $('#event-dialog').showModal();
}
async function loadHistory(){
 const data=await api('/api/investigations?page='+state.historyPage);state.history=data.runs;
 $('#run-count').textContent=data.total;$('#history-page').textContent=`第 ${state.historyPage+1} / ${Math.max(1,Math.ceil(data.total/30))} 页 · ${num(data.total)} 次调查`;$('#history-prev').disabled=state.historyPage===0;$('#history-next').disabled=(state.historyPage+1)*30>=data.total;
 $('#history-list').innerHTML=state.history.map(r=>`<button class="history-row" data-run="${r.id}"><div><strong>${esc(r.node_label)}</strong><small>${esc(r.dataset_id)} · ${new Date(r.created_at).toLocaleString('zh-CN')} · ${r.id.slice(0,10)}</small></div><span>${num(r.retained_edges)} / ${num(r.candidate_edges)} 条<br><small>预算 ${num(r.budget_edges)} · 重开 →</small></span></button>`).join('')||'<div class="card empty-message">尚无调查记录。运行一次节点调查后，结果会独立保存在这里。</div>';
 $('#history-list').querySelectorAll('button').forEach(b=>b.onclick=()=>openRun(b.dataset.run).catch(report));
}
async function openRun(id){
 if(state.busy)return;
 clearError();const data=await api('/api/investigations/'+encodeURIComponent(id));
 switchPanel('workspace');renderRun(data);
 // Frozen evidence opens first. Live input preparation is optional.
 if(state.datasets.some(d=>d.id===data.dataset.id)){
  try{
   $('#dataset').value=data.dataset.id;await selectDataset(data.dataset.id,true);
   await selectNode(data.graph.nodes.find(n=>n.id===data.poi.node_id));
   state.anchor={id:data.poi.event_id};$('#budget').value=data.metrics.budget_edges;updateBudget();updateRunButton();
   renderRun(data);$('#run-status').textContent='已重开冻结结果。更改左侧输入后需重新运行。';
   return;
  }catch{/* Stored evidence remains available if the live source went offline. */}
 }
 state.offline=true;state.node=null;state.anchor=null;updateRunButton();
 $('#anchor-settings').hidden=true;$('#node-list').innerHTML='<p class="empty-message">原数据集已离线。冻结证据仍可查看和导出，重新运行需要恢复源数据。</p>';
 renderRun(data);$('#run-status').textContent='冻结结果已重开 · 原数据源当前离线。';
}

function debounce(fn,delay=240){let timer;return ()=>{clearTimeout(timer);timer=setTimeout(()=>fn().catch(report),delay);};}
$('#workspace-nav').onclick=()=>switchPanel('workspace');$('#history-nav').onclick=()=>switchPanel('history');$('#method-nav').onclick=()=>switchPanel('method');
$('#refresh-history').onclick=()=>loadHistory().catch(report);
$('#history-prev').onclick=()=>{state.historyPage--;loadHistory().catch(report);};$('#history-next').onclick=()=>{state.historyPage++;loadHistory().catch(report);};
$('#dataset').onchange=()=>selectDataset($('#dataset').value).catch(report);
$('#node-search').oninput=debounce(loadNodes);$('#node-type').onchange=()=>loadNodes().catch(report);
$('#anchor-search').oninput=debounce(async()=>{state.anchorPage=0;await loadAnchors();});
$('#anchor-prev').onclick=()=>{state.anchorPage--;loadAnchors().catch(report);};$('#anchor-next').onclick=()=>{state.anchorPage++;loadAnchors().catch(report);};
$('#budget').oninput=updateBudget;
for(const b of document.querySelectorAll('[data-ratio]'))b.onclick=()=>{$('#budget').value=Math.max(1,Math.floor(state.dataset.metrics.candidate_edges*Number(b.dataset.ratio)));updateBudget();};
$('#investigation-form').onsubmit=async e=>{
 e.preventDefault();if(!pending())return;clearError();setBusy(true);$('#run-status').textContent='统计历史频次、节点扩散、选择完整路径并核验…';
 try{
  const data=await api('/api/investigations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dataset_id:state.dataset.id,node_id:state.node.id,anchor_event_id:state.anchor.id,budget_edges:Number($('#budget').value)})});
  renderRun(data);$('#run-status').textContent='核验通过，独立调查已保存。';state.historyPage=0;await loadHistory();
 }catch(error){report(error);$('#run-status').textContent='本次调查未完成；已有冻结结果不受影响。';}
 finally{setBusy(false);}
};
$('#event-search').oninput=debounce(async()=>{state.eventPage=0;await loadEvents();});$('#event-filter').onchange=()=>{state.eventPage=0;loadEvents().catch(report);};
$('#events-prev').onclick=()=>{state.eventPage--;loadEvents().catch(report);};$('#events-next').onclick=()=>{state.eventPage++;loadEvents().catch(report);};
$('#close-dialog').onclick=()=>$('#event-dialog').close();$('#event-dialog').onclick=e=>{if(e.target===$('#event-dialog')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)e.target.close();}};
$('#login-form').onsubmit=async e=>{e.preventDefault();$('#login-error').textContent='';try{await api('/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:$('#access-token').value})});$('#access-token').value='';await boot();}catch(error){$('#login-error').textContent=error.message;}};
$('#logout').onclick=async()=>{try{await api('/api/session',{method:'DELETE'});location.reload();}catch(error){report(error);}};
async function boot(){
 try{
  const session=await api('/api/session');$('#deployment').textContent=session.deployment==='private'?'单组织私有部署':'回环地址 · 本地演示';
  $('#logout').hidden=!session.auth_required;
  $('#login-panel').hidden=session.authenticated;$('#app-content').hidden=!session.authenticated;
  if(!session.authenticated){$('#health-label').textContent='需要登录';$('#access-token').focus();return;}
  await loadHistory();let data;try{data=await api('/api/datasets');}catch{data={datasets:[]};}state.datasets=data.datasets;
  if(!data.datasets.length){$('#health-label').textContent='仅冻结证据可用';$('#node-list').innerHTML='<p class="empty-message">暂无在线数据集。可在调查记录中重开已有证据。</p>';switchPanel('history');return;}
  $('#dataset').innerHTML=data.datasets.map(d=>`<option value="${esc(d.id)}">${esc(d.name)} · ${esc(d.id)}</option>`).join('');
  $('#health-label').textContent='调查服务就绪';await selectDataset(data.datasets[0].id);await loadHistory();
 }catch(error){report(error);$('#health-label').textContent='服务未就绪';}
}
boot();
