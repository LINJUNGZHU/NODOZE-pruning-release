'use strict';
const $=s=>document.querySelector(s);
const state={data:null,cases:[],page:0,limit:20,loadVersion:0,tableVersion:0,busy:false,zoom:1,pan:[0,0],positions:[],selectedNode:null};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>Number(n).toLocaleString('zh-CN');
const score=n=>n==null?'—':Number(n)===0?'0':Number(n).toPrecision(6);
const localTime=s=>String(s??'').split('T')[1]?.replace(/[-+]\d\d:\d\d$/,'')||String(s??'');
const short=(s,n=48)=>s.length>n?'…'+s.slice(1-n):s;
const base=()=>`/api/datasets/${encodeURIComponent(state.data.dataset.id)}`;
async function api(url,options){const r=await fetch(url,options);const d=await r.json();if(!r.ok)throw Error(d.error||`请求失败 (${r.status})`);return d;}
function fail(e){$('#error').hidden=false;$('#error').textContent=e.message;}
function renderCases(){
 $('#case-list').innerHTML=state.cases.map(c=>`<button class="case-card ${state.data?.dataset.id===c.id?'active':''}" data-case="${esc(c.id)}" aria-pressed="${state.data?.dataset.id===c.id}" ${state.busy?'disabled':''}><span class="case-title">${esc(c.name)}</span><span class="case-count">${fmt(c.metrics.candidate_edges)}<small>条原始边</small></span><span class="case-desc">${esc(c.description)}</span></button>`).join('');
 $('#case-list').querySelectorAll('button').forEach(b=>b.onclick=()=>loadCase(b.dataset.case));
}
function setBusy(value){state.busy=value;$('#apply-poi').disabled=value;$('#apply-poi').textContent=value?'分析中，请稍候…':'重新分析 ↗';renderCases();}
async function loadCase(id){
 if(state.busy)return;const version=++state.loadVersion;setBusy(true);$('#error').hidden=true;$('#health').textContent='正在读取全量图';
 try{const d=await api(`/api/datasets/${encodeURIComponent(id)}/view`);if(version!==state.loadVersion)return;render(d);$('#prune-status').textContent='';}
 catch(e){fail(e);}finally{if(version===state.loadVersion)setBusy(false);}
}
function render(d){
 state.data=d;state.page=0;state.tableVersion++;state.zoom=1;state.pan=[0,0];state.selectedNode=null;$('#graph-tooltip').hidden=true;
 state.nodes=new Map(d.graph.nodes.map((n,i)=>[n[0],{id:n[0],label:n[1],type:n[2],index:i}]));
 if(d.graph.sampled||d.graph.edges.length!==d.metrics.candidate_edges)throw Error('图数据不完整，请重新生成案例。');
 $('#health').textContent='全量数据就绪';$('#edge-search').value='';$('#edge-decision').value='all';
 const m=d.metrics;$('#metrics').innerHTML=[['原始事件',fmt(m.candidate_edges),`${fmt(m.candidate_nodes)} 个节点`],['保留事件',fmt(m.retained_edges),`${fmt(m.retained_nodes)} 个节点`],['减少阅读量',`${(100*(1-m.retained_edges/m.candidate_edges)).toFixed(1)}%`,`${fmt(m.candidate_edges-m.retained_edges)} 条边已剪去`],['推断攻击进程',fmt(d.attack?.summary.inferred_attack_nodes||0),'独立识别，点击下方核验']].map(([label,v,n],i)=>`<div class="metric ${i===2?'emphasis':''}"><span>${esc(label)}</span><strong>${esc(v)}</strong><span>${esc(n)}</span></div>`).join('');
 $('#before-count').textContent=`${fmt(m.candidate_edges)} 边 · ${fmt(m.candidate_nodes)} 节点`;
 $('#after-count').textContent=`${fmt(m.retained_edges)} 边 · ${fmt(m.retained_nodes)} 节点`;
 $('#scope-note').textContent=`全量绘制 ${fmt(d.graph.edges.length)} 条原始事件，无抽样。拖动平移、滚轮缩放，点击节点查日志；相同端点的多条事件可能重合。图用于观察整体结构，方向与时间请在下方活动路径和事件日志中核验。`;
 $('#poi-select').innerHTML=(d.poi_presets||[]).map(p=>`<option value="${esc(p.event_id)}">${esc(p.label)} · ${esc(localTime(p.timestamp))}</option>`).join('')+'<option value="custom">自定义事件 ID</option>';
 $('#poi-select').value=d.poi_presets.some(p=>p.event_id===d.poi.event_id)?d.poi.event_id:'custom';$('#poi-id').value=d.poi.event_id;
 $('#poi-evidence').textContent=`当前起点：${d.poi.label}。${d.poi.groundtruth_backed?'此预设依据 Ground Truth 选择。':'此起点不代表已确认攻击。'}`;
 $('#edge-budget').value=String(d.algorithm.budget_ratio);$('#selection-mode').value=d.algorithm.selection_mode||'context';$('#detector').value=d.attack?.detector||'rules';$('#attack-quantile').value=String(d.attack?.config.anomaly_quantile||.9);updateDetectorControl();
 $('#history-note').textContent=`频率来自起点 ${localTime(d.poi.timestamp)} 之前的全部 ${fmt(d.history.history_edges)} 条同主机历史事件；不含起点同刻及之后的事件。时间均为数据集本地 UTC−04:00。`;
 $('#run-log').textContent=d.logs.map((line,i)=>`${String(i+1).padStart(2,'0')}  ${line}`).join('\n');
 $('#download-audit').href=base()+'/decision-audit';
 const c=d.decision_certificate;$('#decision-summary').textContent=c?`预算校验：${c.budget_valid?'通过':'未通过'}；完整时序见证：${c.complete_witnesses?'通过':'未通过'}；剩余 ${fmt(c.unused_budget)} 条预算。保留比例是上限，不强制填满。`:'';
 $('#source-note').textContent=JSON.stringify({数据范围:d.dataset,真值参考:d.truth.source,边评分与选择:d.decision_contract},null,2);
 renderCases();layoutGraph();scheduleDraw();renderAttack();if(!$('#panel-events').hidden)renderTable();
}
// Process hubs share one deterministic layout; resource placement uses actual neighbors.
function layoutGraph(){
 const nodes=state.data.graph.nodes,edges=state.data.graph.edges,hub=[];
 nodes.forEach((n,i)=>{if(n[2]==='process')hub.push(i);});hub.sort((a,b)=>nodes[a][0].localeCompare(nodes[b][0]));
 const pos=nodes.map(()=>null),cols=Math.ceil(Math.sqrt(hub.length*1.55)),rows=Math.ceil(hub.length/cols),cw=940/Math.max(cols,1),ch=620/Math.max(rows,1);
 hub.forEach((idx,j)=>{pos[idx]=[30+cw*(j%cols+.5),30+ch*(Math.floor(j/cols)+.5)];});
 const owners=new Map();for(const e of edges){const a=nodes[e[1]][2]==='process',b=nodes[e[2]][2]==='process';if(a&&!b&&!owners.has(e[2]))owners.set(e[2],e[1]);if(b&&!a&&!owners.has(e[1]))owners.set(e[1],e[2]);}
 nodes.forEach((n,i)=>{if(pos[i])return;const owner=owners.get(i),center=pos[owner]||[500,340];let h=2166136261;for(const c of n[0])h=Math.imul(h^c.charCodeAt(0),16777619);h>>>=0;const a=(h%65536)*Math.PI*2/65536,r=Math.sqrt((h>>>16)/65535)*Math.min(cw,ch)*.43;pos[i]=[center[0]+Math.cos(a)*r,center[1]+Math.sin(a)*r];});
 state.positions=pos;state.keptNodes=new Set(edges.filter(e=>e[3]).flatMap(e=>[e[1],e[2]]));state.predicted=new Set((state.data.attack?.nodes||[]).filter(n=>n.predicted_attack).map(n=>n.id));
}
let frame;
function scheduleDraw(){cancelAnimationFrame(frame);frame=requestAnimationFrame(()=>{if(state.data){drawGraph(false);drawGraph(true);}});}
function transform(canvas){const rect=canvas.getBoundingClientRect(),unit=Math.min(rect.width/1000,rect.height/680);return {rect,unit,scale:unit*state.zoom,ox:rect.width/2+state.pan[0]*unit,oy:rect.height/2+state.pan[1]*unit};}
function drawGraph(after){
 const canvas=$(after?'#after':'#before'),t=transform(canvas),ratio=Math.min(devicePixelRatio||1,2),ctx=canvas.getContext('2d');
 if(canvas.width!==Math.round(t.rect.width*ratio)||canvas.height!==Math.round(t.rect.height*ratio)){canvas.width=Math.round(t.rect.width*ratio);canvas.height=Math.round(t.rect.height*ratio);}
 ctx.setTransform(ratio,0,0,ratio,0,0);ctx.clearRect(0,0,t.rect.width,t.rect.height);ctx.translate(t.ox,t.oy);ctx.scale(t.scale,t.scale);ctx.translate(-500,-340);
 const es=state.data.graph.edges,pos=state.positions,nodes=state.data.graph.nodes;ctx.strokeStyle=after?'#328e8038':'#617f7c38';ctx.lineWidth=.42/t.scale;let count=0;
 for(const e of es){if(after&&!e[3])continue;const a=pos[e[1]],b=pos[e[2]];ctx.beginPath();ctx.moveTo(a[0],a[1]);if(e[1]===e[2])ctx.arc(a[0]+2,a[1],2,Math.PI,3*Math.PI);else ctx.lineTo(b[0],b[1]);count++;ctx.stroke();}
 const drawNodes=(process)=>{ctx.fillStyle=process?(after?'#28695f':'#576f72'):(after?'#73b2a6':'#a6b7b5');ctx.beginPath();nodes.forEach((n,i)=>{if((n[2]==='process')!==process||(after&&!state.keptNodes.has(i)))return;const p=pos[i],r=(process?1.6:.55)/Math.sqrt(t.scale);ctx.moveTo(p[0]+r,p[1]);ctx.arc(p[0],p[1],r,0,Math.PI*2);});ctx.fill();};drawNodes(false);drawNodes(true);
 ctx.fillStyle='#c05b40';nodes.forEach((n,i)=>{if(!state.predicted.has(n[0])||(after&&!state.keptNodes.has(i)))return;const p=pos[i];ctx.beginPath();ctx.arc(p[0],p[1],3/Math.sqrt(t.scale),0,Math.PI*2);ctx.fill();});
 canvas.dataset.renderedEdges=String(count);canvas.dataset.sampled='false';
}
function initCanvas(){
 for(const canvas of [$('#before'),$('#after')]){
  let drag=null;canvas.addEventListener('pointerdown',e=>{if(!state.data)return;drag={x:e.clientX,y:e.clientY,px:state.pan[0],py:state.pan[1],moved:false};canvas.setPointerCapture(e.pointerId);});
  canvas.addEventListener('pointermove',e=>{if(!drag)return;const t=transform(canvas),dx=e.clientX-drag.x,dy=e.clientY-drag.y;drag.moved=drag.moved||Math.hypot(dx,dy)>4;state.pan=[drag.px+dx/t.unit,drag.py+dy/t.unit];scheduleDraw();});
  canvas.addEventListener('pointerup',e=>{if(!drag)return;const clicked=!drag.moved;drag=null;if(!clicked)return;const t=transform(canvas),x=(e.clientX-t.rect.left-t.ox)/t.scale+500,y=(e.clientY-t.rect.top-t.oy)/t.scale+340;let best=null,dist=12/t.scale;state.positions.forEach((p,i)=>{if(canvas.id==='after'&&!state.keptNodes.has(i))return;const d=Math.hypot(p[0]-x,p[1]-y);if(d<dist){dist=d;best=i;}});if(best!=null){const n=state.data.graph.nodes[best];selectTab('events');$('#edge-search').value=n[0];state.page=0;renderTable();$('#graph-tooltip').hidden=false;$('#graph-tooltip').textContent=`已筛选：${n[1]} · ${n[0]}`;}});
  canvas.addEventListener('pointercancel',()=>drag=null);
  canvas.addEventListener('wheel',e=>{if(!state.data)return;e.preventDefault();state.zoom=Math.max(.5,Math.min(30,state.zoom*Math.exp(-e.deltaY*.0015)));scheduleDraw();},{passive:false});
 }
 document.querySelectorAll('[data-zoom]').forEach(b=>b.onclick=()=>{if(b.dataset.zoom==='fit'){state.zoom=1;state.pan=[0,0];}else state.zoom=Math.max(.5,Math.min(30,state.zoom*(b.dataset.zoom==='in'?1.4:1/1.4)));scheduleDraw();});new ResizeObserver(scheduleDraw).observe($('.comparison'));
}
async function renderTable(){
 if(!state.data)return;const version=++state.tableVersion,id=state.data.dataset.id;
 const params=new URLSearchParams({page:state.page,limit:state.limit,q:$('#edge-search').value,filter:$('#edge-decision').value});
 try{const result=await api(`${base()}/edges?${params}`);if(version!==state.tableVersion||id!==state.data.dataset.id)return;const rows=result.edges,max=Math.max(...rows.map(e=>e.score),1e-30);state.table=result;
 $('#edge-total').textContent=`${fmt(result.total)} 条匹配事件`;
 $('#edge-rows').innerHTML=rows.map(e=>`<tr><td><button class="row-link" data-event="${esc(e.id)}">${esc(localTime(e.timestamp))}<span class="secondary">${esc(e.relation)}</span></button></td><td><button class="row-link" data-event="${esc(e.id)}">${esc(short(e.source_label))}<span class="secondary">→ ${esc(short(e.target_label))}</span></button></td><td title="${esc(e.score)}"><span class="score-number">${score(e.score)}</span><div class="score-meter"><i style="width:${100*e.score/max}%"></i></div></td><td>${fmt(e.historical_count)}</td><td><span class="pill ${e.retained?'keep':'remove'}">${e.retained?'保留':'删除'}</span></td></tr>`).join('')||'<tr><td colspan="5" class="empty">没有匹配事件。可重置筛选后重试。</td></tr>';
 bindEventButtons($('#edge-rows'));const pages=Math.max(1,Math.ceil(result.total/state.limit));$('#page-info').textContent=`第 ${state.page+1} / ${fmt(pages)} 页 · 每页 ${state.limit} 条`;
 $('#prev-page').disabled=state.page===0;$('#next-page').disabled=state.page+1>=pages;
 const pts=rows.map((e,i)=>({e,x:55+i*915/Math.max(1,rows.length-1),y:85-60*e.score/max}));
 $('#score-chart').innerHTML=`<path d="M45 18V90H980" stroke="#d4e0d8" fill="none"/><text x="50" y="14" font-size="9" fill="#75877e">本页最高分 ${esc(score(max))} · 线性坐标，真实同分不作扰动</text><text x="50" y="110" font-size="9" fill="#75877e">当前页逐边评分 · 按分数降序 · 点击点查看日志</text><polyline points="${pts.map(p=>`${p.x},${p.y}`).join(' ')}" fill="none" stroke="#87b7a6" stroke-width="1.5"/>`+pts.map(p=>`<circle data-event="${esc(p.e.id)}" tabindex="0" role="button" aria-label="事件 ${esc(p.e.id)}，评分 ${esc(score(p.e.score))}" cx="${p.x}" cy="${p.y}" r="4" fill="${p.e.retained?'#188774':'#9bacaa'}"><title>${esc(p.e.id)} · ${score(p.e.score)}</title></circle>`).join('');bindEventButtons($('#score-chart'));
 }catch(e){if(version===state.tableVersion)fail(e);}
}
function bindEventButtons(container){container.querySelectorAll('[data-event]').forEach(b=>{b.onclick=()=>showEvent(b.dataset.event);if(b.tagName.toLowerCase()==='circle')b.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();b.onclick();}};});}
function showDialog(title,html){$('#detail-title').textContent=title;$('#detail-content').innerHTML=html;if(!$('#detail-dialog').open)$('#detail-dialog').showModal();}
async function showEvent(id){
 const dataset=state.data.dataset.id;try{const e=await api(`${base()}/events/${encodeURIComponent(id)}`);if(dataset!==state.data.dataset.id)return;
 showDialog('原始事件与评分依据',`<p class="hint">${esc(e.id)}</p><div class="detail-facts"><div><small>边评分</small>${score(e.score)} · ${e.retained?'保留':'删除'}</div><div><small>POI 前历史频次</small>${fmt(e.historical_count)}</div></div><p>${esc(e.reason)}</p><p class="hint">评分表示调查相关性，不是恶意概率。完整路径、边预算和处理顺序共同决定保留结果。</p><button id="use-event-poi">将此事件设为调查起点</button><pre>${esc(JSON.stringify({事件时间:e.timestamp,源:e.source_label,目标:e.target_label,评分:e.score,评分分量:e.components,判定记录:e.decision,攻击推断角色:e.attack_role,历史频率:e.historical_frequency,频率截止:state.data.poi.timestamp,来源文件:e.source_file,来源行:e.source_line,原始日志:e.raw},null,2))}</pre>`);
 $('#use-event-poi').onclick=()=>{$('#poi-id').value=id;$('#poi-id').dispatchEvent(new Event('input'));$('#detail-dialog').close();$('.controls').scrollIntoView({behavior:'smooth'});};
 }catch(e){fail(e);}
}
function selectTab(name){document.querySelectorAll('[data-tab]').forEach(b=>{const selected=b.dataset.tab===name;b.classList.toggle('active',selected);b.setAttribute('aria-selected',String(selected));$('#panel-'+b.dataset.tab).hidden=!selected;});if(name==='events')renderTable();}
function updateDetectorControl(){$('#quantile-control').hidden=$('#detector').value==='neural';}
$('#detector').onchange=updateDetectorControl;
$('#close-detail').onclick=()=>$('#detail-dialog').close();$('#detail-dialog').onclick=e=>{if(e.target===$('#detail-dialog')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)e.target.close();}};
document.querySelectorAll('[data-tab]').forEach(b=>{b.onclick=()=>selectTab(b.dataset.tab);b.onkeydown=e=>{if(!['ArrowLeft','ArrowRight'].includes(e.key))return;e.preventDefault();const tabs=[...document.querySelectorAll('[data-tab]')],next=tabs[(tabs.indexOf(b)+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length];next.focus();selectTab(next.dataset.tab);};});
let searchTimer;$('#edge-search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.page=0;renderTable();},220);};$('#edge-decision').onchange=()=>{state.page=0;renderTable();};$('#clear-edge').onclick=()=>{$('#edge-search').value='';$('#edge-decision').value='all';state.page=0;renderTable();};$('#prev-page').onclick=()=>{state.page--;renderTable();};$('#next-page').onclick=()=>{state.page++;renderTable();};
$('#poi-select').onchange=()=>{const p=state.data?.poi_presets.find(p=>p.event_id===$('#poi-select').value);$('#poi-id').value=p?p.event_id:'';$('#poi-evidence').textContent=p?`待应用：${p.label}。点击“重新分析”生效。`:'在自定义设置中输入候选图内的事件 ID。';if(!p){$('.advanced').open=true;$('#poi-id').focus();}};
$('#poi-id').oninput=()=>{const p=state.data?.poi_presets.find(p=>p.event_id===$('#poi-id').value.trim());$('#poi-select').value=p?p.event_id:'custom';$('#poi-evidence').textContent='新的起点尚未生效。点击“重新分析”后更新结果。';};
$('#poi-form').onsubmit=async e=>{e.preventDefault();if(!state.data||state.busy)return;setBusy(true);$('#error').hidden=true;$('#prune-status').textContent='正在重新统计 POI 前频次、剪枝并识别进程…';try{const d=await api(base()+'/prune',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({poi_event_id:$('#poi-id').value.trim(),budget_ratio:Number($('#edge-budget').value),selection_mode:$('#selection-mode').value,attack_quantile:Number($('#attack-quantile').value),detector:$('#detector').value,compact:true})});render(d);$('#prune-status').textContent='分析完成，结果已保存。';}catch(e){fail(e);$('#prune-status').textContent='本次未完成，仍显示上一次成功的结果。';}finally{setBusy(false);}};
async function boot(){try{const d=await api('/api/datasets');state.cases=d.datasets;$('#detector option[value="neural"]').disabled=!d.neural_available;renderCases();if(!d.datasets.length)throw Error('没有已准备的案例。');await loadCase(d.datasets[0].id);}catch(e){fail(e);}}
initCanvas();boot();
