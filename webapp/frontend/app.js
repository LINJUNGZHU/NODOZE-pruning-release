const $ = s => document.querySelector(s);
const state = {data:null,path:'path-2',scores:true,page:0,group:null,view:{scale:1,dx:0,dy:0}};
const fmt = n => new Intl.NumberFormat('zh-CN').format(n);
const pct = n => `${(n*100).toFixed(2)}%`;
const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const score = n => n == null ? '未记录' : Number(n)===0 ? '0' : Number(n)>=.001 ? Number(n).toFixed(4) : Number(n).toExponential(2);
const label = s => {
 const raw=String(s??''),text=raw.replace(/^(process|file|socket|memory|pipe):/,'');
 if(/^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$/i.test(text))return raw.startsWith('memory:')?'内存对象（名称未解析）':'未解析实体（见原始证据）';
 return text==='N/A'?'名称未记录':text;
};
const short = s => {const text=label(s);return text.length>22 ? '…'+text.slice(-21) : text;};
const time = e => new Date(e.timestamp_ns/1e6).toISOString().slice(11,23);
const operations={EVENT_OPEN:'打开文件',EVENT_WRITE:'写入文件',EVENT_MMAP:'映射内存',EVENT_EXECUTE:'执行程序',EVENT_CLONE:'创建子进程',EVENT_READ:'读取',EVENT_RECVFROM:'接收数据',EVENT_SENDTO:'发送数据',EVENT_CLOSE:'关闭',EVENT_CONNECT:'建立连接'};
const operation = e => operations[e.relation] || e.relation.replace('EVENT_','');
const titles={'path-1':'Firefox → gtcache','path-2':'载荷释放 → memtrace.so','path-3':'Micro APT 执行'};
const key = e => JSON.stringify([e.source,e.target,e.relation]);

function showDetails(e){
 if(!e)return;
 const fields=[['时间（UTC）',time(e)],['操作',`${operation(e)} · ${e.relation}`],['最终重要性评分',score(e.score)],['源实体',label(e.source_label)],['目标实体',label(e.target_label)],['剪枝结果',e.retained?'保留':'删除'],['局部稀有度',score(e.components.rarity)],['局部因果扩散',score(e.components.diffusion)],['行为分量',score(e.components.behavior)]];
 if(state.algorithm==='adaptive'&&e.adaptive)fields.push([e.adaptive.high_score_membership==null?'T-MASS 组内阈值':'高分群归属度（非攻击概率）',score(e.adaptive.high_score_membership??e.adaptive.threshold)],['严格时序可达 POI',e.adaptive.temporal_reachable?'是（不等于真实攻击）':'未找到严格递增连接'],['当前决策来源','T-MASS；原始 reasons 仅属于旧基线']);
 $('#details').classList.remove('empty-state');
 $('#details').innerHTML=`<div class="detail-grid">${fields.map(([k,v])=>`<div><label>${esc(k)}</label>${esc(v)}</div>`).join('')}</div><details><summary>辅助结构影响（DEPIMPACT）与原始证据</summary><p>当前实验包含权重 0.05 的结构影响辅助项，数值为 ${score(e.components.depimpact)}。0 表示该 POI 局部结果的结构影响为零，不是缺失。这里的分量来自贡献最大的 POI；最终分数还经过归一化与多 POI 聚合，不等于这些列直接相加。</p><p>事件名称补全仅影响展示，不改变历史实验的分数或保留决定。</p><pre>${esc(JSON.stringify(e,null,2))}</pre></details>`;
}

function selectScope(){
 $('#path-select').value=state.path;
 document.querySelectorAll('.path-tab').forEach(b=>b.classList.toggle('active',b.dataset.path===state.path));
 const paths=state.data.paths.filter(p=>state.path==='all'||p.id===state.path);
 state.pathIds=new Set(paths.flatMap(p=>p.event_ids));
 const core=paths.flatMap(p=>p.event_ids.map(id=>state.data.edges.find(e=>e.id===id)).filter(Boolean));
 const anchors=new Set(core.flatMap(e=>[e.source,e.target]));
 state.edges=state.data.edges.filter(e=>anchors.has(e.source)||anchors.has(e.target));
 const ids=new Set(state.edges.flatMap(e=>[e.source,e.target]));
 state.nodes=state.data.nodes.filter(n=>ids.has(n.id));
 makeLayout(core,anchors);
 $('#reference-paths').innerHTML=paths.map(p=>`<div class="reference"><strong>${esc(titles[p.id]||p.id)} · ${p.event_ids.length} 条参考事件${p.event_ids.length===1?' · 单事件参考':''}</strong><div class="event-chain">${p.event_ids.map((id,i)=>{const e=state.data.edges.find(e=>e.id===id);return e?`<article class="step" data-event="${esc(id)}"><div class="step-head"><span>STEP 0${i+1}</span><span>${time(e)} UTC</span></div><h3>${esc(operation(e))}</h3><div class="entity">${esc(label(e.source_label))}</div><div class="arrow">↓</div><div class="entity">${esc(label(e.target_label))}</div><div class="step-bottom"><span>S = ${score(e.score)}</span><span class="badge ${e.poi?'poi':''}">${e.poi?'POI · ':''}${e.retained?'已保留':'已删除'}</span></div></article>`:`<p>参考事件缺失</p>`}).join('')}</div></div>`).join('');
 const kept=state.edges.filter(e=>e.retained),afterNodes=new Set(kept.flatMap(e=>[e.source,e.target]));
 $('#local-stats').innerHTML=`<span>事件边 <b>${state.edges.length}</b> → <b>${kept.length}</b></span><span>节点 <b>${state.nodes.length}</b> → <b>${afterNodes.size}</b></span><span>局部删除 <b>${pct(1-kept.length/Math.max(1,state.edges.length))}</b></span>`;
 const c=state.algorithm==='repair'?state.data.adaptive_experiment.repair_context_counts:state.algorithm==='adaptive'?state.data.adaptive_experiment.full_context_counts:state.data.sample.full_context_counts;
 $('#scope-note').textContent=`当前为参考链的一跳上下文抽样；布局与聚合规则在剪枝前后保持一致。${state.clustered?'外围同类型实体已聚合，框内显示实际实体数量；逐边表保留所有展示事件。':''}`;
 $('#sample-note').textContent=c?`全部参考链的一跳上下文：${fmt(c.retained+c.removed)} 条事件，删除 ${fmt(c.removed)} 条。顶部压缩率是全图结果，非本图比例。`:'';
 state.page=0;state.group=null;renderTable();redraw();showDetails(core[0]);
}

function makeLayout(core,anchors){
 const lookup=new Map(state.nodes.map(n=>[n.id,n]));
 const ordered=[...anchors];
 const rest=state.nodes.filter(n=>!anchors.has(n.id)).sort((a,b)=>label(a.label).localeCompare(label(b.label))||a.id.localeCompare(b.id));
 state.clustered=rest.length>45;state.nodeMap=new Map();state.visual=new Map();
 for(const n of state.nodes){
  const id=state.clustered&&!anchors.has(n.id)?`context:${n.type}`:n.id;
  state.nodeMap.set(n.id,id);
  if(!state.visual.has(id))state.visual.set(id,{id,label:id.startsWith('context:')?({file:'文件上下文',process:'进程上下文',socket:'网络上下文',memory:'内存对象',unknown:'未解析上下文'}[n.type]||n.type):n.label,type:n.type,core:anchors.has(n.id),poi:n.poi,members:[]});
  state.visual.get(id).members.push(n.id);
 }
 const width=Math.max(680,ordered.length*142+80);
 state.width=width;state.height=480;state.pos=new Map();
 ordered.forEach((id,i)=>state.pos.set(id,{x:70+(width-140)*i/Math.max(1,ordered.length-1),y:235}));
 const contexts=[...state.visual.values()].filter(n=>!n.core);
 const columns=Math.max(4,Math.ceil(contexts.length/4));
 contexts.forEach((n,i)=>{const row=Math.floor(i/columns),col=i%columns;const ys=[58,132,350,422];state.pos.set(n.id,{x:70+(width-140)*(col+.5)/(columns),y:ys[row%4]})});
}

function graphGroups(edges){const map=new Map();for(const e of edges){const source=state.nodeMap.get(e.source),target=state.nodeMap.get(e.target),k=JSON.stringify([source,target,e.relation]);if(!map.has(k))map.set(k,{key:k,source,target,edges:[]});map.get(k).edges.push(e)}return [...map.values()];}
function hash(s){let h=0;for(const c of s)h=(Math.imul(h,31)+c.charCodeAt(0))|0;return h>>>0;}
function draw(svg,after){
 const edges=state.edges.filter(e=>!after||e.retained),ids=new Set(edges.flatMap(e=>[e.source,e.target]));
 const gs=graphGroups(edges),visualIds=new Set([...ids].map(id=>state.nodeMap.get(id)));
 $('#'+(after?'after-count':'before-count')).textContent=`${edges.length} 事件 · ${ids.size} 实体`;
 svg.setAttribute('viewBox',`0 0 ${state.width} ${state.height}`);
 const marker=after?'arrow-after':'arrow-before';
 const lines=gs.map(g=>{const a=state.pos.get(g.source),b=state.pos.get(g.target),core=g.edges.some(e=>state.pathIds.has(e.id)),removed=g.edges.every(e=>!e.retained),color=core?'#b85e45':removed?'#c0cac2':'#548b74';
  const offset=(hash(g.key)%5-2)*12;
  const sx=a.x+(b.x>=a.x?48:-48),tx=b.x+(b.x>=a.x?-48:48);
  let d,mx,my;
  if(g.source===g.target){d=`M ${a.x+30} ${a.y-15} C ${a.x+80} ${a.y-100},${a.x-80} ${a.y-100},${a.x-30} ${a.y-15}`;mx=a.x;my=a.y-72;}
  else{const cx=(sx+tx)/2;d=`M ${sx} ${a.y} C ${cx} ${a.y+offset},${cx} ${b.y+offset},${tx} ${b.y}`;mx=(sx+tx)/2;my=(a.y+b.y)/2+offset*.75;}
  const scores=g.edges.map(e=>e.score),min=Math.min(...scores),max=Math.max(...scores),txt=`${g.edges.length>1?'×'+g.edges.length+' · ':''}${min===max?score(max):score(min)+'–'+score(max)}`;
  return `<g class="dependency" data-group="${esc(g.key)}" style="cursor:pointer"><title>${esc(g.edges[0].relation)} · ${g.edges.length} 条事件 · ${esc(txt)}</title><path d="${d}" fill="none" stroke="transparent" stroke-width="14"/><path d="${d}" fill="none" stroke="${color}" stroke-width="${core?2.4:1.1}" ${removed?'stroke-dasharray="4 4"':''} marker-end="url(#${marker})"/>${state.scores?`<rect x="${mx-txt.length*2.6-4}" y="${my-10}" width="${txt.length*5.2+8}" height="15" rx="3" fill="#fcfdfa"/><text x="${mx}" y="${my}" text-anchor="middle" font-size="9" font-family="monospace" fill="${core?'#a0523d':'#79867e'}">${esc(txt)}</text>`:''}</g>`;
 }).join('');
 const nodes=[...state.visual.values()].filter(n=>visualIds.has(n.id)).map(n=>{const p=state.pos.get(n.id),count=n.members.filter(id=>ids.has(id)).length,name=n.members.length>1?`${n.label} · ${count}`:short(n.label),fill=n.poi?'#fff7e8':n.core?'#fbf0e9':'#ffffff',stroke=n.poi?'#c3a268':n.core?'#bf8e74':'#d5dfd7';return `<g data-node="${esc(n.id)}"><title>${esc(label(n.label))} · ${count} 实体</title><rect x="${p.x-51}" y="${p.y-19}" width="102" height="38" rx="5" fill="${fill}" stroke="${stroke}"/><text x="${p.x}" y="${p.y-3}" font-size="9" text-anchor="middle" fill="#38483f">${esc(name)}</text><text x="${p.x}" y="${p.y+10}" font-size="7" text-anchor="middle" fill="#8b978e">${n.poi?'POI · ':''}${esc(n.type.toUpperCase())}</text></g>`}).join('');
 svg.innerHTML=`<defs><marker id="${marker}" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="#9aaa9d"/></marker></defs><g transform="translate(${state.view.dx} ${state.view.dy}) scale(${state.view.scale})">${lines}${nodes}</g>`;
 svg._groups=gs;
}
function redraw(){if(state.data){draw($('#before'),false);draw($('#after'),true)}}
function filtered(){const q=$('#edge-search').value.toLowerCase();return state.edges.filter(e=>(!state.group||state.group.has(e.id))&&`${e.id} ${e.source_label} ${e.target_label} ${e.relation} ${operation(e)}`.toLowerCase().includes(q)).sort((a,b)=>Number(state.pathIds.has(b.id))-Number(state.pathIds.has(a.id))||b.score-a.score||a.id.localeCompare(b.id));}
function renderTable(){
 const es=filtered(),pages=Math.max(1,Math.ceil(es.length/20));state.page=Math.min(state.page,pages-1);
 $('#edge-rows').innerHTML=es.slice(state.page*20,(state.page+1)*20).map(e=>`<tr data-id="${esc(e.id)}" class="${state.pathIds.has(e.id)?'path-row':''}"><td><span class="num">${time(e)}</span><small>${esc(operation(e))}</small></td><td><div class="event-label">${esc(label(e.source_label))}<br><span style="color:#99a69c">↳</span> ${esc(label(e.target_label))}</div><small>${state.pathIds.has(e.id)?'参考链事件 · ':''}${e.poi?'POI · ':''}${esc(e.relation)}</small></td><td class="num">${score(e.score)}</td><td class="num">${score(e.components.rarity)}</td><td class="num">${score(e.components.diffusion)}</td><td><span class="badge ${e.retained?'':'removed'}">${e.retained?'保留':'删除'}</span></td></tr>`).join('');
 $('#edge-total').textContent=`${es.length} 条可查事件`;
 $('#page-info').textContent=`第 ${state.page+1} / ${pages} 页 · ${es.length} 条事件`;
 $('#prev-page').disabled=state.page===0;$('#next-page').disabled=state.page===pages-1;
}
$('#edge-rows').onclick=ev=>{const id=ev.target.closest('tr')?.dataset.id;if(id)showDetails(state.edges.find(e=>e.id===id))};
$('#reference-paths').onclick=ev=>{const id=ev.target.closest('[data-event]')?.dataset.event;if(id)showDetails(state.edges.find(e=>e.id===id))};
for(const id of ['before','after']){
 const svg=$('#'+id);let drag=null,moved=false;
 svg.onpointerdown=e=>{drag={x:e.clientX,y:e.clientY,...state.view};moved=false};
 svg.onpointermove=e=>{if(!drag)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;if(Math.abs(dx)+Math.abs(dy)>4)moved=true;if(moved){const scale=state.width/svg.getBoundingClientRect().width;state.view.dx=drag.dx+dx*scale;state.view.dy=drag.dy+dy*scale;redraw()}};
 window.addEventListener('pointerup',()=>{drag=null});
 svg.onclick=e=>{if(moved)return;const group=e.target.closest('[data-group]')?.dataset.group;if(group){const g=svg._groups.find(g=>g.key===group);state.group=new Set(g.edges.map(e=>e.id));state.page=0;renderTable();showDetails(g.edges[0]);$('#scores-section').scrollIntoView({behavior:'smooth',block:'start'})}};
 svg.addEventListener('wheel',e=>{e.preventDefault();state.view.scale=Math.max(.5,Math.min(5,state.view.scale*(e.deltaY<0?1.12:.89)));redraw()},{passive:false});
}
function changePath(path){state.path=path;state.view={scale:1,dx:0,dy:0};selectScope()}
function renderMetrics(m){
 $('#metrics').innerHTML=[[fmt(m.candidate_edges),'候选事件 · 全图'],[fmt(m.retained_edges),'保留事件 · 全图'],[pct(m.compression_ratio),'事件压缩率 · 全图'],[pct(m.attack_event_recall),'派生攻击事件召回'],[`${m.retained_paths} / ${m.reference_paths}`,'参考链事件完整保留']].map(([v,k])=>`<div class="metric"><span>${k}</span><strong>${v}</strong></div>`).join('');
}
function changeAlgorithm(value){
 state.algorithm=value;
 for(const e of state.data.edges)e.retained=value==='repair'?e.adaptive.repair_retained:value==='adaptive'?e.adaptive.retained:state.baseline.get(e.id);
 const report=state.data.adaptive_experiment;
 const m=value==='repair'?report.results.find(r=>r.method==='baseline_witness_repair'):value==='adaptive'?report.results.find(r=>r.method===report.primary_method):state.data.metrics;
 renderMetrics(m);selectScope();
 $('#paths').textContent=value!=='baseline'?'当前为研究版决策；评分沿用 PS-RDP。详情 adaptive 字段提供分群证据、时序可达性和下一条连接事件；原始 reasons 字段仅解释历史 PS-RDP 决策。':'当前为 PS-RDP 历史决策；实体名称按原始 CDM 声明补全。';
}
$('#algorithm-select').onchange=e=>changeAlgorithm(e.target.value);
$('#path-tabs').onclick=e=>{const p=e.target.closest('[data-path]')?.dataset.path;if(p)changePath(p)};
$('#path-select').onchange=e=>changePath(e.target.value);
$('#show-scores').onchange=e=>{state.scores=e.target.checked;redraw()};
$('#fit').onclick=()=>{state.view={scale:1,dx:0,dy:0};redraw()};
$('#edge-search').oninput=()=>{state.page=0;renderTable()};
$('#clear-edge').onclick=()=>{state.group=null;state.page=0;$('#edge-search').value='';renderTable()};
$('#prev-page').onclick=()=>{state.page--;renderTable()};$('#next-page').onclick=()=>{state.page++;renderTable()};
$('#export-edges').onclick=()=>{const fields=['id','timestamp_ns','relation','source_label','target_label','score','retained'];const quote=v=>'"'+String(v).replace(/"/g,'""')+'"';const rows=filtered().map(e=>fields.map(f=>quote(typeof e[f]==='string'&&/^[=+@-]/.test(e[f])?"'"+e[f]:e[f])).join(','));const url=URL.createObjectURL(new Blob(['\ufeff'+[fields.join(','),...rows].join('\n')],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='path-context-events.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
$('#upload-form').onsubmit=async e=>{e.preventDefault();const output=$('#upload-status');try{const body=new FormData();[...$('#files').files].forEach(f=>body.append('files',f));output.textContent='正在上传…';const r=await fetch('/api/imports',{method:'POST',body}),job=await r.json();if(!r.ok)throw new Error(job.error);while(true){const response=await fetch(`/api/imports/${job.id}`),j=await response.json();output.textContent=JSON.stringify(j,null,2);if(['complete','failed'].includes(j.status))break;await new Promise(r=>setTimeout(r,2000))}}catch(err){output.textContent=err.message}};
(async()=>{
 const r=await fetch('/api/datasets/theia-case3/graph');if(!r.ok)throw new Error(await r.text());state.data=await r.json();const m=state.data.metrics;
 state.baseline=new Map(state.data.edges.map(e=>[e.id,e.retained]));state.algorithm='baseline';renderMetrics(m);
 const report=state.data.adaptive_experiment;
 if(report){
  $('#algorithm-select option[value="adaptive"]').disabled=false;
  $('#algorithm-select option[value="adaptive"]').textContent=`T-MASS · ${report.primary_method}`;
  if(report.results.some(r=>r.method==='baseline_witness_repair')&&state.data.edges.every(e=>typeof e.adaptive?.repair_retained==='boolean'))$('#algorithm-select').insertAdjacentHTML('beforeend','<option value="repair">PS-RDP ＋ 最少跳时序修复</option>');
  const resultTable=rows=>`<div class="table-scroll"><table><thead><tr><th>方法 / 消融</th><th>保留边</th><th>压缩率</th><th>攻击事件召回</th><th>参考链</th><th>时序补边</th><th>丢失 POI 连接</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.method)}</td><td>${fmt(r.retained_edges)}</td><td>${pct(r.compression_ratio)}</td><td>${pct(r.attack_event_recall)}</td><td>${r.retained_paths}/${r.reference_paths}</td><td>${fmt(r.witness_added_edges)}</td><td>${r.lost_retained_poi_connections==null?'—':fmt(r.lost_retained_poi_connections)}</td></tr>`).join('')}</tbody></table></div>`;
  const mainNames=new Set(['baseline_ps_rdp_20pct','score_top20pct','baseline_witness_repair',report.primary_method]);
  $('#algorithm-results').innerHTML=resultTable(report.results.filter(r=>mainNames.has(r.method)))+`<details><summary>展开全部 ${report.results.length} 组阈值与消融结果</summary>${resultTable(report.results)}</details><p>全量候选边、相同 POI、相同评分。丢失 POI 连接指保留事件在原图可按严格时序到达 POI、但在剪枝图不可达的数量，不等于真实攻击链数量。新方法没有固定边预算，不同比例不能当作同预算胜负。参数预设，真值仅事后评估；耗时仅含评分账本重放。</p>`;
 }
 $('#health').textContent='● 数据已就绪';
 $('#path-tabs').innerHTML=state.data.paths.map((p,i)=>`<button class="path-tab" data-path="${esc(p.id)}">0${i+1}　${esc(titles[p.id]||p.id)}<small>${p.event_ids.length} 条参考事件 · 点击查看</small></button>`).join('')+'<button class="path-tab" data-path="all">全部关键路径<small>聚合上下文概览</small></button>';
 state.data.paths.forEach(p=>$('#path-select').insertAdjacentHTML('beforeend',`<option value="${esc(p.id)}">${esc(p.id)}</option>`));
 $('#paths').textContent='当前展示使用已有实验分数；实体名称根据原始 CDM 声明补全，原始 UUID 和名称来源保存在展开证据中。';
 selectScope();
})().catch(e=>{$('#health').textContent='数据加载失败';$('#details').textContent=e.message});
