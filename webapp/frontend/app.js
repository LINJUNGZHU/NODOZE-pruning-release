const $=s=>document.querySelector(s), state={data:null,page:0,selected:null};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>Number(n).toLocaleString('zh-CN');
const score=n=>n===0?'0':n<.001?n.toExponential(2):n.toFixed(4);
const short=s=>s.length>25?'…'+s.slice(-24):s;
const localTime=s=>{const m=s.match(/T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?/);return m?`${m[1]}.${(m[2]||'').padEnd(3,'0')}`:s;};
function details(e){state.selected=e.id;$('#use-event-poi').disabled=false;$('#event-detail').open=true;$('#details').textContent=JSON.stringify({事件:e.id,评分:e.score,分量:e.components,剪枝结果:e.retained?'保留':'删除',原因:e.reason,参考证据:e.reference_evidence,POI前计数:e.historical_count,POI前频率:e.historical_frequency,频率统计截止:state.data.poi?.timestamp,来源文件:e.source_file,来源行:e.source_line,原始日志:e.raw},null,2);renderTable();}
function drawGraph(after){
 const svg=$(after?'#after':'#before'), es=state.display.filter(e=>!after||e.retained), visible=new Set(es.flatMap(e=>[e.source,e.target]));
 $(after?'#after-count':'#before-count').textContent=`${es.length} 边 · ${visible.size} 节点`;
 const positions=state.positions, marker=after?'after-arrow':'before-arrow';
 svg.innerHTML=`<defs><marker id="${marker}" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0 0L5 2.5L0 5" fill="#8b9f92"/></marker></defs>`+es.map(e=>{
  const a=positions.get(e.source),b=positions.get(e.target),idx=state.display.indexOf(e),bend=(idx%7-3)*12;
  const x=(a.x+b.x)/2+bend,y=(a.y+b.y)/2-bend;
  const d=e.source===e.target?`M${a.x} ${a.y} c-45 -60 45 -60 0 0`:`M${a.x} ${a.y} Q${x} ${y} ${b.x} ${b.y}`;
  const color=e.reference_evidence.length?'#c17a36':e.retained?'#258368':'#c4cfc7';
  return `<g class="graph-edge" data-id="${esc(e.id)}"><title>${esc(e.relation)} · ${score(e.score)} · ${e.retained?'保留':'删除'}</title><path d="${d}" fill="none" stroke="transparent" stroke-width="12"/><path d="${d}" fill="none" stroke="${color}" stroke-width="${e.retained?1.8:1}" ${e.retained?'':'stroke-dasharray="4 4"'} marker-end="url(#${marker})"/>${$('#show-scores').checked?`<text x="${x}" y="${y}" fill="#496457" font-size="8" paint-order="stroke" stroke="#fff" stroke-width="3">${score(e.score)}</text>`:''}</g>`;
 }).join('')+[...visible].map(id=>{const p=positions.get(id),n=state.nodes.get(id);return `<g><title>${esc(n.label)} · ${esc(id)}</title><circle cx="${p.x}" cy="${p.y}" r="${n.type==='process'?6:3}" fill="${n.type==='process'?'#315d4a':'#b1c2b6'}"/>${n.type==='process'?`<text x="${p.x+8}" y="${p.y-7}" font-size="8" fill="#476352">${esc(short(n.label.split('\\').pop()))}</text>`:''}</g>`}).join('');
 svg.querySelectorAll('[data-id]').forEach(g=>g.addEventListener('click',()=>details(state.byId.get(g.dataset.id))));
}
function filtered(){const q=$('#edge-search').value.trim().toLowerCase(),d=$('#edge-decision').value;return state.sorted.filter(e=>(d==='all'||d==='reference'&&e.reference_evidence.length||d==='retained'&&e.retained||d==='removed'&&!e.retained)&&(!q||e.search.includes(q)));}
function renderTable(){
 const es=filtered(),pages=Math.max(1,Math.ceil(es.length/30));state.page=Math.min(state.page,pages-1);const rows=es.slice(state.page*30,state.page*30+30);
 $('#edge-total').textContent=`${fmt(es.length)} 条可查事件`;
 $('#edge-rows').innerHTML=rows.map(e=>`<tr tabindex="0" data-id="${esc(e.id)}" class="${e.id===state.selected?'selected':''}"><td>${esc(localTime(e.timestamp))}<small>${esc(e.relation)}</small></td><td>${esc(e.source_label)}<small>→ ${esc(e.target_label)}</small></td><td>${score(e.score)}<div class="bar"><i class="${e.retained?'':'removed'}" style="width:${Math.max(0,Math.min(100,e.score*100))}%"></i></div></td><td>${fmt(e.historical_count)}<small>${(e.historical_frequency*100).toFixed(5)}%</small></td><td><span class="badge ${e.retained?'':'removed'}">${e.retained?'保留':'删除'}</span>${e.reference_evidence.length?'<small class="truth">PDF 参考</small>':''}</td></tr>`).join('')||'<tr><td colspan="5">没有匹配事件</td></tr>';
 $('#page-info').textContent=`第 ${state.page+1} / ${pages} 页 · 时间 UTC−04:00`;
 $('#prev-page').disabled=state.page===0;$('#next-page').disabled=state.page>=pages-1;
 $('#edge-rows').querySelectorAll('tr[data-id]').forEach(tr=>{tr.onclick=()=>details(state.byId.get(tr.dataset.id));tr.onkeydown=e=>{if(e.key==='Enter')tr.click();};});
 const pts=rows.map((e,i)=>({x:45+i*925/Math.max(1,rows.length-1),y:120-e.score*100,e}));
 $('#score-chart').innerHTML=`<path d="M40 20V120H980" stroke="#d0dbd3" fill="none"/><text x="12" y="25" font-size="10" fill="#728779">1</text><text x="12" y="122" font-size="10" fill="#728779">0</text><text x="45" y="143" font-size="10" fill="#728779">当前页 · 按评分降序 · 点击评分点查看事件</text><polyline points="${pts.map(p=>`${p.x},${p.y}`).join(' ')}" fill="none" stroke="#aac1b2" stroke-width="1.5"/>`+pts.map(p=>`<circle class="chart-dot" data-id="${esc(p.e.id)}" cx="${p.x}" cy="${p.y}" r="3.5" fill="${p.e.retained?'#258368':'#aab6ad'}"><title>${esc(p.e.id)} · ${score(p.e.score)}</title></circle>`).join('');
 $('#score-chart').querySelectorAll('[data-id]').forEach(c=>c.onclick=()=>details(state.byId.get(c.dataset.id)));
}
async function load(){try{
 const response=await fetch('/api/datasets');if(!response.ok)throw new Error((await response.json()).error||'数据加载失败');const list=await response.json();if(!list.datasets.length)throw new Error('没有已准备的数据集');
 const graph=await fetch(`/api/datasets/${encodeURIComponent(list.datasets[0].id)}/graph`);if(!graph.ok)throw new Error('图数据读取失败');const d=await graph.json();if(d.schema_version!==2)throw new Error('请运行 prepare_optc.py 更新 OPTC 的 POI 历史索引');renderData(d);
}catch(e){$('#health').textContent='加载失败';$('#error').hidden=false;$('#error').textContent=e.message;$('#run-log').textContent='未载入运行结果。';}}

function renderData(d){
 state.data=d;state.page=0;state.selected=null;$('#use-event-poi').disabled=true;$('#details').textContent='点击图中的边、评分点或表格行查看。';
 $('#dataset').textContent=`${d.dataset.name} · ${d.dataset.description}`;$('#health').textContent='数据就绪';
 const m=d.metrics;$('#metrics').innerHTML=[['剪枝前',fmt(m.candidate_edges),`${fmt(m.candidate_nodes)} 个节点`],['剪枝后',fmt(m.retained_edges),`${fmt(m.retained_nodes)} 个节点`],['删除比例',`${((1-m.retained_edges/m.candidate_edges)*100).toFixed(1)}%`,`${fmt(m.candidate_edges-m.retained_edges)} 条边已删除`],['参考事件保留',`${d.truth.retained_events} / ${d.truth.matched_events}`,`${(d.truth.retention_rate*100).toFixed(1)}% · PDF 指标参考保留率`]].map(([l,v,n])=>`<div class="metric"><span>${esc(l)}</span><strong>${esc(v)}</strong><small>${esc(n)}</small></div>`).join('');
 state.byId=new Map(d.edges.map(e=>[e.id,e]));state.nodes=new Map(d.nodes.map(n=>[n.id,n]));state.display=d.display_event_ids.map(id=>state.byId.get(id));
 const ids=[...new Set(state.display.flatMap(e=>[e.source,e.target]))].sort();state.positions=new Map(ids.map((id,i)=>{const angle=i*2*Math.PI/ids.length;return [id,{x:320+260*Math.cos(angle),y:210+170*Math.sin(angle)}];}));
 state.sorted=[...d.edges].sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));d.edges.forEach(e=>e.search=`${e.id} ${e.source_label} ${e.target_label} ${e.relation}`.toLowerCase());
 $('#scope-note').textContent=`上方统计覆盖完整候选窗口；图中按时间等间隔抽取 ${state.display.length} 条边，不按评分或剪枝结果选样。逐边评分表覆盖全部 ${fmt(d.edges.length)} 条边。`;
 $('#run-log').textContent=d.logs.map((s,i)=>`${String(i+1).padStart(2,'0')}  ${s}`).join('\n');$('#truth-note').textContent=d.truth.note;$('#source-note').textContent=`数据：${d.dataset.source}；真值：${d.truth.source}；算法：${d.algorithm.name}，预算 ${d.algorithm.budget_ratio*100}%，稀有度：${d.algorithm.rarity}。`;
 const selected=d.poi;
 $('#poi-select').innerHTML=d.poi_presets.map(p=>`<option value="${esc(p.event_id)}">${esc(p.label)} · ${esc(localTime(p.timestamp))}</option>`).join('')+'<option value="custom">自定义事件 ID</option>';
 $('#poi-select').value=selected.groundtruth_backed?selected.event_id:'custom';$('#poi-id').value=selected.event_id;
 $('#poi-evidence').textContent=`当前 POI：${selected.label}。${selected.evidence}`;
 const utc=ns=>ns==null?'无':new Date(ns/1e6).toISOString();
 $('#history-note').textContent=`频率统计：${utc(d.history.start_ns)} 至 ${utc(d.history.last_event_ns)}（UTC），共 ${fmt(d.history.history_edges)} 条。严格早于 POI ${selected.timestamp}，不含同刻及之后事件；按所提供文件的全部可用历史统计。`;
 $('#stage-results').textContent=d.truth.stages.map(r=>`${r.label}：保留 ${r.retained} / ${r.matched}`).join('；')+`。排除指定 POI：${d.truth.non_poi_retained} / ${d.truth.non_poi_matched}。`;
 drawGraph(false);drawGraph(true);renderTable();

}
$('#show-scores').onchange=()=>{if(state.data){drawGraph(false);drawGraph(true);}};
for(const id of ['#edge-search','#edge-decision'])$(id).addEventListener('input',()=>{if(state.data){state.page=0;renderTable();}});
$('#clear-edge').onclick=()=>{$('#edge-search').value='';$('#edge-decision').value='all';state.page=0;if(state.data)renderTable();};
$('#prev-page').onclick=()=>{state.page--;renderTable();};$('#next-page').onclick=()=>{state.page++;renderTable();};load();

$('#poi-select').onchange=()=>{
 const p=state.data?.poi_presets.find(p=>p.event_id===$('#poi-select').value);
 if(p){$('#poi-id').value=p.event_id;$('#poi-evidence').textContent=`待应用：${p.evidence}`;}
 else{$('#poi-id').value='';$('#poi-id').focus();}
};
$('#poi-id').oninput=()=>{
 const p=state.data?.poi_presets.find(p=>p.event_id===$('#poi-id').value.trim());
 $('#poi-select').value=p?p.event_id:'custom';
 $('#poi-evidence').textContent=p?`待应用：${p.evidence}`:'待应用：自定义事件；未声称由 Ground Truth 证实。';
};
$('#use-event-poi').onclick=()=>{
 if(!state.selected)return;
 $('#poi-id').value=state.selected;$('#poi-id').dispatchEvent(new Event('input'));
 $('#poi-panel').scrollIntoView({behavior:'smooth'});
};
$('#poi-form').onsubmit=async event=>{
 event.preventDefault();if(!state.data||state.busy)return;
 const id=$('#poi-id').value.trim();if(!id)return;
 state.busy=true;$('#apply-poi').disabled=true;$('#poi-select').disabled=true;$('#poi-id').disabled=true;
 $('#prune-status').textContent='正在统计 POI 前全部历史并重新剪枝…';$('#error').hidden=true;
 try{
  const response=await fetch(`/api/datasets/${encodeURIComponent(state.data.dataset.id)}/prune`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({poi_event_id:id})});
  const d=await response.json();if(!response.ok)throw new Error(d.error||'重算失败');
  $('#edge-search').value='';$('#edge-decision').value='all';$('#event-detail').open=false;
  renderData(d);$('#prune-status').textContent=`已应用 ${d.poi.label}，图、评分、频率和运行日志已更新。`;
 }catch(error){$('#prune-status').textContent='重算失败，原结果保持不变。';$('#error').hidden=false;$('#error').textContent=error.message;}
 finally{state.busy=false;$('#apply-poi').disabled=false;$('#poi-select').disabled=false;$('#poi-id').disabled=false;}
};
