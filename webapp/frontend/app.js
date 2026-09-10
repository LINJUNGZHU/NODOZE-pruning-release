const state = { data:null, selectedPath:"all", showRemoved:true, view:{scale:1,dx:0,dy:0} };
const colors = { process:"#2f6f9f", file:"#2a9d8f", socket:"#7c3aed", unknown:"#64748b" };
const fmt = n => new Intl.NumberFormat("zh-CN").format(n);
const pct = n => `${(n*100).toFixed(2)}%`;
const short = s => (s || "").replace(/^(process|file|socket):/,"").split("/").pop().slice(0,24) || s.slice(0,12);

function metricCards(m){
  const rows=[[fmt(m.candidate_edges),"候选边"],[fmt(m.retained_edges),"剪枝后边"],[pct(m.compression_ratio),"图压缩率"],[pct(m.attack_event_recall),"攻击事件召回"],[`${m.retained_paths}/${m.reference_paths}`,"完整攻击路径"]];
  document.querySelector("#metrics").innerHTML=rows.map(([v,k])=>`<div class="metric"><strong>${v}</strong><span>${k}</span></div>`).join("");
}

function layout(data){
  const incident=new Map();
  data.edges.forEach(e=>{[e.source,e.target].forEach(id=>{const v=incident.get(id)||[];v.push(e.timestamp_ns);incident.set(id,v)})});
  const times=data.edges.map(e=>e.timestamp_ns), lo=Math.min(...times), hi=Math.max(...times), span=Math.max(1,hi-lo);
  const lanes={process:.22,file:.48,socket:.74,unknown:.88};
  const pos=new Map();
  data.nodes.forEach((n,i)=>{const ts=Math.min(...(incident.get(n.id)||[lo]));const jitter=((hash(n.id)%100)/100-.5)*.13;pos.set(n.id,{x:.06+.88*(ts-lo)/span,y:(lanes[n.type]||.88)+jitter,node:n})});
  return pos;
}
function hash(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return h>>>0}

function draw(canvas, after=false){
  const data=state.data, rect=canvas.getBoundingClientRect(), dpr=devicePixelRatio||1;
  canvas.width=rect.width*dpr;canvas.height=rect.height*dpr;
  const ctx=canvas.getContext("2d");ctx.scale(dpr,dpr);ctx.clearRect(0,0,rect.width,rect.height);
  const pos=state.pos, tr=p=>({x:(p.x*rect.width*state.view.scale)+state.view.dx,y:(p.y*rect.height*state.view.scale)+state.view.dy});
  const visible=data.edges.filter(e=>(!after||e.retained)&&(state.showRemoved||e.retained));
  visible.forEach(e=>{const a=tr(pos.get(e.source)),b=tr(pos.get(e.target));if(!a||!b)return;const active=state.selectedPath==="all"?e.attack_paths.length:e.attack_paths.includes(state.selectedPath);ctx.strokeStyle=active?"#dc2626":e.retained?"#7d9db2":"#d8e0e7";ctx.globalAlpha=active?1:e.retained?.34:.22;ctx.lineWidth=active?2.2:.7;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke()});
  ctx.globalAlpha=1;data.nodes.forEach(n=>{const p=tr(pos.get(n.id));if(p.x<0||p.x>rect.width||p.y<0||p.y>rect.height)return;const active=state.selectedPath==="all"?n.attack:data.edges.some(e=>e.attack_paths.includes(state.selectedPath)&&(e.source===n.id||e.target===n.id));ctx.fillStyle=n.poi?"#f59e0b":active?"#dc2626":colors[n.type]||colors.unknown;ctx.beginPath();ctx.arc(p.x,p.y,n.poi?5:active?4:2.2,0,Math.PI*2);ctx.fill();if(n.poi){ctx.fillStyle="#132238";ctx.font="11px system-ui";ctx.fillText(short(n.label),p.x+7,p.y-6)}});
  canvas._visible=visible;canvas._transform=tr;
}
function redraw(){draw(document.querySelector("#before"),false);draw(document.querySelector("#after"),true)}

function wireCanvas(canvas){
  let drag=null;
  canvas.addEventListener("mousedown",e=>{drag={x:e.clientX,y:e.clientY,dx:state.view.dx,dy:state.view.dy};canvas.style.cursor="grabbing"});
  addEventListener("mouseup",()=>{drag=null;canvas.style.cursor="grab"});
  addEventListener("mousemove",e=>{if(!drag)return;state.view.dx=drag.dx+e.clientX-drag.x;state.view.dy=drag.dy+e.clientY-drag.y;redraw()});
  canvas.addEventListener("wheel",e=>{e.preventDefault();state.view.scale=Math.max(.5,Math.min(5,state.view.scale*(e.deltaY<0?1.12:.89)));redraw()},{passive:false});
  canvas.addEventListener("click",e=>{if(!state.pos)return;const rect=canvas.getBoundingClientRect();let best=null,dist=18;state.data.nodes.forEach(n=>{const p=canvas._transform(state.pos.get(n.id));const d=Math.hypot(p.x-(e.clientX-rect.left),p.y-(e.clientY-rect.top));if(d<dist){dist=d;best=n}});if(best)document.querySelector("#details").textContent=JSON.stringify(best,null,2)});
}

async function load(){
  const res=await fetch("/api/datasets/theia-case3/graph");if(!res.ok)throw new Error(await res.text());
  state.data=await res.json();state.pos=layout(state.data);metricCards(state.data.metrics);
  document.querySelector("#health").textContent="● 服务正常";
  document.querySelector("#sample-note").textContent=`交互视图为 ${fmt(state.data.sample.node_count)} 个节点、${fmt(state.data.sample.edge_count)} 条代表边；完整统计来自百万边账本。`;
  const retained=state.data.edges.filter(e=>e.retained).length;
  document.querySelector("#before-count").textContent=`${fmt(state.data.edges.length)} 条代表边`;
  document.querySelector("#after-count").textContent=`${fmt(retained)} 条保留边`;
  const sel=document.querySelector("#path-select");state.data.paths.forEach(p=>sel.insertAdjacentHTML("beforeend",`<option value="${p.id}">${p.id}（${p.event_ids.length} 事件）</option>`));
  document.querySelector("#paths").innerHTML=state.data.paths.map((p,i)=>`<div class="path-item"><strong>路径 ${i+1} · ${p.event_ids.length} 个核心事件</strong><code>${p.event_ids.join(" → ")}</code></div>`).join("");
  redraw();
}

document.querySelector("#path-select").addEventListener("change",e=>{state.selectedPath=e.target.value;redraw()});
document.querySelector("#show-removed").addEventListener("change",e=>{state.showRemoved=e.target.checked;redraw()});
document.querySelector("#fit").addEventListener("click",()=>{state.view={scale:1,dx:0,dy:0};redraw()});
addEventListener("resize",()=>state.data&&redraw());
wireCanvas(document.querySelector("#before"));wireCanvas(document.querySelector("#after"));

document.querySelector("#upload-form").addEventListener("submit",async e=>{
  e.preventDefault();const output=document.querySelector("#upload-status"),body=new FormData();[...document.querySelector("#files").files].forEach(f=>body.append("files",f));output.textContent="正在上传…";
  const res=await fetch("/api/imports",{method:"POST",body});const job=await res.json();if(!res.ok){output.textContent=JSON.stringify(job,null,2);return}output.textContent=JSON.stringify(job,null,2);
  const timer=setInterval(async()=>{const r=await fetch(`/api/imports/${job.id}`),j=await r.json();output.textContent=JSON.stringify(j,null,2);if(["complete","failed"].includes(j.status))clearInterval(timer)},2000);
});

load().catch(err=>{document.querySelector("#health").textContent="● 数据未就绪";document.querySelector("#details").textContent=err.message});
