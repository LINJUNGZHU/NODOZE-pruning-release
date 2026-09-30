(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const NS = 'http://www.w3.org/2000/svg';
  const LABELS = {rarity_only: '仅稀有度', diffusion_only: '仅扩散', rasp: '原 RASP', context_v1: '上下文融合 v1', reliability: '可靠度校准融合', adaptive_v1: '整链自适应 v1', reliability_chain: '可靠度融合 + 整链选择'};
  const COLORS = {rarity_only: '#ad8452', diffusion_only: '#668cbd', rasp: '#8f969a', context_v1: '#a16fa2', reliability: '#d28056', adaptive_v1: '#60a59a', reliability_chain: '#087f79'};
  const TRACKS = {base: '基础候选范围', expanded: '扩展候选范围'};
  const POLICIES = {single: '最早声明单起点', declared: '全部声明起点', adaptive: '最早单起点 + 自适应建议'};
  const state = {report: null, reportHash: null, subgraph: null, request: 0, catalog: null, caseIndex: 0, track: '', poi: '', method: 'reliability_chain', budget: 1024};
  const el = (tag, value, cls) => { const node = document.createElement(tag); if (value != null) node.textContent = String(value); if (cls) node.className = cls; return node; };
  const svg = (tag, attributes = {}, value) => { const node = document.createElementNS(NS, tag); for (const [key, val] of Object.entries(attributes)) node.setAttribute(key, String(val)); if (value != null) node.textContent = String(value); return node; };
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const num = value => finite(value) ? value.toLocaleString('en-US') : 'N/A';
  const pct = value => finite(value) ? `${(value * 100).toFixed(1)}%` : 'N/A';
  const methodLabel = method => LABELS[method] || method;
  const currentCase = () => state.report.cases[state.caseIndex];
  const variant = () => currentCase().variants.find(item => item.track === state.track && item.poi_policy === state.poi);
  const methods = () => [...new Set(variant().rows.map(row => row.method))];
  const methodRows = () => variant().rows.filter(row => row.method === state.method).sort((a, b) => a.budget - b.budget);
  const currentRow = () => methodRows().find(row => row.budget === state.budget);
  const referenceRatio = row => row && row.reference_chain_count > 0 && finite(row.reference_chain_retention) ? `${num(row.retained_reference_chains)} / ${num(row.reference_chain_count)}` : 'N/A';
  const positiveRatio = row => row && row.positive_count > 0 && finite(row.positive_retention) ? `${num(row.retained_positive_events)} / ${num(row.positive_count)} (${pct(row.positive_retention)})` : 'N/A';
  const incrementalRatio = row => row && row.incremental_positive_count > 0 && finite(row.incremental_retention) ? `${num(row.retained_incremental_positives)} / ${num(row.incremental_positive_count)} (${pct(row.incremental_retention)})` : 'N/A';
  function options(id, values, selected, label) {
    $(id).replaceChildren(...values.map(value => { const option = el('option', label(value)); option.value = String(value); return option; }));
    $(id).value = String(selected);
  }
  function selectVariant() {
    const item = currentCase(), tracks = [...new Set(item.variants.map(v => v.track))];
    if (!tracks.includes(state.track)) state.track = tracks.includes('base') ? 'base' : tracks[0];
    options('track-select', tracks, state.track, value => TRACKS[value] || value);
    const policies = item.variants.filter(v => v.track === state.track).map(v => v.poi_policy);
    if (!policies.includes(state.poi)) state.poi = policies.includes('declared') ? 'declared' : policies[0];
    options('poi-select', policies, state.poi, value => POLICIES[value] || value);
    selectMethod();
  }
  function selectMethod() {
    const available = methods();
    if (!available.includes(state.method)) state.method = available.includes('reliability_chain') ? 'reliability_chain' : available[0];
    options('method-select', available, state.method, methodLabel);
    const budgets = methodRows().map(row => row.budget);
    if (!budgets.includes(state.budget)) state.budget = budgets[0];
    options('budget-select', budgets, state.budget, budget => `${num(budget)} 个候选事件条目`);
    render();
  }
  function renderMetrics() {
    const row = currentRow(), v = variant(), item = currentCase();
    const fixedCompression = finite(row.fixed_scope_compression) ? row.fixed_scope_compression : finite(v.source_scope_events) && v.source_scope_events > 0 ? 1 - row.retained_events / v.source_scope_events : null;
    const values = [
      ['retained', '实际保留事件', num(row.retained_events), `候选事件条目预算上限 ${num(row.budget)}`],
      ['candidate', '候选事件数', num(v.candidate_events), `声明 / 建议 POI 共 ${num(v.poi_count)} 个`],
      ['compression', '候选范围压缩率', pct(row.compression), '使用实际保留数与当前候选分母'],
      ['source-compression', '固定源范围压缩率', pct(fixedCompression), `固定源范围 ${num(v.source_scope_events)} 个事件`],
      ['reference', '完整参考链保留', referenceRatio(row), `固定参考保留率 ${pct(row.reference_chain_retention)}`],
      ['positive', '已知正事件保留', pct(row.positive_retention), positiveRatio(row)],
      ['incremental', '排除原始输入 POI 后的正例保留', pct(row.incremental_retention), `${incrementalRatio(row)} · 同案例固定分母`],
      ['verified', '已核验完整攻击链', 'N/A', '缺独立完整攻击范围真值'],
    ];
    $('metrics').replaceChildren(...values.map(([id, title, value, note]) => {
      const node = el('article', null, `metric${id === 'verified' ? ' unknown' : ''}`); node.id = 'metric-' + id;
      node.append(el('p', title, 'metric-label'), el('p', value, 'metric-value'), el('p', note, 'metric-note')); return node;
    }));
    const summary = item.fixed_reference_summary;
    $('reference-coverage-note').classList.remove('contains-lineage');
    if (summary && finite(summary.chain_count)) {
      const covered = summary.covered_positive_events, singles = summary.singleton_positive_events;
      const total = finite(covered) && finite(singles) ? covered + singles : null;
      const lineage = summary.paths_containing_synthetic_lineage;
      let note = `固定参考 ${num(summary.chain_count)} 条，覆盖源中 ${num(covered)} / ${num(total)} 个已知正事件；另有 ${num(singles)} 个正事件未进入多事件参考链。`;
      if (summary.chain_count > 0) note += `参考长度 ${num(summary.min_chain_events)}–${num(summary.max_chain_events)} 个事件。`;
      note += '参考路径非穷举，完整比例不等于全部正事件或完整攻击范围保留。';
      if (finite(lineage) && lineage > 0) {
        note += ` ${num(lineage)} / ${num(summary.chain_count)} 条含 LINEAGE 派生关系。`;
        if (lineage === summary.chain_count) note += '本案例的参考链曲线完全依赖含派生关系的路径，不能作为独立原始日志完整攻击链的证据。';
        $('reference-coverage-note').classList.add('contains-lineage');
      }
      $('reference-coverage-note').textContent = note;
    } else $('reference-coverage-note').textContent = item.annotation_status === 'unavailable' ? '该案例没有可用参考标注，完整参考与正事件保留统计为 N/A；实际保留子图仍可独立核对。' : '此汇总未提供完整的参考覆盖分解；不要将固定参考链比例解释为全部已知正事件或完整攻击范围的保留率。';
    const split = {development: '开发集', external: '外部检验', heldout: '留出检验'}[item.split] || item.split || '未声明';
    const annotation = {partial_positive: '部分正事件标注', unavailable: '无可用标注', derived_reference: '自动派生参考', captain_event_pattern_reference: 'CAPTAIN 事件模式参考（非完整链真值）', local_critical_partial_reference: '本地关键事件部分参考（非完整链真值）'}[item.annotation_status] || item.annotation_status || '未声明';
    $('case-note').textContent = `提供方 ${item.provider || '未声明'} · ${split} · 标注状态：${annotation}。剪枝评分未使用参考标签；保留目标预算由离线参考评价筛选。`;
    $('variant-note').textContent = `${TRACKS[v.track] || v.track} · ${POLICIES[v.poi_policy] || v.poi_policy} · POI ${num(v.poi_count)} 个 · 候选 ${num(v.candidate_events)} / 固定源范围 ${num(v.source_scope_events)} 个事件。自适应起点为算法建议${finite(v.suggested_poi_count) ? `（新增 ${num(v.suggested_poi_count)} 个，未经核验）` : '，未经核验'}。`;
  }
  function renderChart() {
    const chart = $('retention-chart'); chart.replaceChildren();
    const mobile = window.matchMedia('(max-width:650px)').matches;
    chart.setAttribute('viewBox', mobile ? '0 0 420 330' : '0 0 1000 410');
    chart.append(svg('desc', {id: 'chart-description'}, '横轴为实际压缩率，纵轴为固定参考链完整保留率。点与线仅表示已经运行的预算结果。'));
    const x = value => (mobile ? 72 : 74) + value * (mobile ? 328 : 884), y = value => (mobile ? 260 : 336) - value * (mobile ? 222 : 298);
    for (let tick = 0; tick <= 5; tick++) {
      const value = tick / 5;
      chart.append(svg('line', {x1: x(0), y1: y(value), x2: x(1), y2: y(value), stroke: '#e4ece7'}));
      chart.append(svg('text', {x: x(0) - 13, y: y(value) + 4, 'text-anchor': 'end', class: 'chart-label'}, `${tick * 20}%`));
      chart.append(svg('text', {x: x(value), y: mobile ? 282 : 359, 'text-anchor': 'middle', class: 'chart-label'}, `${tick * 20}%`));
    }
    chart.append(svg('line', {x1: x(0), y1: y(0), x2: x(1), y2: y(0), stroke: '#9eb6af'}));
    chart.append(svg('text', {x: mobile ? 225 : 515, y: mobile ? 317 : 397, 'text-anchor': 'middle', class: 'chart-axis-title'}, '实际压缩率（当前候选分母）'));
    chart.append(svg('text', {transform: mobile ? 'translate(14 150) rotate(-90)' : 'translate(20 190) rotate(-90)', 'text-anchor': 'middle', class: 'chart-axis-title'}, '完整参考链保留率'));
    let validPoints = 0;
    const legend = [];
    for (const method of methods()) {
      const color = COLORS[method] || '#5f8381';
      const points = variant().rows.filter(row => row.method === method && row.reference_chain_count > 0 && finite(row.reference_chain_retention) && finite(row.compression)).sort((a, b) => a.compression - b.compression);
      validPoints += points.length;
      if (points.length) chart.append(svg('polyline', {points: points.map(row => `${x(row.compression)},${y(row.reference_chain_retention)}`).join(' '), fill: 'none', stroke: color, 'stroke-width': method === state.method ? 3 : 1.6, opacity: method === state.method ? 1 : .7}));
      for (const row of points) {
        const selected = method === state.method && row.budget === state.budget;
        const circle = svg('circle', {cx: x(row.compression), cy: y(row.reference_chain_retention), r: selected ? 6 : 3.6, fill: selected ? '#fff' : color, stroke: color, 'stroke-width': selected ? 3 : 1});
        circle.append(svg('title', {}, `${methodLabel(method)} · 候选事件条目预算 ${num(row.budget)} · 压缩 ${pct(row.compression)} · 完整参考链 ${referenceRatio(row)}`));
        circle.addEventListener('click', () => { state.method = method; state.budget = row.budget; selectMethod(); }); chart.append(circle);
      }
      const button = el('button', null, method === state.method ? 'active' : ''); button.type = 'button'; button.style.setProperty('--method-color', color); button.setAttribute('aria-pressed', String(method === state.method)); button.append(el('i'), el('span', methodLabel(method)));
      button.addEventListener('click', () => { state.method = method; selectMethod(); }); legend.push(button);
    }
    $('chart-legend').replaceChildren(...legend);
    $('chart-note').textContent = validPoints ? '固定参考来自源日志已知正事件子图中的见证，全部必需成员保留才计为完整；不等同于现实全部攻击链。扩展范围的横轴分母会变化，跨范围应结合固定源压缩率和相同候选事件条目预算比较。' : '当前范围没有可定义的完整参考链保留率，图中不填入 0% 或推测点。请核对参考数量与标注范围。';
    $('point-buttons').replaceChildren(...methodRows().map(row => {
      const button = el('button', null, row.budget === state.budget ? 'active' : ''); button.type = 'button'; button.setAttribute('aria-pressed', String(row.budget === state.budget));
      button.append(el('strong', `预算 ${num(row.budget)}`), el('span', `压缩 ${pct(row.compression)} · 整链 ${referenceRatio(row)}`));
      button.addEventListener('click', () => { state.budget = row.budget; $('budget-select').value = String(row.budget); render(); }); return button;
    }));
  }
  function renderComparison() {
    $('comparison-note').textContent = `固定候选事件条目预算 ${num(state.budget)}。LINEAGE 派生关系也占用条目预算。仅对照相同范围和相同起点策略的实际结果；未运行的组合显示 N/A，不按比例换算。耗时仅含选择器，不含候选提取、评分与导出。`;
    $('comparison-rows').replaceChildren(...methods().map(method => {
      const data = variant().rows.find(row => row.method === method && row.budget === state.budget), row = el('tr', null, method === state.method ? 'comparison-active' : '');
      const methodCell = el('td'), button = el('button', methodLabel(method), 'method-button'); button.type = 'button'; button.addEventListener('click', () => { state.method = method; selectMethod(); }); methodCell.append(button);
      row.append(methodCell, el('td', num(state.budget), 'raw-budget'), el('td', num(data?.retained_events)), el('td', pct(data?.compression)), el('td', referenceRatio(data)), el('td', positiveRatio(data)), el('td', incrementalRatio(data)), el('td', finite(data?.selection_seconds) ? data.selection_seconds.toFixed(4) : 'N/A'));
      return row;
    }));
  }
  function renderStages() {
    const row = currentRow(), stages = [['源日志可见', row.source_positive_events], ['候选范围覆盖', row.candidate_positive_events], ['时序见证可达', row.temporal_positive_events], ['最终保留', row.retained_positive_events]];
    $('stage-rows').replaceChildren(...stages.map(([label, count], index) => {
      const previous = stages[index - 1]?.[1], difference = index > 0 && finite(previous) && finite(count) ? previous - count : null;
      const tr = el('tr'); tr.append(el('td', label), el('td', num(count), 'stage-count'), el('td', difference == null ? '—' : difference >= 0 ? num(difference) : '阶段非嵌套，不能作损失相减')); return tr;
    }));
    $('stage-note').textContent = `正例增量指标统一排除原始输入 POI，所有策略使用同案例固定分母。固定正事件标注数 ${num(row.positive_count)}；源记录缺失 ${num(row.source_missing_positive_events)}。缺少统计字段显示 N/A；阶段差仅在可比较计数之间展示，未给出完整链首次损失归因。`;
  }
  function renderReadiness() {
    const names = {ready: '日志已接入', available: '数据可用', available_partial_logs: '部分日志已接入', annotation_only_missing_matching_event_source: '仅有标注，缺匹配日志', annotation_only: '仅有标注', annotations_only: '仅有标注', missing_logs: '缺匹配日志', unavailable: '尚不可用', pending: '待接入', partial: '部分可用'};
    $('readiness-rows').replaceChildren(...(state.report.data_readiness || []).map(item => {
      const row = el('tr'), cell = el('td'), pending = !['ready', 'available'].includes(item.status);
      cell.append(el('span', names[item.status] || item.status || '未声明', `status-label${pending ? ' pending' : ''}`));
      row.append(el('td', item.dataset), el('td', item.provider), cell, el('td', item.reason || '未提供')); return row;
    }));
    if (!$('readiness-rows').children.length) { const row = el('tr'), cell = el('td', '汇总未提供数据就绪清单，不推断外部数据可用。'); cell.colSpan = 4; row.append(cell); $('readiness-rows').append(row); }
    $('methodology-json').textContent = JSON.stringify({methods: state.report.methods || {}, methodology: state.report.methodology || {}, protocol: state.report.protocol || {}}, null, 2);
    $('report-meta').textContent = `汇总生成时间：${state.report.generated_at || '未提供'} · ${state.report.cases.length} 个案例 · 当前页面为聚合指标，逐事件明细见本机实际保留链路。`;
  }
  function renderExport() {
    const row = currentRow(), item = currentCase();
    const entries = state.catalog || [];
    const match = entries.find(entry => entry.study_version === 'chain-workbench-v2' && entry.case_id === item.id && entry.track === state.track && entry.poi_policy === state.poi && entry.method === row.method && entry.budget_edges === row.budget && typeof entry.id === 'string');
    const link = $('exact-export-link'); link.hidden = !match; link.removeAttribute('href');
    if (match) link.setAttribute('href', '/assets/retained-chains.html?entry=' + encodeURIComponent(match.id));
    $('export-point-note').textContent = match ? '此链接与当前案例、候选范围、起点策略、方法和条目预算精确对应。' : '未找到与当前点完全一致的本机导出；导出目录中的其他图不能代表这个曲线点。可用下方 CLI 从当前冻结决策精确导出。';
    const decisions = state.report.cases.reduce((total, caseItem) => total + caseItem.variants.reduce((count, v) => count + v.rows.length, 0), 0);
    const current = entries.filter(entry => entry.study_version === 'chain-workbench-v2').length;
    $('export-catalog-note').textContent = `汇总含 ${num(decisions)} 个已冻结决策，任意方法和预算均可精确导出。` + (state.catalog ? ` 本机目录：本轮代表导出 ${num(current)} 份，旧版归档 ${num(entries.length - current)} 份。` : ' 本机逐事件导出目录尚未读取到；公开汇总不附带私有事件图。');
    $('point-export-command').textContent = `python -m scripts.export_chain_workbench --frozen <本轮目录>/${item.id}/${state.track}/${state.poi} --method ${row.method} --budget ${row.budget} --output <新的导出目录>`;
  }
  const SUBGRAPH_COUNTS = ['reference_subgraph_count', 'complete_subgraphs', 'reference_events', 'retained_reference_events', 'singleton_event_count', 'retained_singleton_events', 'terminal_pairs', 'reachable_terminal_pairs', 'reference_dependencies', 'retained_dependencies', 'fork_count', 'complete_forks', 'join_count', 'complete_joins'];
  const SUBGRAPH_RATIOS = ['subgraph_retention', 'event_retention', 'terminal_reachability', 'dependency_retention', 'fork_retention', 'join_retention'];
  const subgraphKey = (caseId, track, poi, method, budget) => JSON.stringify([caseId, track, poi, method, budget]);
  function validateSubgraphReport(data) {
    if (data?.schema_version !== 'chain-subgraph-report-v1' || !Array.isArray(data.cases)) throw new Error('子图附加汇总格式不匹配。');
    if (!state.reportHash || data.base_report_sha256 !== state.reportHash) throw new Error('子图附加汇总与当前 v2 报告的文件哈希不匹配，已拒绝混用。');
    const rows = new Map(), cases = new Map();
    for (const item of data.cases) {
      const original = state.report.cases.find(c => c.id === item.id);
      if (!original || cases.has(item.id) || !Array.isArray(item.variants)) throw new Error('子图汇总的案例范围与冻结决策不匹配。');
      for (const field of ['reference_sha256', 'source_positive_snapshot_sha256']) if (original[field] != null && item[field] !== original[field]) throw new Error('子图参考来源哈希与 v2 汇总不匹配。');
      cases.set(item.id, item);
      for (const v of item.variants) {
        const base = original.variants.find(b => b.track === v.track && b.poi_policy === v.poi_policy);
        if (!base || v.candidate_events !== base.candidate_events || !Array.isArray(v.rows)) throw new Error('子图候选范围与冻结决策不匹配。');
        for (const row of v.rows) {
          const before = base.rows.find(b => b.method === row.method && b.budget === row.budget);
          const key = subgraphKey(item.id, v.track, v.poi_policy, row.method, row.budget);
          if (!before || rows.has(key) || row.retained_events !== before.retained_events || row.compression !== before.compression) throw new Error('子图附加行与原有冻结决策不匹配。');
          for (const scope of ['native', 'augmented']) {
            const m = row.scopes?.[scope];
            if (!m || m.independent_attack_count !== null || m.attack_stage_completeness !== null) throw new Error('子图参考不能提供未经独立验证的攻击数量或攻击阶段完整性。');
            if (SUBGRAPH_COUNTS.some(field => m[field] !== null && (!Number.isInteger(m[field]) || m[field] < 0)) || SUBGRAPH_RATIOS.some(field => m[field] !== null && (!finite(m[field]) || m[field] < 0 || m[field] > 1))) throw new Error('子图计数或比例不符合汇总格式。');
            for (const [a, b] of [['complete_subgraphs', 'reference_subgraph_count'], ['retained_reference_events', 'reference_events'], ['retained_singleton_events', 'singleton_event_count'], ['reachable_terminal_pairs', 'terminal_pairs'], ['retained_dependencies', 'reference_dependencies'], ['complete_forks', 'fork_count'], ['complete_joins', 'join_count']]) if (finite(m[a]) && finite(m[b]) && m[a] > m[b]) throw new Error('子图保留数量超过参考分母。');
            for (const [ratio, numerator, denominator] of [['subgraph_retention', 'complete_subgraphs', 'reference_subgraph_count'], ['event_retention', 'retained_reference_events', 'reference_events'], ['terminal_reachability', 'reachable_terminal_pairs', 'terminal_pairs'], ['dependency_retention', 'retained_dependencies', 'reference_dependencies'], ['fork_retention', 'complete_forks', 'fork_count'], ['join_retention', 'complete_joins', 'join_count']]) {
              const a = m[numerator], b = m[denominator], value = m[ratio];
              if ((a === null) !== (b === null) || ((b === null || b === 0) ? value !== null : value === null || Math.abs(value - a / b) > 1e-12)) throw new Error('子图比例与对应分子、分母不一致。');
            }
          }
          rows.set(key, row);
        }
      }
    }
    return {data, rows, cases};
  }
  const subgraphRow = (method = state.method, budget = state.budget) => state.subgraph?.rows.get(subgraphKey(currentCase().id, state.track, state.poi, method, budget));
  const countRatio = (a, b) => finite(a) && finite(b) && b > 0 ? `${num(a)} / ${num(b)}` : 'N/A';
  const SUBGRAPH_LABELS = {event_retention: '参考事件保留率', dependency_retention: '事件依赖保留率', terminal_reachability: '固定入口—出口可达率', subgraph_retention: '完整参考子图保留率'};
  const exactPct = value => finite(value) ? `${(value * 100).toFixed(2)}%` : 'N/A';
  function retentionTarget() {
    const scope = $('subgraph-scope').value, target = Number($('retention-target').value);
    const fields = ['event_retention', 'dependency_retention'];
    if ($('retention-terminals').checked) fields.push('terminal_reachability');
    const rows = methodRows().map(row => subgraphRow(state.method, row.budget));
    if (!rows.length || rows.some(row => !row || fields.some(key => !finite(row.scopes[scope][key])))) return {status: 'unavailable', scope, target, fields};
    const valid = rows.filter(row => fields.every(key => row.scopes[scope][key] >= target)).sort((a, b) => b.compression - a.compression || a.budget - b.budget);
    if (valid.length) return {status: 'met', row: valid[0], scope, target, fields};
    const score = row => Math.min(...fields.map(key => row.scopes[scope][key]));
    const closest = [...rows].sort((a, b) => score(b) - score(a) || b.compression - a.compression || a.budget - b.budget)[0];
    const m = closest.scopes[scope], counts = m.event_stage_counts;
    let reason = '已测预算中没有同时达标的点，不能通过曲线插值承诺达标。';
    if (counts && m.reference_events > 0) {
      if (counts.candidate / m.reference_events < target) reason = `候选事件覆盖上限 ${exactPct(counts.candidate / m.reference_events)}，应先扩大候选范围。`;
      else if (counts.temporal_eligible / m.reference_events < target) reason = `当前方法的时序资格事件覆盖上限 ${exactPct(counts.temporal_eligible / m.reference_events)}，增加预算仍无法越过这一缺口。`;
    }
    return {status: 'unmet', closest, reason, scope, target, fields};
  }
  function renderRetentionTarget() {
    const result = retentionTarget(), node = $('retention-target-result'), button = $('apply-retention-target');
    node.dataset.status = result.status; node.removeAttribute('data-budget'); button.disabled = result.status !== 'met';
    if (result.status === 'unavailable') node.textContent = 'N/A：所需参考指标没有可用分母，无法据此筛选达标预算。';
    else {
      const row = result.row || result.closest, m = row.scopes[result.scope];
      const values = `事件 ${exactPct(m.event_retention)} · 依赖 ${exactPct(m.dependency_retention)} · 入口—出口可达 ${exactPct(m.terminal_reachability)}`;
      if (result.status === 'met') {
        node.dataset.budget = String(row.budget);
        node.textContent = `已测预算中的最高达标压缩率 ${exactPct(row.compression)}：预算 ${num(row.budget)}，实际保留 ${num(row.retained_events)} 个事件。${values}。`;
      } else node.textContent = `${result.reason} 联合保留率最高的已测点为预算 ${num(row.budget)}：${values}。`;
    }
    const current = subgraphRow()?.scopes[result.scope];
    const available = current && result.fields.every(key => finite(current[key]));
    $('retention-current-status').textContent = !available ? '当前预算的目标状态：N/A。' : `当前预算 ${num(state.budget)}：${result.fields.every(key => current[key] >= result.target) ? '已达标' : '尚未达标'}。${$('retention-terminals').checked ? '事件、依赖和端点可达率须同时满足目标。' : '本目标约束事件和依赖，端点可达率单独显示。'}`;
  }
  function renderSubgraphChart() {
    const chart = $('subgraph-chart'); chart.replaceChildren();
    const scope = $('subgraph-scope').value, mobile = window.matchMedia('(max-width:650px)').matches;
    const metric = $('subgraph-metric-select').value, label = SUBGRAPH_LABELS[metric];
    $('subgraph-curve-title').textContent = '压缩率—' + label;
    chart.setAttribute('viewBox', mobile ? '0 0 420 330' : '0 0 1000 410');
    chart.append(svg('desc', {id: 'subgraph-chart-description'}, `纵轴为${label}，只显示已测预算。事件和依赖保留允许部分保留；完整子图要求全部固定成员保留。`));
    const x = value => (mobile ? 72 : 74) + value * (mobile ? 328 : 884), y = value => (mobile ? 260 : 336) - value * (mobile ? 222 : 298);
    for (let tick = 0; tick <= 5; tick++) {
      const value = tick / 5;
      chart.append(svg('line', {x1: x(0), y1: y(value), x2: x(1), y2: y(value), stroke: '#e4ece7'}));
      chart.append(svg('text', {x: x(0) - 13, y: y(value) + 4, 'text-anchor': 'end', class: 'chart-label'}, `${tick * 20}%`));
      chart.append(svg('text', {x: x(value), y: mobile ? 282 : 359, 'text-anchor': 'middle', class: 'chart-label'}, `${tick * 20}%`));
    }
    chart.append(svg('text', {x: mobile ? 225 : 515, y: mobile ? 317 : 397, 'text-anchor': 'middle', class: 'chart-axis-title'}, '实际压缩率（当前候选分母）'));
    chart.append(svg('text', {transform: mobile ? 'translate(14 150) rotate(-90)' : 'translate(20 190) rotate(-90)', 'text-anchor': 'middle', class: 'chart-axis-title'}, label));
    if (metric !== 'subgraph_retention' && (metric !== 'terminal_reachability' || $('retention-terminals').checked)) {
      const floor = Number($('retention-target').value);
      chart.append(svg('line', {x1: x(0), y1: y(floor), x2: x(1), y2: y(floor), class: 'target-floor'}));
    }
    const legends = [];
    for (const method of methods()) {
      const color = COLORS[method] || '#5f8381';
      const points = variant().rows.filter(row => row.method === method).map(row => subgraphRow(method, row.budget)).filter(row => row && finite(row.scopes[scope][metric])).sort((a, b) => a.compression - b.compression);
      if (points.length) chart.append(svg('polyline', {points: points.map(row => `${x(row.compression)},${y(row.scopes[scope][metric])}`).join(' '), fill: 'none', stroke: color, 'stroke-width': method === state.method ? 3 : 1.6, opacity: method === state.method ? 1 : .65}));
      for (const row of points) {
        const m = row.scopes[scope], selected = method === state.method && row.budget === state.budget;
        const dot = svg('circle', {cx: x(row.compression), cy: y(m[metric]), r: selected ? 6 : 3.6, fill: selected ? '#fff' : color, stroke: color, 'stroke-width': selected ? 3 : 1});
        dot.append(svg('title', {}, `${methodLabel(method)} · 条目预算 ${num(row.budget)} · 压缩 ${exactPct(row.compression)} · ${label} ${exactPct(m[metric])}`));
        dot.addEventListener('click', () => { state.method = method; state.budget = row.budget; selectMethod(); }); chart.append(dot);
      }
      const button = el('button', null, method === state.method ? 'active' : ''); button.type = 'button'; button.style.setProperty('--method-color', color); button.setAttribute('aria-pressed', String(method === state.method)); button.append(el('i'), el('span', methodLabel(method))); button.addEventListener('click', () => { state.method = method; selectMethod(); }); legends.push(button);
    }
    $('subgraph-legend').replaceChildren(...legends);
    $('subgraph-point-buttons').replaceChildren(...methodRows().map(base => {
      const row = subgraphRow(state.method, base.budget), m = row?.scopes[scope];
      const button = el('button', null, base.budget === state.budget ? 'active' : ''); button.type = 'button'; button.setAttribute('aria-pressed', String(base.budget === state.budget));
      button.append(el('strong', `预算 ${num(base.budget)}`), el('span', `压缩 ${exactPct(base.compression)} · ${label} ${m ? exactPct(m[metric]) : 'N/A'}`));
      button.addEventListener('click', () => { state.budget = base.budget; $('budget-select').value = String(base.budget); render(); }); return button;
    }));
  }
  function renderSubgraphs() {
    if (!state.subgraph) return;
    const row = subgraphRow();
    $('subgraph-content').hidden = !row; $('subgraph-status').hidden = Boolean(row);
    if (!row) { $('subgraph-status').textContent = '当前冻结决策尚未提供子图附加评价；原有路径结果仍有效。'; return; }
    const scope = $('subgraph-scope').value, m = row.scopes[scope], item = state.subgraph.cases.get(currentCase().id), quality = item.reference_summaries?.[scope] || {};
    renderRetentionTarget();
    const metrics = [
      ['complete', '完整参考子图', countRatio(m.complete_subgraphs, m.reference_subgraph_count), pct(m.subgraph_retention)],
      ['events', '参考事件保留', countRatio(m.retained_reference_events, m.reference_events), pct(m.event_retention)],
      ['singletons', '单事件参考保留', countRatio(m.retained_singleton_events, m.singleton_event_count), '单例单独核对，不充当多事件攻击数'],
      ['terminals', '端点时序可达', countRatio(m.reachable_terminal_pairs, m.terminal_pairs), pct(m.terminal_reachability)],
      ['dependencies', '事件依赖保留', countRatio(m.retained_dependencies, m.reference_dependencies), pct(m.dependency_retention)],
      ['forks', '完整分支点', countRatio(m.complete_forks, m.fork_count), pct(m.fork_retention)],
      ['joins', '完整汇合点', countRatio(m.complete_joins, m.join_count), pct(m.join_retention)],
      ['verified', '已核验完整攻击', 'N/A', '攻击阶段完整性也为 N/A'],
    ];
    $('subgraph-metrics').replaceChildren(...metrics.map(([id, title, value, note]) => { const node = el('article', null, 'metric'); node.id = 'subgraph-metric-' + id; node.append(el('p', title, 'metric-label'), el('p', value, 'metric-value'), el('p', note, 'metric-note')); return node; }));
    $('subgraph-scope-note').textContent = `${scope === 'native' ? '原生审计事件范围：排除 LINEAGE 等派生关系。' : '含派生关系范围：保留 LINEAGE 等关系，用于敏感性核对。'} 参考范围切换不改变冻结候选、预算、压缩率或保留决策。两种范围各自使用固定分母，不可把比例差直接解释为方法提升。一个参考子图的多条路径、分支和汇合不计为多个独立攻击。`;
    $('subgraph-quality-note').textContent = `输入事件 ${num(quality.input_events)} · 排除派生事件 ${num(quality.excluded_synthetic_events)} · 当前含 LINEAGE 等派生事件 ${num(quality.synthetic_events)} · 推断主机依赖 ${num(quality.inferred_host_dependencies)} · 时间不可核验 ${num(quality.unverifiable_time_events)} · 源中缺失正事件 ${num(item.source_missing_positive_events)}。完整性仅针对离线固定参考，不能证明未观测攻击范围。`;
    const stages = [['source', '源中可见'], ['candidate', '候选覆盖'], ['temporal_eligible', '时序资格'], ['retained', '最终保留']];
    $('subgraph-stage-rows').replaceChildren(...stages.map(([key, label]) => { const tr = el('tr'); tr.append(el('td', label), el('td', num(m.subgraph_stage_counts?.[key])), el('td', num(m.event_stage_counts?.[key])), el('td', key === 'source' ? '—' : num(m.first_loss_counts?.[key]))); return tr; }));
    renderSubgraphChart();
  }
  async function loadSubgraphs(request) {
    state.subgraph = null; $('subgraph-content').hidden = true; $('subgraph-status').hidden = false; $('subgraph-status').textContent = '正在校验子图附加汇总…';
    try {
      const response = await fetch('/assets/chain-subgraph-summary.json', {cache: 'no-store'});
      if (request !== state.request) return;
      if (!response.ok) throw new Error(response.status === 404 ? '子图附加评价尚未发布；现有路径曲线、保留图和下载仍可使用。' : `子图附加汇总读取失败（HTTP ${response.status}）；现有 v2 结果仍可使用。`);
      const data = await response.json(); if (request !== state.request) return;
      state.subgraph = validateSubgraphReport(data); renderSubgraphs();
    } catch (error) { if (request !== state.request) return; state.subgraph = null; $('subgraph-content').hidden = true; $('subgraph-status').hidden = false; $('subgraph-status').textContent = error.message; }
  }
  function render() { renderMetrics(); renderChart(); renderComparison(); renderStages(); renderExport(); renderSubgraphs(); }
  async function load() {
    const request = ++state.request; state.subgraph = null;
    $('load-error').hidden = true; $('workbench-content').hidden = true; $('load-status').hidden = false;
    try {
      const response = await fetch('/assets/chain-workbench-summary.json', {cache: 'no-store'});
      if (!response.ok) throw new Error(response.status === 404 ? '尚未发布本轮公开汇总，现有链路与参考链页面仍可访问。' : `汇总读取失败（HTTP ${response.status}）。`);
      const reportBytes = await response.arrayBuffer();
      const report = JSON.parse(new TextDecoder().decode(reportBytes));
      const reportHash = window.crypto?.subtle ? Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', reportBytes)), byte => byte.toString(16).padStart(2, '0')).join('') : null;
      if (request !== state.request) return;
      state.reportHash = reportHash;
      if (report.schema_version !== 'chain-workbench-v2-report' || !Array.isArray(report.cases) || !report.cases.length) throw new Error('汇总格式不匹配，或尚无已完成的实验案例。');
      if (report.cases.some(item => !Array.isArray(item.variants) || !item.variants.length || item.variants.some(v => !Array.isArray(v.rows) || !v.rows.length))) throw new Error('汇总包含没有结果行的实验范围，请完成对应实验后再发布。');
      state.report = report; state.caseIndex = 0; state.catalog = null;
      try {
        const catalogResponse = await fetch('/assets/retained-chain-catalog.json', {cache: 'no-store'});
        if (catalogResponse.ok) { const catalog = await catalogResponse.json(); if (Array.isArray(catalog.entries)) state.catalog = catalog.entries; }
      } catch (_) { /* Aggregate comparisons remain usable without local exports. */ }
      options('case-select', report.cases.map((_, i) => i), 0, i => report.cases[i].label || report.cases[i].id);
      selectVariant(); renderReadiness(); $('workbench-content').hidden = false; $('load-status').hidden = true; loadSubgraphs(request);
    } catch (error) { $('load-status').hidden = true; $('load-error').hidden = false; $('load-error-detail').textContent = error.message; }
  }
  $('case-select').addEventListener('change', event => { state.caseIndex = Number(event.target.value); selectVariant(); });
  $('track-select').addEventListener('change', event => { state.track = event.target.value; selectVariant(); });
  $('poi-select').addEventListener('change', event => { state.poi = event.target.value; selectMethod(); });
  $('method-select').addEventListener('change', event => { state.method = event.target.value; selectMethod(); });
  $('budget-select').addEventListener('change', event => { state.budget = Number(event.target.value); render(); });
  $('subgraph-scope').addEventListener('change', renderSubgraphs);
  $('subgraph-metric-select').addEventListener('change', renderSubgraphChart);
  $('retention-target').addEventListener('change', renderSubgraphs);
  $('retention-terminals').addEventListener('change', renderSubgraphs);
  $('apply-retention-target').addEventListener('click', () => {
    const result = retentionTarget();
    if (result.status === 'met') { state.budget = result.row.budget; $('budget-select').value = String(state.budget); render(); }
  });
  $('reload-button').addEventListener('click', load);
  window.addEventListener('resize', () => { if (state.report) { renderChart(); if (state.subgraph) renderSubgraphs(); } });
  load();
})();
