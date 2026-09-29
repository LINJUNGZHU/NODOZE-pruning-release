(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const NS = 'http://www.w3.org/2000/svg';
  const LABELS = {rarity_only: '仅稀有度', diffusion_only: '仅扩散', rasp: '原 RASP', context_v1: '上下文融合 v1', reliability: '可靠度校准融合', adaptive_v1: '整链自适应 v1', reliability_chain: '可靠度融合 + 整链选择'};
  const COLORS = {rarity_only: '#ad8452', diffusion_only: '#668cbd', rasp: '#8f969a', context_v1: '#a16fa2', reliability: '#d28056', adaptive_v1: '#60a59a', reliability_chain: '#087f79'};
  const TRACKS = {base: '基础候选范围', expanded: '扩展候选范围'};
  const POLICIES = {single: '最早声明单起点', declared: '全部声明起点', adaptive: '最早单起点 + 自适应建议'};
  const state = {report: null, catalog: null, caseIndex: 0, track: '', poi: '', method: 'reliability_chain', budget: 1024};
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
    $('case-note').textContent = `提供方 ${item.provider || '未声明'} · ${split} · 标注状态：${annotation}。参考标签用于离线评价，不作为结果选择的证据。`;
    $('variant-note').textContent = `${TRACKS[v.track] || v.track} · ${POLICIES[v.poi_policy] || v.poi_policy} · POI ${num(v.poi_count)} 个 · 候选 ${num(v.candidate_events)} / 固定源范围 ${num(v.source_scope_events)} 个事件。自适应起点为算法建议${finite(v.suggested_poi_count) ? `（新增 ${num(v.suggested_poi_count)} 个，未经核验）` : '，未经核验'}。`;
  }
  function renderChart() {
    const chart = $('retention-chart'); chart.replaceChildren();
    const mobile = window.matchMedia('(max-width:650px)').matches;
    chart.setAttribute('viewBox', mobile ? '0 0 420 330' : '0 0 1000 410');
    chart.append(svg('desc', {id: 'chart-description'}, '横轴为实际压缩率，纵轴为固定参考链完整保留率。点与线仅表示已经运行的预算结果。'));
    const x = value => (mobile ? 54 : 74) + value * (mobile ? 346 : 884), y = value => (mobile ? 260 : 336) - value * (mobile ? 222 : 298);
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
  function render() { renderMetrics(); renderChart(); renderComparison(); renderStages(); renderExport(); }
  async function load() {
    $('load-error').hidden = true; $('workbench-content').hidden = true; $('load-status').hidden = false;
    try {
      const response = await fetch('/assets/chain-workbench-summary.json', {cache: 'no-store'});
      if (!response.ok) throw new Error(response.status === 404 ? '尚未发布本轮公开汇总，现有链路与参考链页面仍可访问。' : `汇总读取失败（HTTP ${response.status}）。`);
      const report = await response.json();
      if (report.schema_version !== 'chain-workbench-v2-report' || !Array.isArray(report.cases) || !report.cases.length) throw new Error('汇总格式不匹配，或尚无已完成的实验案例。');
      if (report.cases.some(item => !Array.isArray(item.variants) || !item.variants.length || item.variants.some(v => !Array.isArray(v.rows) || !v.rows.length))) throw new Error('汇总包含没有结果行的实验范围，请完成对应实验后再发布。');
      state.report = report; state.caseIndex = 0; state.catalog = null;
      try {
        const catalogResponse = await fetch('/assets/retained-chain-catalog.json', {cache: 'no-store'});
        if (catalogResponse.ok) { const catalog = await catalogResponse.json(); if (Array.isArray(catalog.entries)) state.catalog = catalog.entries; }
      } catch (_) { /* Aggregate comparisons remain usable without local exports. */ }
      options('case-select', report.cases.map((_, i) => i), 0, i => report.cases[i].label || report.cases[i].id);
      selectVariant(); renderReadiness(); $('workbench-content').hidden = false; $('load-status').hidden = true;
    } catch (error) { $('load-status').hidden = true; $('load-error').hidden = false; $('load-error-detail').textContent = error.message; }
  }
  $('case-select').addEventListener('change', event => { state.caseIndex = Number(event.target.value); selectVariant(); });
  $('track-select').addEventListener('change', event => { state.track = event.target.value; selectVariant(); });
  $('poi-select').addEventListener('change', event => { state.poi = event.target.value; selectMethod(); });
  $('method-select').addEventListener('change', event => { state.method = event.target.value; selectMethod(); });
  $('budget-select').addEventListener('change', event => { state.budget = Number(event.target.value); render(); });
  $('reload-button').addEventListener('click', load);
  window.addEventListener('resize', () => { if (state.report) renderChart(); });
  load();
})();
