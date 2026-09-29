/* Fixed reports only: this view never chooses reference paths or changes scores. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const COLORS = ['#087f79', '#bd7942', '#687bad', '#b05f83', '#779649', '#716582', '#3b98ae'];
  const METHODS = {adaptive: '自适应融合', baseline: '原方法', chain_only: '仅完整路径束', rarity: '仅稀有度', rarity_only: '仅稀有度', diffusion: '仅图扩散', diffusion_only: '仅图扩散', rasp: '原 RASP', rasp_d0: '原 RASP-D', contextual: '上下文融合', contextual_adaptive: '上下文自适应融合', contextual_chain: '上下文融合 + 整链选择', adaptive_chain: '自适应整链剪枝', raw_rarity: '原始稀有度'};
  const STAGES = {reference: '固定参考', source: '源日志可见', database: '数据库可见', scope: '调查范围', candidate: '候选覆盖', witness: '时序见证', budget: '预算可行', retained: '最终保留', final: '最终保留', scored: '评分覆盖', available: '源日志可见', invalid_reference: '源参考无效', scoring: '评分覆盖', selected: '最终保留', witnessable: '时序见证可用', temporal_eligible: '时序见证覆盖', bundle_eligible: '完整路径束可用'};
  const state = {report: null, caseIndex: 0, method: '', point: 0, chainId: null, eventPage: 0, branch: 'all'};
  const PAGE_SIZE = 40;
  const identity = value => String(value).trim().toUpperCase();
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const pct = value => finite(value) ? `${(value * 100).toFixed(1)}%` : 'N/A';
  const number = value => finite(value) ? value.toLocaleString('zh-CN') : 'N/A';
  const metric = value => value && typeof value === 'object' ? value : {};
  const ratio = value => {
    const item = metric(value);
    return finite(item.denominator) && item.denominator > 0 && finite(item.numerator)
      ? `${number(item.numerator)} / ${number(item.denominator)}` : 'N/A';
  };
  const jsonText = value => JSON.stringify(value ?? {}, null, 2);
  const description = value => typeof value === 'string' ? value : jsonText(value);
  const methodName = name => METHODS[name] || String(name);
  const stageName = name => STAGES[name] || String(name);
  const el = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined && text !== null) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  };
  const svg = (tag, attrs = {}, text) => {
    const element = document.createElementNS(SVG_NS, tag);
    Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, String(value)));
    if (text !== undefined) element.textContent = String(text);
    return element;
  };
  const currentCase = () => state.report.cases[state.caseIndex];
  const methods = () => [...new Set((currentCase().results || []).map(row => row.method))];
  const methodRows = () => (currentCase().results || []).filter(row => row.method === state.method).sort((a, b) => a.budget_ratio - b.budget_ratio);
  const currentRow = () => methodRows()[state.point] || methodRows()[0] || {};
  const evaluation = () => currentRow().chain_evaluation || {};
  const setOptions = (select, rows, value) => {
    select.replaceChildren(...rows.map(([key, label]) => {
      const option = el('option', label);
      option.value = String(key);
      return option;
    }));
    if (value !== undefined) select.value = String(value);
  };
  function selectCase(index) {
    state.caseIndex = index;
    state.chainId = null;
    state.branch = 'all';
    const names = methods();
    state.method = names.includes(state.method) ? state.method : names.find(name => /adaptive|contextual/.test(name)) || names[0] || '';
    setOptions($('method-select'), names.map(name => [name, methodName(name)]), state.method);
    const rows = methodRows();
    const preferred = rows.findIndex(row => row.budget_ratio === 0.2);
    state.point = preferred >= 0 ? preferred : 0;
    $('case-note').textContent = `${currentCase().kind === 'synthetic' ? '合成场景，用于方法契约验证' : '真实日志场景'} · ${description(currentCase().reference_scope || '参考范围由报告声明')}`;
    $('case-kind').textContent = currentCase().kind === 'synthetic' ? '合成参考 · 与真实实验分列' : '真实日志 · 固定参考';
    $('provenance-json').textContent = jsonText(currentCase().source_provenance);
    render();
  }
  function render() {
    const rows = methodRows();
    state.point = Math.min(state.point, Math.max(0, rows.length - 1));
    state.eventPage = 0;
    setOptions($('budget-select'), rows.map((row, index) => [index, `预算 ${pct(row.budget_ratio)} · 实际压缩 ${pct(row.actual_compression)}`]), state.point);
    renderMetrics();
    renderChart();
    renderStages();
    renderChains();
  }
  function renderMetrics() {
    const row = currentRow(), count = currentCase().candidate_edges;
    const cards = [
      ['candidate', '候选原始事件', number(count), '压缩率的固定分母', ''],
      ['retained', '实际保留事件', number(row.retained_edges), `预算上限 ${number(row.budget_edges)} 条`, ''],
      ['compression', '实际事件压缩率', pct(row.actual_compression), '1 − 保留事件 / 候选事件', 'primary'],
      ['complete', '完整参考链', ratio(row.complete_reference_retention), `保留率 ${pct(metric(row.complete_reference_retention).value)}`, 'primary'],
      ['coverage', '候选整链覆盖上限', pct(metric(row.candidate_chain_coverage).value), `覆盖 ${ratio(row.candidate_chain_coverage)} 条参考链`, ''],
      ['verified', '已核验完整攻击链', ratio(row.verified_attack_chain_retention), finite(metric(row.verified_attack_chain_retention).value) ? `保留率 ${pct(row.verified_attack_chain_retention.value)}` : '缺独立完整链真值，暂不定义', 'verified'],
    ];
    $('metrics').replaceChildren(...cards.map(([id, title, value, note, cls]) => {
      const card = el('article', null, `metric ${cls}`);
      card.id = `metric-${id}`;
      card.append(el('p', title, 'metric-label'), el('p', value, 'metric-value'), el('p', note, 'metric-note'));
      return card;
    }));
  }
  function renderChart() {
    const chart = $('retention-chart');
    chart.replaceChildren(svg('desc', {id: 'chart-description'}, '横轴：实际事件压缩率；纵轴：完整参考链保留率。预算按钮提供各点的精确数值。'));
    const left = 75, right = 950, top = 25, bottom = 350;
    const x = value => left + value * (right - left), y = value => bottom - value * (bottom - top);
    for (let step = 0; step <= 5; step++) {
      const value = step / 5;
      chart.append(svg('line', {x1: left, x2: right, y1: y(value), y2: y(value), stroke: '#e5ece7'}));
      chart.append(svg('text', {x: left - 13, y: y(value) + 4, 'text-anchor': 'end', class: 'axis-text'}, `${step * 20}%`));
      chart.append(svg('text', {x: x(value), y: bottom + 27, 'text-anchor': 'middle', class: 'axis-text'}, `${step * 20}%`));
    }
    chart.append(svg('line', {x1: left, x2: right, y1: bottom, y2: bottom, stroke: '#9eb5ac'}));
    chart.append(svg('text', {x: (left + right) / 2, y: 409, 'text-anchor': 'middle', class: 'axis-title'}, '实际事件压缩率 →'));
    chart.append(svg('text', {x: 20, y: (top + bottom) / 2, transform: `rotate(-90,20,${(top + bottom) / 2})`, 'text-anchor': 'middle', class: 'axis-title'}, '完整参考链保留率'));
    const cap = metric(currentRow().candidate_chain_coverage).value;
    if (finite(cap)) chart.append(svg('line', {x1: left, x2: right, y1: y(cap), y2: y(cap), stroke: '#536b61', 'stroke-dasharray': '7 5', 'stroke-width': 1.3}));
    const names = methods();
    $('chart-legend').replaceChildren(...names.map((name, index) => {
      const legend = el('span', null, name === state.method ? 'selected' : '');
      const swatch = el('i');
      swatch.style.setProperty('--legend-color', COLORS[index % COLORS.length]);
      legend.append(swatch, document.createTextNode(methodName(name)));
      return legend;
    }), el('span', '┄ 候选整链覆盖上限'));
    let validCount = 0;
    names.forEach((name, index) => {
      const color = COLORS[index % COLORS.length];
      const points = (currentCase().results || []).filter(row => row.method === name && finite(row.actual_compression) && finite(metric(row.complete_reference_retention).value)).sort((a, b) => a.actual_compression - b.actual_compression);
      validCount += points.length;
      const selected = name === state.method;
      if (points.length > 1) chart.append(svg('polyline', {points: points.map(row => `${x(row.actual_compression)},${y(row.complete_reference_retention.value)}`).join(' '), fill: 'none', stroke: color, 'stroke-width': selected ? 3 : 1.7, opacity: selected ? 1 : 0.55}));
      points.forEach(row => {
        const active = selected && row === currentRow();
        const point = svg('circle', {cx: x(row.actual_compression), cy: y(row.complete_reference_retention.value), r: active ? 7 : 4, fill: active ? color : '#fff', stroke: color, 'stroke-width': active ? 3 : 2, cursor: 'pointer'});
        point.append(svg('title', {}, `${methodName(name)}，预算 ${pct(row.budget_ratio)}，实际压缩 ${pct(row.actual_compression)}，完整参考链 ${ratio(row.complete_reference_retention)}`));
        point.addEventListener('click', () => {
          state.method = name;
          $('method-select').value = name;
          state.point = methodRows().indexOf(row);
          render();
        });
        chart.append(point);
      });
    });
    if (!validCount) chart.append(svg('text', {x: 510, y: 185, 'text-anchor': 'middle', class: 'axis-title'}, '没有可计算的完整参考链指标；不将 N/A 绘制为零。'));
    $('chart-note').textContent = `当前方法：${methodName(state.method)}。候选覆盖上限 ${pct(cap)}；参考事件保留 ${ratio(currentRow().positive_event_retention)}。已核验完整攻击链指标独立展示。`;
    $('point-buttons').replaceChildren(...methodRows().map((row, index) => {
      const button = el('button', null, index === state.point ? 'active' : '');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(index === state.point));
      button.append(el('strong', `预算 ${pct(row.budget_ratio)}`), document.createTextNode(`压缩 ${pct(row.actual_compression)} · 完整链 ${ratio(row.complete_reference_retention)}`));
      button.addEventListener('click', () => { state.point = index; render(); });
      return button;
    }));
  }
  function renderStages() {
    const data = evaluation(), funnel = data.event_funnel || {}, stages = data.stage_order || Object.keys(data.stages || {});
    $('stage-rows').replaceChildren(...stages.map(name => {
      const chain = data.stages?.[name] || {}, event = funnel.stages?.[name] || {};
      const row = el('tr');
      const chainCount = ratio(chain.reference_chain_retention);
      const eventCount = ratio(event.total_retention);
      [stageName(name), chainCount !== 'N/A' ? chainCount : number(chain.reference_chain_count), number(data.first_loss_counts?.[name]), eventCount !== 'N/A' ? eventCount : number(event.retained_event_count), number(funnel.first_loss_counts?.[name]), pct(metric(event.conditional_retention).value)].forEach(value => row.append(el('td', value)));
      return row;
    }));
    if (!stages.length) {
      const row = el('tr'), cell = el('td', '此结果未提供分阶段诊断。');
      cell.colSpan = 6; row.append(cell); $('stage-rows').append(row);
    }
    $('stage-note').textContent = '分母与阶段状态使用评估器的固定参考。搜索未完成、源记录缺失或标注范围不完整时，不能据此证明全局攻击链完整。';
    $('diagnostic-json').textContent = jsonText({diagnostics: currentRow().diagnostics || {}, first_loss_counts: data.first_loss_counts || {}, event_first_loss_counts: funnel.first_loss_counts || {}});
  }
  function chainEvaluation(chain) { return (evaluation().chains || []).find(item => item.id === chain.id) || {}; }
  function requiredIds(chain) {
    const item = chainEvaluation(chain);
    if (Array.isArray(item.required_event_ids)) return item.required_event_ids;
    const ids = [...(chain.event_ids || []), ...(chain.required_event_ids || [])];
    for (const branch of chain.branches || []) ids.push(...(Array.isArray(branch) ? branch : branch.event_ids || []));
    return [...new Set(ids.map(identity))];
  }
  function chainStatus(chain) {
    const item = chainEvaluation(chain), stages = evaluation().stage_order || [];
    const finalName = stages[stages.length - 1];
    const final = item.stages?.[finalName] || item.stages?.retained || item.stages?.final;
    if (final && typeof final.complete === 'boolean') return final.complete;
    const ids = requiredIds(chain);
    const kept = new Set((currentRow().retained_event_ids || []).map(identity));
    return ids.length > 0 && ids.every(id => kept.has(identity(id)));
  }
  function chainTitle(chain) {
    if (chain.title && chain.title !== chain.id) return chain.title;
    const events = chain.events || [], ids = chain.event_ids || [];
    const first = events.find(event => identity(event.event_id) === identity(ids[0])) || events[0];
    const last = events.find(event => identity(event.event_id) === identity(ids[ids.length - 1])) || events[events.length - 1];
    if (!first || !last) return chain.title || chain.id;
    const reversed = event => event.causal_direction === 'dst_to_src' || String(event.relation).toUpperCase() === 'EVENT_EXECUTE';
    const start = reversed(first) ? first.dst_label || first.dst : first.src_label || first.src;
    const end = reversed(last) ? last.src_label || last.src : last.dst_label || last.dst;
    const ordinal = (currentCase().reference_chains || []).findIndex(item => item.id === chain.id) + 1;
    return `参考链 ${String(ordinal).padStart(3, '0')} · ${start} → ${end}`;
  }
  function renderChains() {
    const aggregate = state.report.data_visibility === 'aggregate_only';
    $('chain-layout').classList.toggle('summary-only', aggregate);
    $('chain-filter').disabled = aggregate;
    $('chain-filter').parentElement.hidden = aggregate;
    if (aggregate) {
      state.chainId = null;
      const count = currentCase().reference_chain_count;
      const countText = finite(count) ? `${number(count)} 条固定参考链参与统计` : '固定参考链已参与汇总统计';
      $('chain-list').replaceChildren(el('p', `${countText}；汇总文件不包含逐事件内容。请在本机生成详细报告，查看完整或断裂的参考链及原始事件。`, 'no-data'));
      $('chain-events').replaceChildren();
      $('chain-detail').hidden = true;
      return;
    }
    const filter = $('chain-filter').value;
    const chains = (currentCase().reference_chains || []).filter(chain => filter === 'all' || (filter === 'complete' ? chainStatus(chain) : !chainStatus(chain)));
    if (!chains.some(chain => chain.id === state.chainId)) { state.chainId = chains[0]?.id ?? null; state.branch = 'all'; }
    $('chain-list').replaceChildren(...chains.map(chain => {
      const complete = chainStatus(chain), item = chainEvaluation(chain);
      const button = el('button', null, chain.id === state.chainId ? 'active' : '');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(chain.id === state.chainId));
      button.append(el('strong', chainTitle(chain)), el('span', `${complete ? '● 完整保留' : '◌ 断裂 / 不完整'} · ${requiredIds(chain).length} 个必需事件`));
      if (item.first_loss_stage) button.append(el('span', `首次损失：${stageName(item.first_loss_stage)}`));
      button.addEventListener('click', () => { state.chainId = chain.id; state.eventPage = 0; state.branch = 'all'; renderChains(); });
      return button;
    }));
    $('chain-detail').hidden = !chains.length;
    if (!chains.length) $('chain-list').append(el('p', '没有符合筛选条件的参考链。', 'no-data'));
    else renderChainDetail(chains.find(chain => chain.id === state.chainId));
  }
  function evidenceDetails(evidence) {
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence) || !Object.keys(evidence).length) return null;
    const score = value => finite(value) ? value.toLocaleString('zh-CN', {maximumFractionDigits: 4}) : 'N/A';
    const detail = el('details', null, 'event-evidence');
    detail.append(el('summary', `评分依据 · 稀有 ${score(evidence.raw_rarity)} · 异常 ${score(evidence.anomaly_score)} · 历史置信 ${score(evidence.confidence)}`));
    detail.append(el('p', '少见 ≠ 异常；置信度反映历史支持，评分不是恶意概率。', 'evidence-note'));
    const fields = [
      ['raw_rarity', '原始稀有度'], ['novelty', '行为新颖度'],
      ['contextual_surprise', '上下文偏离'], ['confidence', '历史置信度'],
      ['anomaly_score', '上下文异常分'], ['score_rasp', '原 RASP 分'],
      ['score_contextual', '上下文融合分'],
    ];
    const grid = el('dl', null, 'evidence-grid');
    fields.forEach(([key, label]) => {
      if (Object.prototype.hasOwnProperty.call(evidence, key)) {
        const field = el('div'); field.append(el('dt', label), el('dd', score(evidence[key]))); grid.append(field);
      }
    });
    detail.append(grid);
    if (evidence.reason !== undefined && evidence.reason !== null) {
      const reasons = {
        unseen_context_no_historical_support: '行为上下文未见过，缺少历史支持',
        unseen_pattern_in_supported_context: '已有历史上下文，但当前行为模式未出现过',
        new_resource_matches_historical_semantic_pattern: '资源名称首次出现，但行为语义符合历史模式',
        observed_pattern_scored_against_historical_context: '已知行为模式，按其历史上下文评估偏离',
      };
      const reason = typeof evidence.reason === 'string' ? reasons[evidence.reason] || evidence.reason : description(evidence.reason);
      detail.append(el('p', `判定依据：${reason}`, 'evidence-note'));
    }
    return detail;
  }
  function renderChainDetail(chain) {
    if (!chain) return;
    const item = chainEvaluation(chain), complete = chainStatus(chain);
    $('selected-chain-title').textContent = chainTitle(chain);
    $('chain-status').textContent = `${complete ? '当前预算完整保留此参考链' : '当前预算未完整保留此参考链'}${item.first_loss_stage ? ` · 首次损失：${stageName(item.first_loss_stage)}` : ''}`;
    const kind = {derived_reference: '自动派生参考链，不是独立核验的完整攻击链。', synthetic: '合成参考链，用于验证方法行为，不作为真实攻击成果。', independent_review: '独立核验参考；完整范围与审核状态仍以报告声明为准。'}[chain.kind || chain.provenance?.kind || item.provenance?.kind] || '参考类型未声明，不推断其攻击真值状态。';
    $('chain-scope').textContent = `${kind} 参考 ID：${chain.id}`;
    $('chain-validation').textContent = jsonText(item);
    const branches = [];
    const primary = chain.event_ids || item.event_ids || [];
    if (primary.length) branches.push(primary);
    for (const branch of chain.branches || item.branches || []) {
      const ids = Array.isArray(branch) ? branch : branch.event_ids || [];
      if (!branches.some(existing => existing.length === ids.length && existing.every((id, index) => identity(id) === identity(ids[index])))) branches.push(ids);
    }
    const covered = new Set(branches.flat().map(identity));
    for (const id of requiredIds(chain)) {
      // An additional required event is independent unless a source witness declares its sequence.
      if (!covered.has(identity(id))) { branches.push([id]); covered.add(identity(id)); }
    }
    if (!branches.length) branches.push([]);
    $('branch-control').hidden = branches.length < 2;
    setOptions($('branch-select'), [['all', '全部分支'], ...branches.map((_, index) => [index, `分支 ${index + 1}`])], state.branch);
    const byId = new Map((chain.events || []).map(event => [identity(event.event_id), event]));
    let events = [];
    branches.forEach((branch, index) => {
      if (state.branch !== 'all' && String(index) !== state.branch) return;
      const ids = Array.isArray(branch) ? branch : branch.event_ids || [];
      events.push(...ids.map((id, order) => ({id: String(id), branch: index, order, event: byId.get(identity(id))})));
    });
    const kept = new Set((currentRow().retained_event_ids || []).map(identity));
    const totalPages = Math.max(1, Math.ceil(events.length / PAGE_SIZE));
    state.eventPage = Math.min(state.eventPage, totalPages - 1);
    const visible = events.slice(state.eventPage * PAGE_SIZE, (state.eventPage + 1) * PAGE_SIZE);
    $('chain-events').replaceChildren();
    let previousBranch = null;
    visible.forEach(({id, branch, order, event}) => {
      if (branches.length > 1 && previousBranch !== branch) $('chain-events').append(el('h4', `分支 ${branch + 1}`, 'branch-heading'));
      previousBranch = branch;
      const missing = !kept.has(identity(id));
      const row = el('section', null, `event-row${missing ? ' missing' : ''}`);
      row.dataset.eventId = id;
      const meta = el('div', null, 'event-meta');
      const stamp = event?.timestamp_ns;
      const timestamp = el('time', stamp === undefined || stamp === null ? '时间未提供' : `时间戳（ns） ${String(stamp)}`);
      if (typeof stamp === 'number' && !Number.isSafeInteger(stamp)) timestamp.textContent = '时间戳以不安全数值提供，无法展示精确纳秒；请重新生成字符串格式报告。';
      meta.append(el('span', `事件 ${order + 1} · ${missing ? '缺失' : '保留'}`, 'event-state'), timestamp);
      const flow = el('div', null, 'event-flow');
      const reverse = event?.causal_direction === 'dst_to_src' || String(event?.relation || '').toUpperCase() === 'EVENT_EXECUTE';
      const sourceSide = reverse ? 'dst' : 'src', targetSide = reverse ? 'src' : 'dst';
      row.dataset.causalDirection = reverse ? 'dst_to_src' : 'src_to_dst';
      const source = el('div', event?.[`${sourceSide}_label`] || event?.[sourceSide] || '源记录不可用', 'event-node');
      source.append(el('code', event?.[sourceSide] || '—'));
      const target = el('div', event?.[`${targetSide}_label`] || event?.[targetSide] || '目标记录不可用', 'event-node');
      target.append(el('code', event?.[targetSide] || '—'));
      const arrow = el('div', event?.relation || '原始关系未知', 'event-arrow');
      const line = el('div', null, 'arrow-line'); line.setAttribute('aria-hidden', 'true'); arrow.append(line);
      flow.append(source, arrow, target);
      row.append(meta, flow, el('code', `原始事件 ID · ${id}`, 'event-id'));
      if (reverse) row.append(el('p', `执行依赖方向：目标 → 源。原始记录：${event.src_label || event.src} → ${event.dst_label || event.dst}。`, 'event-causality'));
      const evidence = evidenceDetails(event?.evidence);
      if (evidence) row.append(evidence);
      $('chain-events').append(row);
    });
    if (!visible.length) $('chain-events').append(el('p', '此参考没有可展示的原始事件序列。', 'no-data'));
    $('event-page-note').textContent = `${number(events.length)} 个分支事件位置 · 第 ${state.eventPage + 1} / ${totalPages} 页`;
    $('event-prev').disabled = state.eventPage === 0;
    $('event-next').disabled = state.eventPage + 1 >= totalPages;
  }
  async function load() {
    $('load-error').hidden = true;
    $('load-status').hidden = false;
    $('study-content').hidden = true;
    $('aggregate-notice').hidden = true;
    try {
      let reportPath = '/assets/chain-study-results.json';
      let response = await fetch(reportPath, {cache: 'no-store'});
      if (response.status === 404) {
        reportPath = '/assets/chain-study-summary.json';
        response = await fetch(reportPath, {cache: 'no-store'});
      }
      if (!response.ok) throw new Error(`报告请求返回 HTTP ${response.status}`);
      const report = await response.json();
      if (report.schema_version !== 'adaptive-chain-study-v1' || !Array.isArray(report.cases) || !report.cases.length) throw new Error('报告格式不匹配或没有实验案例。');
      state.report = report;
      const aggregate = report.data_visibility === 'aggregate_only';
      $('aggregate-notice').hidden = !aggregate;
      $('download-report').href = reportPath;
      $('download-report').textContent = aggregate ? '下载汇总结果 JSON ↓' : '下载完整结果 JSON ↓';
      setOptions($('case-select'), report.cases.map((item, index) => [index, `${item.label || item.id}${item.kind === 'synthetic' ? ' · 合成' : ''}`]), 0);
      $('methodology-json').textContent = jsonText(report.methodology);
      $('report-meta').textContent = `报告生成时间 ${report.generated_at || '未提供'} · ${report.schema_version} · 固定原始事件与参考分母`;
      selectCase(0);
      $('study-content').hidden = false;
    } catch (error) {
      $('load-error-detail').textContent = error.message;
      $('load-error').hidden = false;
    } finally {
      $('load-status').hidden = true;
    }
  }
  $('case-select').addEventListener('change', event => selectCase(Number(event.target.value)));
  $('method-select').addEventListener('change', event => { state.method = event.target.value; render(); });
  $('budget-select').addEventListener('change', event => { state.point = Number(event.target.value); render(); });
  $('chain-filter').addEventListener('change', () => { state.eventPage = 0; renderChains(); });
  $('branch-select').addEventListener('change', event => { state.branch = event.target.value; state.eventPage = 0; renderChainDetail(currentCase().reference_chains.find(chain => chain.id === state.chainId)); });
  $('event-prev').addEventListener('click', () => { state.eventPage--; renderChainDetail(currentCase().reference_chains.find(chain => chain.id === state.chainId)); });
  $('event-next').addEventListener('click', () => { state.eventPage++; renderChainDetail(currentCase().reference_chains.find(chain => chain.id === state.chainId)); });
  $('reload-button').addEventListener('click', load);
  load();
})();
