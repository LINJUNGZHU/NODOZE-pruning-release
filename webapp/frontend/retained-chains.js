(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const LIST_PAGE = 20, DETAIL_PAGE = 40, EVENT_PAGE = 50;
  const state = {entries: [], artifact: null, selected: null, listPage: 0, detailPage: 0, eventPage: 0, search: [], pathSearch: new Map(), related: new Map(), poiRoles: null, audit: null, auditSelected: null, auditListPage: 0, auditEventPage: 0, request: 0};
  const text = value => value == null ? '' : String(value);
  const identity = value => text(value).trim().toUpperCase();
  const number = value => Number.isFinite(value) ? value.toLocaleString('en-US') : 'N/A';
  const el = (tag, value, className) => { const node = document.createElement(tag); if (value != null) node.textContent = text(value); if (className) node.className = className; return node; };
  const source = event => event.causal_direction === 'dst_to_src' ? 'dst' : 'src';
  const target = event => event.causal_direction === 'dst_to_src' ? 'src' : 'dst';
  const label = (event, side) => text(event[side + '_semantic'] || event[side + '_label'] || event[side]);
  const eventText = event => [event.event_id, event.src, event.dst, label(event, 'src'), label(event, 'dst'), event.relation, event.host, event.timestamp_ns].map(text).join(' ').toLowerCase();
  const allItems = () => $('collection-select').value === 'bundles' ? state.artifact.observed_bundles : state.artifact.paths;
  const isBundle = () => $('collection-select').value === 'bundles';
  const token = item => `${isBundle() ? 'b' : 'p'}:${item.id}`;
  const filteredItems = () => { const q = $('path-search').value.trim().toLowerCase(); return allItems().filter(item => !q || state.pathSearch.get(token(item)).includes(q)); };
  const filteredEvents = () => { const q = $('event-search').value.trim().toLowerCase(); return state.artifact.events.filter((_, i) => !q || state.search[i].includes(q)); };
  function poiLabel(event) {
    const roles = state.poiRoles;
    if (!roles) return event.is_declared_poi ? '声明 POI' : null;
    const original = roles.original.has(identity(event.event_id)), suggested = roles.suggested.has(identity(event.event_id));
    if (original && suggested) return '原始输入 POI / 算法建议（未核验）';
    if (original) return event.is_declared_poi ? '原始输入 POI' : '原始输入 POI（非本次起点）';
    if (suggested) return '算法建议 POI · 未核验';
    return event.is_declared_poi ? '本次起点 · 来源未声明' : null;
  }
  function safeURL(value) {
    if (typeof value !== 'string' || !value.trim()) return null;
    const url = new URL(value, window.location.href);
    return url.origin === location.origin && ['http:', 'https:'].includes(url.protocol) ? url.href : null;
  }
  function validate(data) {
    if (data?.schema_version !== 'retained-chain-export-v1' || !Array.isArray(data.events) || !Array.isArray(data.paths) || !Array.isArray(data.observed_bundles)) throw new Error('导出格式不匹配。请使用当前版本重新导出。');
    if (data.retained_edges !== data.events.length) throw new Error('保留计数与实际事件数量不一致。');
    const ids = new Set();
    for (const event of data.events) {
      if (!event.event_id || ids.has(event.event_id) || typeof event.timestamp_ns !== 'string' || !/^-?\d+$/.test(event.timestamp_ns)) throw new Error('事件 ID 或精确时间戳格式不正确。');
      if (!['src_to_dst', 'dst_to_src'].includes(event.causal_direction)) throw new Error('事件缺少明确的因果方向。');
      ids.add(event.event_id);
    }
    const coverage = new Set();
    for (const [group, items] of [['paths', data.paths], ['bundles', data.observed_bundles]]) {
      const itemIds = new Set();
      for (const item of items) {
        if (!item.id || itemIds.has(item.id) || !Array.isArray(item.event_indices) || !item.event_indices.length) throw new Error('路径或见证标识与成员格式不正确。');
        itemIds.add(item.id);
        for (const i of item.event_indices) {
          if (!Number.isInteger(i) || i < 0 || i >= data.events.length) throw new Error('路径指向不存在的事件。');
          if (group === 'paths') { if (coverage.has(i)) throw new Error('时序路径重复覆盖事件。'); coverage.add(i); }
        }
        if (group === 'bundles') for (const branch of item.paths || []) {
          if (!Array.isArray(branch) || branch.some(i => !item.event_indices.includes(i))) throw new Error('见证分支超出其事件范围。');
        }
      }
    }
    if (coverage.size !== data.events.length) throw new Error('时序路径未覆盖全部保留事件。');
    return data;
  }
  function indexArtifact() {
    state.search = state.artifact.events.map(eventText);
    state.poiRoles = state.artifact.poi_roles ? {
      original: new Set((state.artifact.poi_roles.original_declared_event_ids || []).map(identity)),
      suggested: new Set((state.artifact.poi_roles.suggested_event_ids || []).map(identity))
    } : null;
    state.pathSearch = new Map(); state.related = new Map();
    for (const [prefix, items] of [['p', state.artifact.paths], ['b', state.artifact.observed_bundles]]) {
      for (const item of items) state.pathSearch.set(`${prefix}:${item.id}`, [item.id, ...item.event_indices.map(i => state.search[i])].join(' ').toLowerCase());
    }
    state.artifact.paths.forEach((path, index) => {
      const nodes = new Set(path.event_indices.flatMap(i => { const event = state.artifact.events[i]; return [JSON.stringify([event.host, event.src]), JSON.stringify([event.host, event.dst])]; }));
      for (const node of nodes) { if (!state.related.has(node)) state.related.set(node, new Set()); state.related.get(node).add(index); }
    });
  }
  function pagination(prefix, count, size, page) {
    const pages = Math.ceil(count / size);
    $(prefix + '-page-note').textContent = count ? `${number(count)} 项 · 第 ${page + 1} / ${pages} 页` : '0 项';
    $(prefix + '-prev').disabled = page <= 0;
    $(prefix + '-next').disabled = (page + 1) * size >= count;
  }
  function renderMetrics() {
    const data = state.artifact, singleton = data.paths.filter(path => path.event_indices.length === 1).length;
    const metrics = [
      ['retained', '实际保留事件', data.events.length, '冻结候选条目去重后的精确并集'],
      ['candidate', '候选事件条目', data.candidate_edges, `保留预算上限 ${number(data.budget_edges)}`],
      ['compression', '实际压缩率', Number.isFinite(data.actual_compression) ? `${(data.actual_compression * 100).toFixed(2)}%` : 'N/A', '相对当前候选事件范围'],
      ['pois', state.poiRoles ? '本次调查起点事件' : '保留的声明 POI 事件', data.events.filter(event => event.is_declared_poi).length, state.poiRoles ? '原始输入与算法建议按角色单独标明' : '只统计导出中显式声明的 POI'],
      ['paths', '多事件时序路径', data.paths.length - singleton, '至少 2 个事件；严格时间连续'],
      ['singletons', '单事件路径', singleton, '没有因分解成单事件而隐藏'],
      ['witnesses', '已保留调查见证', data.observed_bundles.length, '可重叠；不等于独立攻击数'],
      ['allpaths', '覆盖全部事件的路径', data.paths.length, '多事件路径 + 单事件路径'],
    ];
    $('metrics').replaceChildren(...metrics.map(([id, name, value, note]) => {
      const card = el('article', null, 'metric'); card.id = 'metric-' + id;
      card.append(el('p', name, 'metric-label'), el('p', typeof value === 'number' ? number(value) : value, 'metric-value'), el('p', note, 'metric-note'));
      return card;
    }));
    $('result-note').textContent = `案例 ${text(data.case_id)} · 方法 ${text(data.method)} · 时间戳单位 ns · 所有条目均来自当前冻结保留决策`;
    const lineageEvents = data.events.filter(event => identity(event.event_id).includes('LINEAGE')).length;
    if (lineageEvents) $('result-note').textContent += ` 其中 ${number(lineageEvents)} 条是 LINEAGE 派生关系，计入冻结候选条目，不作为独立原始审计事件。`;
    const {events, nodes, paths, observed_bundles, ...metadata} = data;
    $('scope-json').textContent = JSON.stringify(metadata, null, 2);
  }
  function renderList() {
    const items = filteredItems();
    state.listPage = Math.min(state.listPage, Math.max(0, Math.ceil(items.length / LIST_PAGE) - 1));
    if (!items.some(item => item.id === state.selected)) { state.selected = items[0]?.id ?? null; state.detailPage = 0; }
    $('path-list').replaceChildren(...items.slice(state.listPage * LIST_PAGE, (state.listPage + 1) * LIST_PAGE).map(item => {
      const button = el('button', null, item.id === state.selected ? 'active' : ''); button.type = 'button';
      button.setAttribute('aria-pressed', String(item.id === state.selected));
      button.append(el('strong', item.id), el('span', `${number(item.event_indices.length)} 个事件 · ${isBundle() ? '调查见证' : item.event_indices.length === 1 ? '单事件路径' : '严格时序路径'}`));
      button.addEventListener('click', () => { state.selected = item.id; state.detailPage = 0; renderList(); });
      return button;
    }));
    if (!items.length) $('path-list').append(el('p', isBundle() ? '当前导出没有匹配的调查见证。全部保留事件仍可在下表查看。' : '没有匹配的时序路径。', 'no-data'));
    $('path-detail').hidden = !items.length;
    pagination('paths', items.length, LIST_PAGE, state.listPage);
    if (items.length) renderDetail(items.find(item => item.id === state.selected));
  }
  function renderRelated(item) {
    const indices = new Set();
    for (const i of item.event_indices) {
      const event = state.artifact.events[i];
      for (const node of [event.src, event.dst]) for (const p of state.related.get(JSON.stringify([event.host, node])) || []) indices.add(p);
    }
    const paths = [...indices].map(i => state.artifact.paths[i]).filter(path => isBundle() || path.id !== item.id);
    $('related-section').hidden = !paths.length;
    $('related-paths').replaceChildren(...paths.slice(0, 8).map(path => {
      const button = el('button', `${path.id} · ${path.event_indices.length} 事件`); button.type = 'button';
      button.addEventListener('click', () => {
        $('collection-select').value = 'paths'; $('path-search').value = ''; state.selected = path.id; state.detailPage = 0;
        state.listPage = Math.floor(state.artifact.paths.indexOf(path) / LIST_PAGE); renderList();
      });
      return button;
    }));
    if (paths.length > 8) $('related-paths').append(el('span', `另有 ${paths.length - 8} 条，可检索共享实体查看。`, 'hint'));
  }
  function eventCard(event) {
    const card = el('div', null, 'event-card'), meta = el('div', null, 'event-meta'); card.dataset.eventId = event.event_id;
    meta.append(el('span', `事件 ${event.event_id}`), poiLabel(event) ? el('span', poiLabel(event), 'poi') : el('span', `主机 ${text(event.host) || '未提供'}`));
    const flow = el('div', null, 'flow');
    const node = side => { const block = el('div', label(event, side), 'flow-node'); block.append(el('code', `${text(event[side + '_type'])} · ${text(event[side])}`)); return block; };
    const arrow = el('div', event.relation, 'flow-arrow'); arrow.append(el('span', '→', 'arrow'));
    flow.append(node(source(event)), arrow, node(target(event)));
    card.append(meta, flow, el('p', `${event.timestamp_ns} ns`, 'event-time'));
    if (event.causal_direction === 'dst_to_src') card.append(el('p', `因果方向：原始目标 → 源；原始记录：${text(event.src)} → ${text(event.dst)}`, 'hint'));
    if (text(event.event_id).toUpperCase().includes('LINEAGE')) card.append(el('p', 'LINEAGE 派生关系：不是独立原始审计事件。', 'lineage-note'));
    return card;
  }
  function renderDetail(item) {
    const bundle = isBundle();
    $('path-title').textContent = item.id;
    $('path-status').textContent = bundle
      ? `${item.event_indices.length} 个去重保留事件 · ${item.complete_in_candidate === true ? '候选内见证完整' : '候选内仍不完整 / 范围未证实'} · 边界状态 ${text(item.boundary_status) || '未提供'} · 仅为观测调查见证`
      : `${item.event_indices.length === 1 ? '单事件路径' : '严格时序路径'} · ${item.event_indices.length} 个保留事件 · 覆盖分解之一，不代表独立攻击`;
    renderRelated(item);
    const branches = bundle && item.paths?.length ? item.paths : [item.event_indices];
    const covered = new Set(branches.flat());
    const remainder = item.event_indices.filter(i => !covered.has(i));
    const displayBranches = remainder.length ? [...branches, remainder] : branches;
    const rows = displayBranches.flatMap((branch, b) => branch.map(i => ({i, branch: b, remainder: b === branches.length})));
    state.detailPage = Math.min(state.detailPage, Math.max(0, Math.ceil(rows.length / DETAIL_PAGE) - 1));
    const visible = rows.slice(state.detailPage * DETAIL_PAGE, (state.detailPage + 1) * DETAIL_PAGE);
    $('path-events').replaceChildren(); let previous = null;
    for (const row of visible) {
      if (displayBranches.length > 1 && previous !== row.branch) $('path-events').append(el('h4', row.remainder ? '见证中其余保留事件（不推断连续路径）' : `见证分支 ${row.branch + 1}`, 'branch-heading'));
      previous = row.branch; $('path-events').append(eventCard(state.artifact.events[row.i]));
    }
    pagination('detail', rows.length, DETAIL_PAGE, state.detailPage);
    if (bundle && rows.length !== item.event_indices.length) $('detail-page-note').textContent += ' · 共享事件按分支重复展示';
  }
  function renderEvents() {
    const events = filteredEvents(); state.eventPage = Math.min(state.eventPage, Math.max(0, Math.ceil(events.length / EVENT_PAGE) - 1));
    $('event-table-body').replaceChildren(...events.slice(state.eventPage * EVENT_PAGE, (state.eventPage + 1) * EVENT_PAGE).map(event => {
      const row = el('tr'); row.dataset.eventId = event.event_id;
      const id = el('td'); id.append(el('code', event.event_id)); if (poiLabel(event)) id.append(el('br'), el('span', poiLabel(event), 'poi'));
      row.append(id, el('td', event.timestamp_ns), el('td', label(event, source(event))), el('td', event.relation), el('td', label(event, target(event))), el('td', Number.isFinite(event.score) ? event.score.toPrecision(5) : 'N/A'));
      return row;
    }));
    $('events-empty').hidden = Boolean(events.length); pagination('events', events.length, EVENT_PAGE, state.eventPage);
  }
  function validateReferenceAudit(data) {
    if (data?.schema_version !== 'chain-workbench-reference-audit-v1' || data.scope !== 'source_positive_subgraph_witnesses_not_complete_attacks' || !Array.isArray(data.chains) || !Array.isArray(data.events) || !data.counts) throw new Error('参考核对格式或声明范围不匹配。');
    const artifact = state.artifact;
    if (!artifact.source_manifest_sha256 || data.source_manifest_sha256 !== artifact.source_manifest_sha256) throw new Error('参考核对的来源哈希与当前导出不同，拒绝混用。');
    for (const field of ['case_id', 'track', 'poi_policy', 'method', 'budget_edges']) if (data[field] !== artifact[field]) throw new Error('参考核对与当前冻结决策的案例、策略、方法或预算不匹配。');
    if (data.verified_attack_chain_count !== null) throw new Error('本参考核对不接受未经独立证明的完整攻击链数量。');
    const retained = new Set(artifact.events.map(event => identity(event.event_id))), byId = new Map();
    for (const event of data.events) {
      if (!event.event_id || byId.has(identity(event.event_id)) || typeof event.timestamp_ns !== 'string' || !/^-?\d+$/.test(event.timestamp_ns) || typeof event.retained !== 'boolean' || event.retained !== retained.has(identity(event.event_id))) throw new Error('参考事件标识、精确时间或保留状态与实际子图不一致。');
      const forward = event.causal_src === event.src && event.causal_dst === event.dst;
      const reverse = event.causal_src === event.dst && event.causal_dst === event.src;
      if (!forward && !reverse) throw new Error('参考事件因果方向字段不一致。');
      byId.set(identity(event.event_id), {...event, causal_direction: reverse && (!forward || text(event.relation).toUpperCase() === 'EVENT_EXECUTE') ? 'dst_to_src' : 'src_to_dst'});
    }
    const chainIds = new Set();
    for (const chain of data.chains) {
      if (!chain.id || chainIds.has(chain.id) || !['complete', 'broken'].includes(chain.status) || !Array.isArray(chain.event_ids) || !chain.event_ids.length || !Array.isArray(chain.missing_event_ids)) throw new Error('固定参考链标识、状态或成员格式不正确。');
      chainIds.add(chain.id);
      if (chain.event_ids.some(id => !byId.has(identity(id))) || new Set(chain.event_ids.map(identity)).size !== chain.event_ids.length) throw new Error('固定参考链存在未提供或重复的事件。');
      const missing = chain.event_ids.filter(id => !byId.get(identity(id)).retained);
      if (missing.length !== chain.missing_event_ids.length || missing.some(id => !chain.missing_event_ids.map(identity).includes(identity(id))) || (chain.status === 'complete') !== (missing.length === 0)) throw new Error('固定参考链完整状态与实际缺失事件不一致。');
      for (let i = 1; i < chain.event_ids.length; i++) {
        const previous = byId.get(identity(chain.event_ids[i - 1])), current = byId.get(identity(chain.event_ids[i]));
        if (previous.causal_dst !== current.causal_src || BigInt(previous.timestamp_ns) >= BigInt(current.timestamp_ns)) throw new Error('固定参考事件不是声明的严格有向时间路径。');
      }
    }
    if (data.counts.reference_chains === null) {
      if (data.chains.length || data.events.length) throw new Error('未标注范围不能同时提供已定义参考链。');
    } else if (data.counts.reference_chains !== data.chains.length || data.counts.retained_reference_chains !== data.chains.filter(chain => chain.status === 'complete').length) throw new Error('参考汇总数量与逐链状态不一致。');
    return {...data, byId};
  }
  const auditItems = () => state.audit.chains.filter(chain => $('audit-filter').value === 'all' || chain.status === $('audit-filter').value);
  function renderAuditList() {
    const audit = state.audit, items = auditItems();
    state.auditListPage = Math.min(state.auditListPage, Math.max(0, Math.ceil(items.length / LIST_PAGE) - 1));
    if (!items.some(item => item.id === state.auditSelected)) { state.auditSelected = items[0]?.id ?? null; state.auditEventPage = 0; }
    $('audit-chain-list').replaceChildren(...items.slice(state.auditListPage * LIST_PAGE, (state.auditListPage + 1) * LIST_PAGE).map(chain => {
      const button = el('button', null, chain.id === state.auditSelected ? 'active' : ''); button.type = 'button'; button.setAttribute('aria-pressed', String(chain.id === state.auditSelected));
      button.append(el('strong', chain.id), el('span', `${chain.status === 'complete' ? '完整保留' : '断裂 / 缺失'} · ${chain.event_ids.length} 个必需事件`));
      button.addEventListener('click', () => { state.auditSelected = chain.id; state.auditEventPage = 0; renderAuditList(); }); return button;
    }));
    if (!items.length) $('audit-chain-list').append(el('p', audit.counts.reference_chains === null ? '该案例没有可用参考标注，完整参考统计为 N/A。' : '没有符合筛选条件的固定参考链。', 'no-data'));
    pagination('audit-paths', items.length, LIST_PAGE, state.auditListPage);
    $('audit-chain-detail').hidden = !items.length;
    if (items.length) renderAuditDetail(items.find(chain => chain.id === state.auditSelected));
  }
  function renderAuditDetail(chain) {
    const stages = {source: '源记录', candidate: '候选范围', temporal: '时序见证', retained: '最终选择', temporal_eligible: '时序见证', bundle_eligible: '完整见证束'};
    $('audit-chain-title').textContent = chain.id;
    $('audit-chain-status').textContent = `${chain.status === 'complete' ? '全部必需事件保留' : `缺失 ${chain.missing_event_ids.length} 个必需事件`}${chain.status === 'broken' && chain.first_loss_stage && chain.first_loss_stage !== 'surviving' ? ` · 首次损失：${stages[chain.first_loss_stage] || chain.first_loss_stage}` : ''} · 仅对该固定参考范围成立`;
    state.auditEventPage = Math.min(state.auditEventPage, Math.max(0, Math.ceil(chain.event_ids.length / DETAIL_PAGE) - 1));
    $('audit-events').replaceChildren(...chain.event_ids.slice(state.auditEventPage * DETAIL_PAGE, (state.auditEventPage + 1) * DETAIL_PAGE).map(id => {
      const event = state.audit.byId.get(identity(id)), card = eventCard(event);
      card.classList.toggle('missing', !event.retained);
      card.prepend(el('p', event.retained ? '已保留' : event.candidate_present === false ? '缺失 · 未进入候选范围' : event.temporal_eligible === false ? '缺失 · 无可用时序见证' : '缺失 · 最终未保留', 'event-state')); return card;
    }));
    pagination('audit-detail', chain.event_ids.length, DETAIL_PAGE, state.auditEventPage);
  }
  async function loadReferenceAudit(entry, request) {
    state.audit = null; state.auditSelected = null; state.auditListPage = state.auditEventPage = 0;
    $('download-reference-audit').removeAttribute('href'); $('download-reference-audit').hidden = true;
    $('reference-audit-panel').hidden = !entry.reference_audit_url;
    $('reference-audit-content').hidden = true; $('reference-audit-error').hidden = true; $('reference-audit-status').hidden = false;
    if (!entry.reference_audit_url) return;
    try {
      const url = safeURL(entry.reference_audit_url); if (!url) throw new Error('参考核对链接不是有效的本机地址。');
      const response = await fetch(url, {cache: 'no-store'});
      if (!response.ok) throw new Error(`参考核对暂不可用（HTTP ${response.status}），实际保留子图仍可查看。`);
      const payload = await response.json(); if (request !== state.request) return;
      state.audit = validateReferenceAudit(payload); const counts = state.audit.counts;
      $('download-reference-audit').href = new URL(url).pathname; $('download-reference-audit').hidden = false;
      $('audit-retention').textContent = counts.reference_chains > 0 ? `${number(counts.retained_reference_chains)} / ${number(counts.reference_chains)}` : 'N/A';
      $('audit-covered').textContent = number(counts.covered_positive_events);
      $('audit-singletons').textContent = number(counts.singleton_positive_events);
      $('audit-scope-note').textContent = '固定参考仅覆盖源正事件子图中可组成路径的部分。单事件、未知桥接与未标注行为不由完整参考链比例证明完整。';
      const lineage = state.audit.chains.filter(chain => chain.event_ids.some(id => text(id).toUpperCase().includes('LINEAGE'))).length;
      $('audit-lineage-note').textContent = lineage ? `${lineage} / ${state.audit.chains.length} 条参考包含 LINEAGE 派生关系，不能视作独立原始日志中的完整攻击链证据。` : '这些是派生参考路径，不是现实攻击链的穷举。';
      $('audit-filter').value = 'all'; renderAuditList(); $('reference-audit-content').hidden = false; $('reference-audit-status').hidden = true;
    } catch (error) {
      if (request !== state.request) return;
      $('reference-audit-status').hidden = true; $('reference-audit-content').hidden = true; $('reference-audit-error').hidden = false; $('reference-audit-error').textContent = error.message;
    }
  }
  function fail(error) {
    $('viewer-content').hidden = true; $('load-status').hidden = true; $('load-error').hidden = false;
    $('load-error-detail').textContent = error.message || '读取失败，请核对本机导出目录。';
  }
  async function loadArtifact(index) {
    const request = ++state.request;
    $('reference-audit-panel').hidden = true;
    $('load-status').hidden = false; $('load-status').textContent = '正在读取冻结保留子图…'; $('load-error').hidden = true; $('viewer-content').hidden = true;
    try {
      const entry = state.entries[index], url = safeURL(entry.artifact_url);
      if (!url) throw new Error('目录中的导出链接不是有效的本机地址。');
      const response = await fetch(url, {cache: 'no-store'});
      if (!response.ok) throw new Error(`保留子图读取失败（HTTP ${response.status}）。请核对目录中的文件链接。`);
      const data = validate(await response.json()); if (request !== state.request) return;
      state.artifact = data; state.selected = null; state.listPage = state.detailPage = state.eventPage = 0;
      $('path-search').value = ''; $('event-search').value = ''; $('collection-select').value = 'paths';
      for (const format of ['json', 'csv', 'graphml']) {
        const link = $('download-' + format), value = entry.downloads?.[format] || (format === 'json' ? entry.artifact_url : null), resolved = safeURL(value);
        if (resolved) link.setAttribute('href', new URL(resolved).pathname + new URL(resolved).search); else link.removeAttribute('href');
      }
      indexArtifact(); renderMetrics(); renderList(); renderEvents();
      $('viewer-content').hidden = false; $('load-status').hidden = true;
      loadReferenceAudit(entry, request);
    } catch (error) { if (request === state.request) fail(error); }
  }
  async function loadCatalog() {
    $('load-error').hidden = true; $('load-status').hidden = false;
    try {
      const response = await fetch('/assets/retained-chain-catalog.json', {cache: 'no-store'});
      if (!response.ok) throw new Error(response.status === 404 ? '本机尚未发布保留链路目录。公开页面不附带逐事件明细。' : `导出目录读取失败（HTTP ${response.status}）。`);
      const catalog = await response.json(); const entries = Array.isArray(catalog) ? catalog : catalog.entries;
      if (!Array.isArray(entries) || !entries.length) throw new Error('导出目录中没有可读取的冻结结果。');
      state.entries = entries;
      const groups = new Map();
      entries.forEach((entry, i) => {
        const label = entry.study_version === 'chain-workbench-v2' ? '本轮 v2 代表导出' : '旧版归档 / 其他导出';
        if (!groups.has(label)) { const group = el('optgroup'); group.label = label; groups.set(label, group); }
        const option = el('option', entry.label || entry.id || `结果 ${i + 1}`); option.value = String(i); groups.get(label).append(option);
      });
      $('export-select').replaceChildren(...groups.values());
      const current = entries.filter(entry => entry.study_version === 'chain-workbench-v2').length;
      $('catalog-scope-note').textContent = `本轮 v2 代表导出 ${number(current)} 份；旧版归档 / 其他导出 ${number(entries.length - current)} 份。代表导出仅覆盖指定的冻结决策，不能替代其他方法、范围、起点策略或预算点。LINEAGE 派生关系也占候选事件条目预算。`;
      const requested = new URLSearchParams(window.location.search).get('entry');
      const index = requested == null ? 0 : entries.findIndex(entry => entry.id === requested);
      if (index < 0) throw new Error('未找到指定导出。请核对目录中的 entry 标识，或去掉地址中的 entry 参数后浏览本机目录；不会以另一份图代替。');
      $('export-select').value = String(index);
      await loadArtifact(index);
    } catch (error) { fail(error); }
  }
  $('audit-filter').addEventListener('change', () => { state.auditListPage = state.auditEventPage = 0; renderAuditList(); });
  for (const [prefix, field, render] of [['audit-paths', 'auditListPage', renderAuditList], ['audit-detail', 'auditEventPage', () => renderAuditDetail(state.audit.chains.find(chain => chain.id === state.auditSelected))]]) {
    $(prefix + '-prev').addEventListener('click', () => { state[field]--; render(); });
    $(prefix + '-next').addEventListener('click', () => { state[field]++; render(); });
  }
  $('reload-button').addEventListener('click', loadCatalog);
  $('export-select').addEventListener('change', event => loadArtifact(Number(event.target.value)));
  $('collection-select').addEventListener('change', () => { state.selected = null; state.listPage = state.detailPage = 0; renderList(); });
  $('path-search').addEventListener('input', () => { state.listPage = state.detailPage = 0; renderList(); });
  $('event-search').addEventListener('input', () => { state.eventPage = 0; renderEvents(); });
  for (const [prefix, field, render] of [['paths', 'listPage', renderList], ['detail', 'detailPage', () => renderDetail(allItems().find(item => item.id === state.selected))], ['events', 'eventPage', renderEvents]]) {
    $(prefix + '-prev').addEventListener('click', () => { state[field]--; render(); });
    $(prefix + '-next').addEventListener('click', () => { state[field]++; render(); });
  }
  loadCatalog();
})();
