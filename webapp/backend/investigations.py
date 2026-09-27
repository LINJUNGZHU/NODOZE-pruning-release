"""Node-focused investigation contract and immutable, single-organization run store."""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import time
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Response, jsonify, request

from tc_pruning.optc_investigation import rescore


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


class RunStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.database = self.directory / 'runs.sqlite'
        self._cache = None
        self._cache_lock = threading.Lock()

    def connect(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        db = sqlite3.connect(self.database, timeout=30)
        os.chmod(self.database, 0o600)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT NOT NULL, metadata TEXT NOT NULL, result BLOB NOT NULL)')
        return db

    def save(self, data, parameters):
        # Each immutable blob and its metadata commit in one transaction.
        record = dict(id=uuid.uuid4().hex, created_at=datetime.now(timezone.utc).isoformat(),
                      dataset_id=data['dataset']['id'], **parameters)
        data['run'] = record
        with self.connect() as db:
            db.execute('INSERT INTO runs VALUES (?, ?, ?, ?)',
                       (record['id'], record['created_at'], canonical(record), gzip.compress(canonical(data).encode(), mtime=0)))
        with self._cache_lock:
            self._cache = (record['id'], data)
        return record

    def load(self, run_id):
        if not re.fullmatch(r'[a-f0-9]{32}', run_id):
            raise KeyError('unknown investigation')
        with self._cache_lock:
            if self._cache is not None and self._cache[0] == run_id:
                return self._cache[1]
            with self.connect() as db:
                row = db.execute('SELECT result FROM runs WHERE id=?', (run_id,)).fetchone()
            if row is None:
                raise KeyError('unknown investigation')
            data = json.loads(gzip.decompress(row[0]))
            self._cache = (run_id, data)
            return data

    def list(self, limit=30, offset=0):
        with self.connect() as db:
            rows = db.execute("SELECT metadata FROM runs WHERE json_extract(metadata, '$.algorithm_version')='node_focus_rasp_v1' ORDER BY created DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def count(self):
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM runs WHERE json_extract(metadata, '$.algorithm_version')='node_focus_rasp_v1'").fetchone()[0]


def candidate_digest(data):
    digest = hashlib.sha256()
    for edge in sorted(data['edges'], key=lambda e: e['id']):
        digest.update(canonical({key: edge.get(key) for key in (
            'id', 'source', 'target', 'relation', 'timestamp_ns', 'raw', 'source_file', 'source_line')}).encode())
        digest.update(b'\n')
    return digest.hexdigest()


def build_summary(data):
    metrics = data['metrics']
    certificate = data['decision_certificate']
    return dict(
        event_reduction_ratio=1-metrics['retained_edges']/metrics['candidate_edges'],
        budget_utilization=metrics['retained_edges']/metrics['budget_edges'],
        certificate_valid=all(certificate.get(k) is True for k in (
            'budget_valid', 'poi_preserved', 'temporal_links_valid', 'complete_witnesses', 'ledger_replayed')),
        unused_budget=certificate['unused_budget'], score_meaning='investigation relevance; not malicious probability',
        FP='NA', FN='NA', Precision='NA', Recall='NA', F1='NA',
        evaluation_scope='No complete event-level labels; no detection claim')


def public_dataset(data):
    # Keep machine filesystem paths in private stored evidence, not UI metadata.
    return {k: v for k, v in data['dataset'].items() if k in (
        'id', 'name', 'description', 'window_start', 'window_end', 'host', 'hostname')}


def run_view(data):
    """Independent display selection; full counts and exported decisions remain exact."""
    focal = data['poi'].get('node_id')
    anchor = data['poi']['event_id']
    # Incident-to-focal preview only: no implied all-graph visual coverage.
    incident = [e for e in data['edges'] if focal in (e['source'], e['target'])]
    selected = sorted(incident, key=lambda e: hashlib.sha256(('product-preview-v1\0'+e['id']).encode()).digest())[:180]
    anchor_edge = next(e for e in data['edges'] if e['id'] == anchor)
    if anchor not in {e['id'] for e in selected}:
        selected = ([anchor_edge]+selected)[:180]
    node_ids = {e[k] for e in selected for k in ('source', 'target')}
    nodes = [n for n in data['nodes'] if n['id'] in node_ids]
    fields = ('id', 'source', 'target', 'source_label', 'target_label', 'relation', 'timestamp', 'score', 'retained', 'reason')
    return dict(run=data['run'], dataset=public_dataset(data), poi=data['poi'], metrics=data['metrics'],
                summary=build_summary(data), algorithm={k: data['algorithm'].get(k) for k in (
                    'product_version', 'seed_policy', 'mode', 'selection_mode', 'truth_used', 'external_alert_used')},
                history={k: data['history'].get(k) for k in ('history_edges', 'cutoff_ns', 'strict_before')},
                certificate=data['decision_certificate'],
                graph=dict(nodes=nodes, edges=[{k:e.get(k) for k in fields} for e in selected],
                           preview=True, scope='incident_to_selected_node', incident_events=len(incident),
                           shown_events=len(selected), total_events=len(data['edges'])),
                reason_counts={reason:sum(e['reason']==reason for e in data['edges']) for reason in {e['reason'] for e in data['edges']}})


def register_investigations(app, load_cache, store, pruning_lock):
    def dataset(dataset_id):
        data = load_cache(dataset_id)
        if data['dataset']['id'] != dataset_id:
            raise KeyError('unknown dataset')
        return data

    @app.errorhandler(KeyError)
    def missing(exc):
        return jsonify(error='Unknown dataset, node, event or investigation'), 404

    @app.errorhandler(FileNotFoundError)
    def unavailable(exc):
        app.logger.warning('Required investigation input missing: %s', exc)
        return jsonify(error='调查数据尚未就绪，请检查数据导入和历史索引。'), 503

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    @app.get('/api/datasets/<dataset_id>/nodes')
    def nodes(dataset_id):
        data = dataset(dataset_id)
        query = request.args.get('q', '').strip().lower()
        node_type = request.args.get('type', 'all')
        found = {}
        for e in data['edges']:
            seen = set()
            for side in ('source', 'target'):
                if e[side] in seen:
                    continue
                seen.add(e[side])
                n = found.setdefault(e[side], dict(id=e[side], label=e[side+'_label'], type=e[side+'_type'], event_count=0))
                n['event_count'] += 1
        result = sorted((n for n in found.values() if (node_type=='all' or n['type']==node_type) and
                         (not query or query in (n['id']+' '+n['label']).lower())),
                        key=lambda n:(n['type']!='process', n['label'], n['id']))
        return jsonify(nodes=result[:60], total=len(result), limit=60)

    @app.get('/api/datasets/<dataset_id>/nodes/<node_id>/events')
    def node_events(dataset_id, node_id):
        data = dataset(dataset_id)
        events = sorted((e for e in data['edges'] if node_id in (e['source'],e['target'])),
                        key=lambda e:(e['timestamp_ns'],e['id']))
        if not events:
            raise KeyError(node_id)
        query = request.args.get('q','').strip().lower()
        if query:
            events=[e for e in events if query in canonical({k:e.get(k) for k in (
                'id','timestamp','relation','source_label','target_label')}).lower()]
        page=int(request.args.get('page',0))
        if page<0:raise ValueError('page must be nonnegative')
        fields=('id','timestamp','relation','source_label','target_label')
        return jsonify(total=len(events), page=page, limit=40,
                       events=[{k:e[k] for k in fields} for e in events[page*40:(page+1)*40]])

    @app.get('/api/investigations')
    def history():
        page=int(request.args.get('page',0))
        if page<0:raise ValueError('page must be nonnegative')
        return jsonify(runs=store.list(offset=page*30), total=store.count(),page=page,limit=30)

    @app.post('/api/investigations')
    def create():
        payload = request.get_json(silent=True)
        if not isinstance(payload,dict):raise ValueError('JSON object required')
        for key in ('dataset_id','node_id','anchor_event_id'):
            if not isinstance(payload.get(key),str) or not payload[key].strip():raise ValueError(f'{key} is required')
        budget=payload.get('budget_edges')
        data=dataset(payload['dataset_id'])
        event_ids=[e['id'] for e in data['edges']]
        if len(set(event_ids))!=len(event_ids):
            raise ValueError('候选账本包含重复事件 ID，请重新建立索引。')
        if isinstance(budget,bool) or not isinstance(budget,int) or not 1<=budget<=len(data['edges']):
            raise ValueError('预算须为 1 到候选事件总数之间的整数。')
        anchor=next((e for e in data['edges'] if e['id']==payload['anchor_event_id']),None)
        if anchor is None or payload['node_id'] not in (anchor['source'],anchor['target']):
            raise ValueError('时间锚事件必须直接关联所选节点。')
        if data.get('schema_version')!=2:raise ValueError('Only schema v2 indexed event ledgers are supported')
        if not pruning_lock.acquire(blocking=False):
            return jsonify(error='已有调查正在计算，请稍后重试。'),409
        try:
            started=time.monotonic()
            # Clear all legacy label/attack artifacts before invoking the engine.
            import copy
            result=copy.deepcopy(data)
            for field in ('truth','attack','context_graph','poi_presets'):
                result.pop(field,None)
            rescore(result,anchor['id'],budget/len(result['edges']),'evidence',
                    focal_node_id=payload['node_id'],pruning_only=True,budget_edges=budget)
            if not build_summary(result)['certificate_valid']:
                raise ValueError('预算或路径核验未通过；本次结果未保存。')
            params=dict(node_id=payload['node_id'],node_label=anchor['source_label'] if anchor['source']==payload['node_id'] else anchor['target_label'],
                        anchor_event_id=anchor['id'],anchor_time=anchor['timestamp'],budget_edges=budget,
                        candidate_sha256=candidate_digest(data),history_index_id=data['history_index']['id'],
                        config_sha256=hashlib.sha256(canonical(result['algorithm']).encode()).hexdigest(),
                        elapsed_seconds=round(time.monotonic()-started,4),
                        retained_edges=result['metrics']['retained_edges'],candidate_edges=len(data['edges']),
                        algorithm_version='node_focus_rasp_v1', status='verified')
            store.save(result,params)
            return jsonify(run_view(result)),201
        finally:
            pruning_lock.release()

    @app.get('/api/investigations/<run_id>')
    def investigation_view(run_id):
        return jsonify(run_view(store.load(run_id)))

    @app.get('/api/investigations/<run_id>/events')
    def events(run_id):
        data=store.load(run_id)
        page=int(request.args.get('page',0))
        if page<0:raise ValueError('page must be nonnegative')
        decision=request.args.get('decision','retained')
        if decision not in ('all','retained','removed'):raise ValueError('unknown decision')
        query=request.args.get('q','').strip().lower()
        rows=[e for e in data['edges'] if (decision=='all' or e['retained']==(decision=='retained')) and
              (not query or query in canonical({k:e.get(k) for k in ('id','source_label','target_label','relation')}).lower())]
        rows.sort(key=lambda e:(e['timestamp_ns'],e['id']))
        fields=('id','source','target','source_label','target_label','relation','timestamp','score','historical_count','retained','reason')
        return jsonify(events=[{k:e.get(k) for k in fields} for e in rows[page*30:(page+1)*30]],total=len(rows),page=page,limit=30)

    @app.get('/api/investigations/<run_id>/events/<event_id>')
    def detail(run_id,event_id):
        data=store.load(run_id)
        edge=next((e for e in data['edges'] if e['id']==event_id),None)
        if edge is None:raise KeyError(event_id)
        witness_ids=edge['decision']['witness_event_ids']
        wanted=set(witness_ids)
        by_id={e['id']:e for e in data['edges'] if e['id'] in wanted}
        return jsonify(event=edge,witness=[{k:by_id[i].get(k) for k in (
            'id','source','target','source_label','target_label','timestamp','relation','retained')} for i in sorted(witness_ids,key=lambda i:(by_id[i]['timestamp_ns'],i))])

    @app.get('/api/investigations/<run_id>/export')
    def export(run_id):
        data=store.load(run_id)
        response=jsonify(run=data['run'],dataset=public_dataset(data),poi=data['poi'],metrics=data['metrics'],
                         summary=build_summary(data),algorithm=data['algorithm'],history=data['history'],
                         certificate=data['decision_certificate'],contract=data['decision_contract'],
                         decision_certificate=data['decision_certificate'],decision_contract=data['decision_contract'],
                         events=[e for e in data['edges'] if e['retained']],
                         decision_inputs=data['decision_inputs'],decision_trace=data['decision_trace'])
        response.headers['Content-Disposition']=f'attachment; filename="nodoze-{run_id}.json"'
        return response

    @app.get('/api/investigations/<run_id>/export.csv')
    def export_csv(run_id):
        data=store.load(run_id)
        out=io.StringIO();fields=('id','timestamp','source','target','source_label','target_label','relation','score','historical_count','reason')
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for edge in data['edges']:
            if edge['retained']:
                # Prevent spreadsheet formula evaluation of untrusted log content.
                writer.writerow({k: "'"+str(edge.get(k,'')) if str(edge.get(k,'')).lstrip().startswith(('=','+','-','@','\t','\r')) else edge.get(k,'') for k in fields})
        return Response('\ufeff'+out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename="nodoze-{run_id}.csv"'})
