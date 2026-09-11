from __future__ import annotations

import json
import copy
import importlib.util
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename


WEBAPP_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = WEBAPP_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))
from tc_pruning.optc_investigation import rescore
FRONTEND_DIR = WEBAPP_DIR / "frontend"
RUNTIME_DIR = WEBAPP_DIR / "runtime"
UPLOAD_DIR = RUNTIME_DIR / "uploads"
DEFAULT_CACHE = RUNTIME_DIR / "optc-demo.json"
ALLOWED_UPLOAD_SUFFIXES = {".json", ".jsonl", ".gz", ".avro"}


def create_app(cache_path: str | Path | None = None, dataset_catalog: str | Path | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("NODOZE_MAX_UPLOAD_BYTES", 2 * 1024**3)
    )
    app.config["DEMO_CACHE"] = Path(
        cache_path or os.environ.get("NODOZE_DEMO_CACHE", DEFAULT_CACHE)
    )
    jobs: dict[str, dict] = {}
    jobs_lock = threading.Lock()
    pruning_lock = threading.Lock()
    cached = {}
    catalog_path = Path(dataset_catalog) if dataset_catalog else RUNTIME_DIR/'examples/catalog.json'

    def catalog():
        return json.loads(catalog_path.read_text()) if (dataset_catalog or (cache_path is None and not os.environ.get('NODOZE_DEMO_CACHE'))) and catalog_path.is_file() else []

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/assets/<path:name>")
    def assets(name: str):
        return send_from_directory(FRONTEND_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "cache_ready": app.config["DEMO_CACHE"].is_file()})

    def load_cache(dataset_id=None) -> dict:
        path = app.config["DEMO_CACHE"]
        entry=next((e for e in catalog() if e['id']==dataset_id),None)
        if entry:path=Path(entry['cache_path'])
        if not path.is_file():
            raise FileNotFoundError(
                f"Demo cache is missing: {path}. Run python webapp/scripts/prepare_optc.py"
            )
        key=str(path.resolve());version=path.stat().st_mtime_ns
        if key not in cached or cached[key][0]!=version:
            cached[key]=(version,json.loads(path.read_text(encoding='utf-8')))
        return cached[key][1]

    def cache_target(dataset_id):
        entry=next((e for e in catalog() if e['id']==dataset_id),None)
        return Path(entry['cache_path']) if entry else app.config['DEMO_CACHE']

    def neural_available():
        from tc_pruning.deep_graph import available_model
        return available_model() is not None and importlib.util.find_spec('torch') is not None

    @app.get("/api/datasets")
    def datasets():
        entries=catalog()
        if entries:
            return jsonify(dict(datasets=[{k:v for k,v in e.items() if k!='cache_path'} for e in entries],
                                neural_available=neural_available()))
        try:
            data = load_cache()
        except FileNotFoundError as exc:
            return jsonify({"datasets": [], "error": str(exc)}), 503
        return jsonify({
            "neural_available": neural_available(),
            "datasets": [{
                "id": data["dataset"]["id"],
                "name": data["dataset"]["name"],
                "description": data["dataset"]["description"],
                "metrics": data["metrics"],
            }]
        })

    @app.get("/api/datasets/<dataset_id>/graph")
    def graph(dataset_id: str):
        try:
            data = load_cache(dataset_id)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 503
        if dataset_id != data["dataset"]["id"]:
            return jsonify({"error": "unknown dataset"}), 404
        return jsonify(data)

    @app.post("/api/datasets/<dataset_id>/prune")
    def prune(dataset_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("poi_event_id"), str):
            return jsonify({"error": "poi_event_id must be an explicit event ID"}), 400
        if not pruning_lock.acquire(blocking=False):
            return jsonify({"error": "Another pruning run is active; retry when it finishes"}), 409
        try:
            data = copy.deepcopy(load_cache(dataset_id))
            if dataset_id != data["dataset"]["id"]:
                return jsonify({"error": "unknown dataset"}), 404
            if data.get("schema_version") != 2:
                return jsonify({"error": "Rebuild the OPTC frequency index with prepare_optc.py"}), 503
            rescore(data, payload["poi_event_id"], payload.get("budget_ratio"), payload.get("selection_mode"),payload.get('attack_quantile'),payload.get('detector'))
            target = cache_target(dataset_id)
            temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
            try:
                temporary.write_text(json.dumps(data, ensure_ascii=False, allow_nan=False), encoding="utf-8")
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
            return jsonify(view_payload(data) if payload.get('compact') else data)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 503
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except ImportError:
            return jsonify({"error": "深度学习依赖未安装：pip install -r requirements-deep.txt"}), 503
        finally:
            pruning_lock.release()

    @app.get("/api/datasets/<dataset_id>/decision-audit")
    def decision_audit(dataset_id: str):
        try:
            data = load_cache(dataset_id)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 503
        if dataset_id != data['dataset']['id']:
            return jsonify({"error": "unknown dataset"}), 404
        if 'decision_certificate' not in data:
            return jsonify({"error": "Recompute the investigation to generate its audit"}), 503
        response=jsonify({key:data[key] for key in ('dataset','poi','history','algorithm','metrics',
                          'decision_contract','decision_certificate','decision_trace','decision_inputs','score_diagnostics')})
        response.headers['Content-Disposition']='attachment; filename="optc-decision-audit.json"'
        return response

    @app.get('/api/datasets/<dataset_id>/attack-report')
    def attack_report(dataset_id: str):
        try:
            data = load_cache(dataset_id)
        except FileNotFoundError as exc:
            return jsonify({'error': str(exc)}), 503
        if dataset_id != data['dataset']['id']:
            return jsonify({'error': 'unknown dataset'}), 404
        if 'attack' not in data:
            return jsonify({'error': 'Recompute the POI to generate attack hypotheses'}), 503
        ids = set(data['attack']['path_event_ids']) | set(data['attack']['evidence_event_ids'])
        response = jsonify(dict(dataset=data['dataset'],poi=data['poi'],history=data['history'],
                                attack=data['attack'],events=[e for e in data['edges'] if e['id'] in ids]))
        response.headers['Content-Disposition'] = 'attachment; filename="optc-attack-report.json"'
        return response

    def view_payload(data):
        # Every raw event appears once in this compact canvas payload. No sampling.
        nodes=data['nodes'];ids={n['id']:i for i,n in enumerate(nodes)}
        fields=('dataset','metrics','poi','poi_presets','history','algorithm','truth','logs','attack')
        return dict(**{k:data[k] for k in fields if k in data},
                    graph=dict(nodes=[[n['id'],n['label'],n['type']] for n in nodes],
                               edges=[[e['id'],ids[e['source']],ids[e['target']],int(e['retained']),e['score']] for e in data['edges']],
                               full_event_count=len(data['edges']),sampled=False),
                    decision_certificate=data.get('decision_certificate'),decision_contract=data.get('decision_contract'))

    @app.get('/api/datasets/<dataset_id>/view')
    def view(dataset_id):
        try:data=load_cache(dataset_id)
        except FileNotFoundError as exc:return jsonify(error=str(exc)),503
        if data['dataset']['id']!=dataset_id:return jsonify(error='unknown dataset'),404
        return jsonify(view_payload(data))

    @app.get('/api/datasets/<dataset_id>/events/<event_id>')
    def event_detail(dataset_id,event_id):
        try:data=load_cache(dataset_id)
        except FileNotFoundError as exc:return jsonify(error=str(exc)),503
        if data['dataset']['id']!=dataset_id:return jsonify(error='unknown dataset'),404
        event=next((e for e in data['edges'] if e['id']==event_id),None)
        return jsonify(event) if event else (jsonify(error='unknown event'),404)

    @app.get('/api/datasets/<dataset_id>/edges')
    def edge_page(dataset_id):
        try:data=load_cache(dataset_id)
        except FileNotFoundError as exc:return jsonify(error=str(exc)),503
        if data['dataset']['id']!=dataset_id:return jsonify(error='unknown dataset'),404
        try:
            page=max(0,int(request.args.get('page',0)));limit=min(100,max(1,int(request.args.get('limit',20))))
        except ValueError:return jsonify(error='invalid pagination'),400
        query=request.args.get('q','').lower().strip();decision=request.args.get('filter','all')
        if decision not in ('all','retained','removed','attack'):return jsonify(error='unknown edge filter'),400
        edges=[e for e in data['edges'] if
               (decision=='all' or decision=='retained' and e['retained'] or decision=='removed' and not e['retained'] or
                decision=='attack' and e.get('attack_role','none')!='none') and
               (not query or query in f"{e['id']} {e['source']} {e['target']} {e['source_label']} {e['target_label']} {e['relation']}".lower())]
        if request.args.get('sort','score')=='score':edges.sort(key=lambda e:(-e['score'],e['id']))
        keys=('id','source_label','target_label','relation','timestamp','score','historical_count','retained','reason','attack_role')
        return jsonify(total=len(edges),page=page,limit=limit,edges=[{k:e.get(k) for k in keys} for e in edges[page*limit:(page+1)*limit]])

    def update_job(job_id: str, **changes) -> None:
        with jobs_lock:
            jobs[job_id].update(changes)

    def monitor_import(job_id: str, command: list[str], log_path: Path) -> None:
        update_job(job_id, status="running", started_at=time.time())
        with log_path.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(
                command,
                cwd=PROJECT_DIR,
                stdout=stream,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        result = None
        if completed.returncode == 0:
            try:
                result = json.loads(log_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                result = {"message": "import completed; inspect the log for details"}
        update_job(
            job_id,
            status="complete" if completed.returncode == 0 else "failed",
            return_code=completed.returncode,
            finished_at=time.time(),
            result=result,
        )

    @app.post("/api/imports")
    def start_import():
        files = request.files.getlist("files")
        if not files or all(not item.filename for item in files):
            return jsonify({"error": "at least one CDM file is required"}), 400
        job_id = uuid.uuid4().hex[:12]
        job_dir = UPLOAD_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=False)
        saved: list[Path] = []
        for item in files:
            name = secure_filename(item.filename or "")
            suffixes = Path(name).suffixes
            if not name or not suffixes or suffixes[-1].lower() not in ALLOWED_UPLOAD_SUFFIXES:
                return jsonify({"error": f"unsupported file: {name or '(empty)'}"}), 400
            target = job_dir / name
            item.save(target)
            saved.append(target)
        database = job_dir / "graph.db"
        log_path = job_dir / "ingest.log"
        command = [
            os.environ.get("PYTHON", "python"), "-m", "tc_pruning.cli", "ingest",
            "--input", *(str(path) for path in saved),
            "--db", str(database), "--batch-size", "50000",
        ]
        with jobs_lock:
            jobs[job_id] = {
                "id": job_id,
                "status": "queued",
                "filenames": [path.name for path in saved],
                "database": str(database),
                "log": str(log_path),
            }
        threading.Thread(
            target=monitor_import,
            args=(job_id, command, log_path),
            daemon=True,
        ).start()
        return jsonify(jobs[job_id]), 202

    @app.get("/api/imports/<job_id>")
    def import_status(job_id: str):
        with jobs_lock:
            job = jobs.get(job_id)
            if job is None:
                return jsonify({"error": "unknown import job"}), 404
            response = dict(job)
        log_path = Path(response["log"])
        if log_path.is_file():
            response["log_tail"] = log_path.read_text(
                encoding="utf-8", errors="replace"
            )[-4000:]
        return jsonify(response)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("NODOZE_WEB_HOST", "127.0.0.1"),
        port=int(os.environ.get("NODOZE_WEB_PORT", "8000")),
        debug=False,
    )
