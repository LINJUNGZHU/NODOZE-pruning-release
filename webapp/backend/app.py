from __future__ import annotations

import json
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


def create_app(cache_path: str | Path | None = None) -> Flask:
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

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/assets/<path:name>")
    def assets(name: str):
        return send_from_directory(FRONTEND_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "cache_ready": app.config["DEMO_CACHE"].is_file()})

    def load_cache() -> dict:
        path = app.config["DEMO_CACHE"]
        if not path.is_file():
            raise FileNotFoundError(
                f"Demo cache is missing: {path}. Run python webapp/scripts/prepare_optc.py"
            )
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/api/datasets")
    def datasets():
        try:
            data = load_cache()
        except FileNotFoundError as exc:
            return jsonify({"datasets": [], "error": str(exc)}), 503
        return jsonify({
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
            data = load_cache()
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
            data = load_cache()
            if dataset_id != data["dataset"]["id"]:
                return jsonify({"error": "unknown dataset"}), 404
            if data.get("schema_version") != 2:
                return jsonify({"error": "Rebuild the OPTC frequency index with prepare_optc.py"}), 503
            rescore(data, payload["poi_event_id"], payload.get("budget_ratio"))
            target = app.config["DEMO_CACHE"]
            temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
            try:
                temporary.write_text(json.dumps(data, ensure_ascii=False, allow_nan=False), encoding="utf-8")
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
            return jsonify(data)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 503
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        finally:
            pruning_lock.release()

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
