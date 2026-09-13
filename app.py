import os
import io
import json
import shutil
import zipfile
import tempfile
import threading
import subprocess
import urllib.request
import uuid
import re
import time

from flask import Flask, request, jsonify, render_template, send_file

from analyzer.engine import scan_project, SKIP_DIR_NAMES
from analyzer.rules import ALL_RULES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(TOOLS_DIR, exist_ok=True)

JADX_VERSION = "1.5.1"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
JADX_DIR = os.path.join(TOOLS_DIR, f"jadx-{JADX_VERSION}")
JADX_PROGRESS_RE = re.compile(r'progress:\s*(\d+)\s*of\s*(\d+)\s*\((\d+)%\)')

app = Flask(__name__)
# Local, single-user tool: allow large uploads (whole projects / big APKs).
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # 2 GB safety cap

# In-memory job store. This is a local, single-user tool with no persistence
# across restarts by design — nothing here is written anywhere permanent.
JOBS = {}          # job_id -> {status, phase, message, percent, error, result, history}
JOBS_LOCK = threading.Lock()
SCAN_HISTORY = []  # list of {scan_id, project_name, generated_at, grade, risk_score, files_scanned, ...}
SCANS = {}         # scan_id -> full result, kept in memory for this session (report export, history detail)


def _set_job(job_id, **kwargs):
    with JOBS_LOCK:
        JOBS[job_id].update(kwargs)


def _safe_join(base, *paths):
    """Join paths and guarantee the result stays inside base (prevents path/zip-slip traversal)."""
    final = os.path.normpath(os.path.join(base, *paths))
    if not final.startswith(os.path.normpath(base) + os.sep) and final != os.path.normpath(base):
        raise ValueError("Unsafe path detected")
    return final


def _ensure_jadx(job_id=None):
    """Download and cache the jadx APK/DEX decompiler on first use. Requires a JRE on PATH
    and, for this one-time download, internet access — after that everything is local."""
    jadx_bin = os.path.join(JADX_DIR, "bin", "jadx")
    if os.path.exists(jadx_bin):
        return jadx_bin
    if shutil.which("java") is None:
        raise RuntimeError(
            "APK decompilation needs a Java runtime (JRE 11+) on PATH, which wasn't found. "
            "Install a JRE and try again, or upload extracted Kotlin/Java source instead."
        )
    if job_id:
        _set_job(job_id, phase="downloading jadx (one-time)", message="Fetching decompiler...")
    zip_path = os.path.join(TOOLS_DIR, "jadx.zip")
    try:
        urllib.request.urlretrieve(JADX_URL, zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(JADX_DIR)
    except Exception as e:
        raise RuntimeError(f"Could not download jadx (needed to decompile .apk files): {e}")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
    os.chmod(jadx_bin, 0o755)
    return jadx_bin


def _decompile_apks(work_dir, job_id=None):
    """Find any .apk files under work_dir and decompile each into a sibling folder using jadx,
    streaming jadx's own progress into the job so the UI can show it. Returns warning strings."""
    warnings = []
    apk_paths = []
    for dirpath, dirnames, filenames in os.walk(work_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for fname in filenames:
            if fname.lower().endswith(".apk"):
                apk_paths.append(os.path.join(dirpath, fname))
    if not apk_paths:
        return warnings

    try:
        jadx_bin = _ensure_jadx(job_id)
    except RuntimeError as e:
        return [str(e)]

    for n, apk_path in enumerate(apk_paths):
        out_dir = apk_path + "_decompiled"
        apk_label = os.path.basename(apk_path)
        if job_id:
            _set_job(job_id, phase="decompiling", message=f"Decompiling {apk_label}...", percent=0)
        try:
            proc = subprocess.Popen(
                [jadx_bin, "-d", out_dir, "-j", str(os.cpu_count() or 2), apk_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            start = time.time()
            for line in proc.stdout:
                m = JADX_PROGRESS_RE.search(line)
                if m and job_id:
                    pct = int(m.group(3))
                    _set_job(job_id, phase="decompiling",
                              message=f"Decompiling {apk_label}... {m.group(1)}/{m.group(2)} classes",
                              percent=pct)
                if time.time() - start > 1200:
                    proc.kill()
                    warnings.append(f"{apk_label}: decompilation timed out after 20 minutes.")
                    break
            proc.wait(timeout=30)
        except Exception as e:
            warnings.append(f"{apk_label}: decompilation failed ({e}).")
    return warnings


def _run_scan_job(job_id, work_dir, project_name):
    start_time = time.time()
    try:
        _set_job(job_id, status="running", phase="preparing", message="Preparing files...", percent=0)

        warnings = _decompile_apks(work_dir, job_id)

        _set_job(job_id, phase="scanning", message="Starting scan...", percent=0)

        def progress_cb(current, total, phase, current_file):
            pct = int((current / total) * 100) if total else 100
            _set_job(job_id, phase=phase, percent=pct,
                      message=f"Scanning {current}/{total} files" + (f" — {current_file}" if current_file else ""))

        result = scan_project(work_dir, project_name=project_name, progress_cb=progress_cb)
        result["warnings"] = warnings
        result["duration_seconds"] = round(time.time() - start_time, 1)

        info_notes = []
        if result.get("skipped_binary_files"):
            info_notes.append(f"Auto-excluded {result['skipped_binary_files']} binary/build-artifact file(s).")
        if result.get("skipped_large_files"):
            info_notes.append(f"Skipped {result['skipped_large_files']} file(s) over the 2 MB size limit.")
        result["info_notes"] = info_notes

        # Trend vs the previous scan of the *same* project, if any, in this session.
        with JOBS_LOCK:
            prev = next((h for h in reversed(SCAN_HISTORY) if h["project_name"] == project_name), None)
            SCANS[result["scan_id"]] = result
            SCAN_HISTORY.append(dict(
                scan_id=result["scan_id"], project_name=result["project_name"],
                generated_at=result["generated_at"], grade=result["grade"],
                risk_score=result["risk_score"], files_scanned=result["files_scanned"],
                security_score=result["security_score"],
                severity_counts=result["severity_counts"],
                category_counts=result["category_counts"],
                duration_seconds=result["duration_seconds"],
            ))
        if prev:
            result["previous_scan"] = dict(
                generated_at=prev["generated_at"], security_score=prev["security_score"],
                severity_counts=prev["severity_counts"], category_counts=prev["category_counts"],
            )
        else:
            result["previous_scan"] = None

        _set_job(job_id, status="done", phase="done", percent=100, message="Scan complete", result=result)
    except Exception as e:
        _set_job(job_id, status="error", error=str(e), message=f"Scan failed: {e}")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    work_dir = tempfile.mkdtemp(prefix="scan_", dir=UPLOAD_ROOT)
    project_name = request.form.get("project_name") or "project"

    try:
        zip_file = request.files.get("zipfile")
        files = request.files.getlist("files")

        if zip_file and zip_file.filename:
            if zip_file.filename.lower().endswith(".apk"):
                dest = _safe_join(work_dir, os.path.basename(zip_file.filename))
                zip_file.save(dest)
            else:
                try:
                    with zipfile.ZipFile(zip_file) as zf:
                        for member in zf.infolist():
                            if member.is_dir():
                                continue
                            if member.filename.startswith("__MACOSX/") or member.filename.endswith(".DS_Store"):
                                continue
                            dest = _safe_join(work_dir, member.filename)
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            with zf.open(member) as src, open(dest, "wb") as out:
                                shutil.copyfileobj(src, out)
                except (zipfile.BadZipFile, ValueError) as e:
                    shutil.rmtree(work_dir, ignore_errors=True)
                    return jsonify(error=f"Could not read zip file: {e}"), 400
        elif files:
            saved_any = False
            for f in files:
                rel_path = f.filename or ""
                if not rel_path:
                    continue
                rel_path = rel_path.replace("\\", "/").lstrip("/")
                try:
                    dest = _safe_join(work_dir, rel_path)
                except ValueError:
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                f.save(dest)
                saved_any = True
            if not saved_any:
                shutil.rmtree(work_dir, ignore_errors=True)
                return jsonify(error="No files were received."), 400
        else:
            shutil.rmtree(work_dir, ignore_errors=True)
            return jsonify(error="No files or zip uploaded."), 400

        job_id = str(uuid.uuid4())
        with JOBS_LOCK:
            JOBS[job_id] = dict(status="queued", phase="queued", message="Queued...", percent=0,
                                 error=None, result=None)
        thread = threading.Thread(target=_run_scan_job, args=(job_id, work_dir, project_name), daemon=True)
        thread.start()
        return jsonify(job_id=job_id)
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise


@app.route("/api/scan/progress/<job_id>")
def api_scan_progress(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify(error="Unknown job id"), 404
        out = {k: v for k, v in job.items() if k != "result"}
        out["ready"] = job["status"] == "done"
    return jsonify(out)


@app.route("/api/scan/result/<job_id>")
def api_scan_result(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.get("status") != "done":
            return jsonify(error="Result not ready"), 404
        result = job["result"]
    return jsonify(result)


@app.route("/api/history")
def api_history():
    with JOBS_LOCK:
        return jsonify(list(reversed(SCAN_HISTORY)))


@app.route("/api/rules")
def api_rules():
    """All active rules, for the Security Rules page. Regex objects aren't
    JSON-serializable, so this returns only the display-relevant fields."""
    out = [
        dict(id=r["id"], title=r["title"], severity=r["severity"], category=r["category"],
             cwe=r["cwe"], tags=r.get("tags", []), file_types=r["file_types"], description=r["description"],
             recommendation=r["recommendation"])
        for r in ALL_RULES
    ]
    return jsonify(out)


@app.route("/api/report/<scan_id>")
def api_report(scan_id):
    result = SCANS.get(scan_id)
    if not result:
        return jsonify(error="Scan not found. Reports are only kept in memory for this session."), 404

    fmt = request.args.get("format", "html")
    if fmt == "json":
        buf = io.BytesIO(json.dumps(result, indent=2).encode("utf-8"))
        return send_file(
            buf, mimetype="application/json", as_attachment=True,
            download_name=f"{result['project_name']}-scan-report.json",
        )

    html = render_template("report.html", r=result)
    buf = io.BytesIO(html.encode("utf-8"))
    return send_file(
        buf, mimetype="text/html", as_attachment=True,
        download_name=f"{result['project_name']}-scan-report.html",
    )


if __name__ == "__main__":
    print("\n  AndroidScan — local static & security analyzer")
    print("  Running locally at http://127.0.0.1:5050  (Ctrl+C to stop)\n")
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
