from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request

import analyzer
import gemini

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
ALLOWED_EXTENSION = ".eml"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 1024 * 1024

# Report cache for the active process. Keeps the report available when the UI
# navigates to the dedicated results page.
REPORTS: dict[str, dict] = {}
REPORT_LIMIT = 25


@app.get("/")
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_MB)


@app.get("/report/<report_id>")
def report_page(report_id: str):
    if report_id not in REPORTS:
        return render_template("index.html", max_upload_mb=MAX_UPLOAD_MB)
    return render_template("report.html", report_id=report_id, google_maps_api_key=os.getenv("GOOGLE_MAPS_API_KEY"))


@app.get("/report-data/<report_id>")
def report_data(report_id: str):
    payload = REPORTS.get(report_id)
    if payload is None:
        return jsonify(error="Report not found or expired."), 404
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return jsonify(
        status="ok",
        gemini_configured=bool(os.getenv("GEMINI_API_KEY")),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
    )


def _save_upload(upload, path: Path) -> int:
    total = 0
    with path.open("wb") as out:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise ValueError(f"File is larger than {MAX_UPLOAD_MB} MB.")
            out.write(chunk)
    return total


def _build_analysis_payload(package: dict) -> dict:
    return package


def _store_report(payload: dict) -> str:
    report_id = uuid.uuid4().hex
    REPORTS[report_id] = payload

    # Keep memory bounded without adding a database.
    while len(REPORTS) > REPORT_LIMIT:
        oldest_key = next(iter(REPORTS))
        REPORTS.pop(oldest_key, None)

    return report_id


@app.post("/analyze")
def analyze_upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify(error="No .eml file was uploaded."), 400

    if not upload.filename.lower().endswith(ALLOWED_EXTENSION):
        return jsonify(error="Only .eml files are accepted."), 400

    job_id = uuid.uuid4().hex
    job_dir = Path(tempfile.mkdtemp(prefix=f"email-forensics-{job_id}-"))

    try:
        input_path = job_dir / "input.eml"
        output_dir = job_dir / "output"
        attachments_dir = output_dir / "attachments"
        attachments_dir.mkdir(parents=True)

        _save_upload(upload, input_path)

        evidence = analyzer.parse_eml(input_path, attachments_dir)
        tool_results = analyzer.run_local_analysis(evidence, output_dir)
        api_results = analyzer.run_api_enrichment(evidence)

        package = {
            "summary": analyzer.build_summary(evidence, tool_results),
            "evidence": evidence,
            "tool_results": tool_results,
            "api_enrichment": api_results,
        }

        result_path = output_dir / "result.json"
        result_path.write_text(
            json.dumps(package, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )

        gemini_result = None
        gemini_error = None
        try:
            gemini_result = gemini.analyze_report(_build_analysis_payload(package))
        except Exception as exc:
            gemini_error = f"Gemini analysis failed: {type(exc).__name__}: {exc}"

        report_id = _store_report({
            "filename": upload.filename,
            "report": package,
            "ai_analysis": gemini_result,
            "ai_error": gemini_error,
        })

        response = jsonify(report_id=report_id)
        response.headers["Cache-Control"] = "no-store"
        return response

    except ValueError as exc:
        return jsonify(error=str(exc)), 413
    except Exception as exc:
        app.logger.exception("Analysis failed")
        return jsonify(
            error="Analysis failed.",
            detail=f"{type(exc).__name__}: {exc}",
        ), 500
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)


@app.errorhandler(413)
def too_large(_):
    return jsonify(error=f"File is larger than {MAX_UPLOAD_MB} MB."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
