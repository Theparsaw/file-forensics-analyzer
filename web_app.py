from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import analyzer


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024


def unique_upload_path(directory: Path, filename: str):
    stem = Path(filename).stem or "upload"
    suffix = Path(filename).suffix
    candidate = directory / f"{stem}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem}_{counter}{suffix}"
        counter += 1
    return candidate


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze_uploads():
    files = request.files.getlist("files")
    files = [item for item in files if item and item.filename]
    if not files:
        return jsonify({"error": "Upload at least one file using the 'files' field.", "results": []}), 400

    results = []
    with tempfile.TemporaryDirectory(prefix="assignment-upload-") as tmp:
        upload_dir = Path(tmp)
        for upload in files:
            original_name = upload.filename or "upload"
            safe_name = secure_filename(original_name)
            if not safe_name:
                results.append(
                    {
                        "path": original_name,
                        "uploaded_filename": original_name,
                        "exists": False,
                        "detected_type": "unknown",
                        "detected_family": "unknown",
                        "description": analyzer.DESCRIPTION_BY_TYPE["unknown"],
                        "size": None,
                        "extension": "",
                        "extension_matches": None,
                        "extension_compatible": None,
                        "notes": [],
                        "indicators": {},
                        "errors": ["Invalid upload filename"],
                    }
                )
                continue

            path = unique_upload_path(upload_dir, safe_name)
            try:
                upload.save(path)
                result = analyzer.analyze_path(path)
                result["uploaded_filename"] = original_name
            except Exception as exc:  # keep one failed upload from hiding the rest
                result = analyzer.make_result(path, path.exists())
                result["uploaded_filename"] = original_name
                result["errors"].append(f"Analysis failed: {exc}")
            results.append(result)

    status = 207 if any(result.get("errors") for result in results) else 200
    return jsonify({"results": results}), status


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
