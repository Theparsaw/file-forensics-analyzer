from __future__ import annotations

import tempfile
#keeps uploaded files in a throwaway folder while the request is running
from pathlib import Path
#used for upload paths and small filename edits

from flask import Flask, jsonify, render_template, request
#flask handles the html page and the json upload route
from werkzeug.utils import secure_filename
#cleans browser-provided filenames before writing them to disk

import analyzer
#this is the same python analysis code used by the command line tool


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
#basic upload limit so a browser request cannot send a huge file by accident


def unique_upload_path(directory: Path, filename: str):
#avoid overwriting files when the user uploads two files with the same name
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
#serve the plain html/css/js interface
    return render_template("index.html")


@app.post("/analyze")
def analyze_uploads():
#receive one batch of browser uploads and return the same style of result dicts as the cli json output
    files = request.files.getlist("files")
    files = [item for item in files if item and item.filename]
    if not files:
        return jsonify({"error": "Upload at least one file using the 'files' field.", "results": []}), 400

    results = []
    with tempfile.TemporaryDirectory(prefix="assignment-upload-") as tmp:
#the analyzer works with file paths, so uploads are saved briefly and deleted automatically after this block
        upload_dir = Path(tmp)
        for upload in files:
            original_name = upload.filename or "upload"
            safe_name = secure_filename(original_name)
            if not safe_name:
#some names can become empty after sanitizing, so report that file as an error and keep going
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
#all detection still happens in analyzer.py, not in javascript or flask
                result["uploaded_filename"] = original_name
            except Exception as exc:  #keep one failed upload from hiding the rest
                result = analyzer.make_result(path, path.exists())
                result["uploaded_filename"] = original_name
                result["errors"].append(f"Analysis failed: {exc}")
            results.append(result)

    status = 207 if any(result.get("errors") for result in results) else 200
#207 makes partial failures visible while still returning the successful file results
    return jsonify({"results": results}), status


if __name__ == "__main__":
#simple local development server for the assignment web version
    app.run(debug=True, use_reloader=False)
