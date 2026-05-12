# Automated Basic Static Analysis Tool

This project is for CS48008 Assignment 1. It identifies the real file type of suspicious files by checking file content instead of trusting the extension. It also performs extra checks for archives, PDFs, and Office files.

The project has both:

- a command-line Python analyzer
- a Flask web version that uploads and analyzes multiple files

## Files

- `analyzer.py` - main analyzer and command-line interface
- `web_app.py` - Flask backend for the HTML version
- `templates/index.html` - web page
- `static/app.js` - browser logic for selecting files, submitting them, and exporting JSON
- `static/styles.css` - web page styling
- `requirements.txt` - external Python libraries
- `install_dependencies.sh` - install script for external libraries

## Requirements From The Assignment

The analyzer checks file content to detect the real file format, including disguised files such as a PDF saved with a `.txt` extension.

It supports the assignment file categories, including:

`exe`, `dll`, `scr`, `pdf`, `doc`, `docx`, `docm`, `xls`, `xlsx`, `xlsm`, `ppt`, `pptx`, `ppsx`, `zip`, `rar`, `7z`, `tar`, `gz`, `bz2`, `js`, `vbs`, `vb`, `bat`, `ps1`, `html`, `php`, `swf`, `gif`, `png`, `jpg`, `jpeg`, `bmp`, `svg`, `chm`, `xml`, `rtf`, `mhtml`, `iso`, `tmp`, `msp`, `msi`, `hkcu`, `eml`, `db`, `sql`, `apk`, `app`, `jar`, `java`, `class`, `sh`, `py`, `rb`, `ps`, `eps`, `mp3`, `wav`, `mp4`, `avi`, `mov`, `pub`, `sct`, `wsf`, and `wsh`.

Extra checks include:

- archive password/encryption indicators
- PDF password protection
- PDF URLs, IP addresses, and domain names
- Office language code
- Office page count or closest equivalent
- Office encryption/password indicators
- Office macro detection
- extension match and family compatibility
- notes and errors explaining uncertain or malformed files

## External Libraries

The project mostly uses the Python standard library.

External libraries:

- `Flask` - runs the web app
- `pypdf` - improves PDF parsing, page count, text extraction, and encryption checks

## Install Dependencies

Run the install script:

```sh
sh install_dependencies.sh
```

The script is:

```sh
#!/bin/sh
set -eu

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

You can also run the install command directly:

```sh
python3 -m pip install -r requirements.txt
```

## Run The Command-Line Analyzer

Analyze one file:

```sh
python3 analyzer.py suspicious_file.bin
```

Analyze multiple files:

```sh
python3 analyzer.py file1 file2 file3
```

Analyze a directory recursively:

```sh
python3 analyzer.py --recursive strict_samples
```

Print JSON output:

```sh
python3 analyzer.py --json file1 file2
```

Write an HTML report from the CLI:

```sh
python3 analyzer.py --recursive strict_samples --html-report analysis_report.html
```

## Run The Web App

Start the Flask web server:

```sh
python3 web_app.py
```

Open this address in a browser:

```text
http://127.0.0.1:5000
```

The web app supports selecting multiple files, adding more files after the first selection, removing selected files, clearing the list, analyzing all selected files together, and exporting the results as JSON.

## Output Fields

Each result includes:

- `detected_type` - real detected type from file content
- `description` - readable description of the detected type
- `size` - file size in bytes
- `extension` - extension shown in the filename
- `extension_matches` - whether the extension exactly matches the detected type
- `extension_compatible` - whether the extension belongs to the same broad family
- `notes` - explanations, mismatch warnings, or uncertainty notes
- `indicators` - extra PDF, archive, or Office analysis details
- `errors` - any analysis errors for that file
