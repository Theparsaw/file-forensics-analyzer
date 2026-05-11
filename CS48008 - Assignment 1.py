import argparse  
#parses command line options in parse_args()
import datetime as _dt  
#used for the time stamps in in write_html_report()
import html  
#escapes report values in write_html_report()
import ipaddress
#filters real IP addresses in unique_sorted()
import json  
#writes JSON output and formats indicators used in  the HTML report
import logging  
#silences pypdf warnings before reading PDF metadata
import re
#matches script signatures, URLs, domains, headers, and language values
import struct
#reads binary headers and container records in the file type checks
import sys
#reads command line args in main()
import tarfile
#detects TAR archives in detect_type()
import zipfile  
#reads ZIP, Office OOXML, and archive metadata
import zlib
#checks 7-Zip header CRC values in seven_zip_password_info()
from pathlib import Path  
#represents input, output, and discovered file paths
from xml.etree import ElementTree  
#parses Office XML metadata in analyze_ooxml()


OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
#I got this from here https://filext.com/file-extension/XLSX#:~:text=The%20first%208%20bytes%20of%20the%20CFB%20format%20are%20D0CF11E0A1B11AE1%20(which%20looks%20like%20%22DOCFILE%22).
SEVEN_Z_MAGIC = bytes.fromhex("377ABCAF271C")
#i got this one from here https://www.wikidata.org/wiki/Q270131#:~:text=format%20identification%20pattern-,377ABCAF271C,-offset

#names I print in the report, i use the short forms in my detector functions instead of typing the entire thing
#i found the list on Wikipedia
DESCRIPTION_BY_TYPE = {
    "exe": "Windows Portable Executable",
    "dll": "Windows Dynamic Link Library",
    "scr": "Windows screen saver executable",
    "lnk": "Windows shortcut file",
    "pdf": "Portable Document Format",
    "doc": "Microsoft Word document (OLE)",
    "docx": "Microsoft Word document",
    "docm": "Macro-enabled Microsoft Word document",
    "xls": "Microsoft Excel spreadsheet (OLE)",
    "xlsx": "Microsoft Excel spreadsheet",
    "xlsm": "Macro-enabled Microsoft Excel workbook",
    "ppt": "Microsoft PowerPoint presentation (OLE)",
    "pptx": "Microsoft PowerPoint presentation",
    "pptm": "Macro-enabled Microsoft PowerPoint presentation",
    "ppsx": "Microsoft PowerPoint slide show",
    "zip": "ZIP archive",
    "rar": "RAR archive",
    "7z": "7-Zip archive",
    "js": "JavaScript source",
    "vbs": "VBScript source",
    "vb": "Visual Basic source",
    "bat": "Windows batch script",
    "html": "HTML document",
    "php": "PHP script",
    "swf": "Small Web Format",
    "gif": "GIF image",
    "png": "PNG image",
    "jpg": "JPEG image",
    "jpeg": "JPEG image",
    "bmp": "Bitmap image",
    "svg": "Scalable Vector Graphics",
    "ps1": "PowerShell script",
    "chm": "Compiled HTML Help",
    "xml": "XML document",
    "rtf": "Rich Text Format",
    "mhtml": "MIME HTML archive",
    "iso": "ISO disc image",
    "tar": "TAR archive",
    "gz": "Gzip archive",
    "bz2": "Bzip2 archive",
    "tmp": "Temporary/unknown file",
    "msp": "Microsoft Patch package",
    "msi": "Microsoft Installer package",
    "hkcu": "Registry script",
    "eml": "Email message",
    "db": "Database file",
    "sql": "SQL script",
    "apk": "Android application package",
    "app": "macOS application bundle",
    "jar": "Java archive",
    "java": "Java source",
    "class": "Java class",
    "sh": "Unix shell script",
    "py": "Python script",
    "rb": "Ruby script",
    "ps": "PostScript",
    "eps": "Encapsulated PostScript",
    "mp3": "MP3 audio",
    "wav": "WAV audio",
    "mp4": "MPEG-4 video",
    "avi": "AVI video",
    "mov": "QuickTime movie",
    "pub": "Microsoft Publisher document",
    "sct": "Windows Script Component",
    "wsf": "Windows Script File",
    "wsh": "Windows Script Host settings",
    "unknown": "Unknown file type",
}

#simple text/script checks after the binary signatures do not match
#the functions returns the first part, e.g. "php" if the pattern matches it
SCRIPT_PATTERNS = [
    ("php", re.compile(br"^\s*<\?php\b", re.I | re.S)),
    ("html", re.compile(br"^\s*(?:<!doctype\s+html|<html\b|<!--.*?<html\b)", re.I | re.S)),
    ("svg", re.compile(br"^\s*(?:<\?xml[^>]*>\s*)?<svg\b", re.I | re.S)),
    ("xml", re.compile(br"^\s*<\?xml\b", re.I | re.S)),
    ("rtf", re.compile(br"^\{\\rtf", re.I)),
    ("bat", re.compile(br"^\s*(?:@echo\s+off|echo\s+off|rem\b|set\s+\w+=|if\s+exist\b)", re.I)),
    ("ps1", re.compile(br"(?:^\s*param\s*\(|\bWrite-Host\b|\bGet-ChildItem\b|\bSet-ExecutionPolicy\b|\$PSVersionTable\b)", re.I)),
    ("vbs", re.compile(br"(?:^\s*(?:Option\s+Explicit|Dim\s+\w+|Set\s+\w+\s*=)|\bWScript\.|\bCreateObject\s*\()", re.I)),
    ("sct", re.compile(br"<scriptlet\b|<registration\b|progid=", re.I)),
    ("wsf", re.compile(br"<job\b|<package\b|<script\s+language=", re.I)),
    ("wsh", re.compile(br"^\s*\[ScriptFile\]", re.I)),
    ("js", re.compile(br"(?:^\s*(?:function\b|const\b|let\b|var\b|import\b|export\b)|\bconsole\.log\s*\(|=>)", re.I)),
    ("java", re.compile(br"^\s*(?:package\s+[\w.]+;|import\s+java\.|public\s+(?:class|interface|enum)\s+)", re.I | re.M)),
    ("py", re.compile(br"^\s*(?:#!.*python|from\s+\w+|import\s+\w+|def\s+\w+\s*\(|class\s+\w+)", re.I | re.M)),
    ("rb", re.compile(br"^\s*(?:#!.*ruby|require\s+['\"]|def\s+\w+|class\s+\w+)", re.I | re.M)),
    ("sh", re.compile(br"^\s*#!\s*/(?:usr/bin/env\s+)?(?:ba|z|k)?sh\b|^\s*(?:if|for|while)\s+.*\b(?:then|do)\b", re.I | re.M)),
    ("sql", re.compile(br"^\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b", re.I)),
    ("hkcu", re.compile(br"^\s*Windows Registry Editor.*?\[HKEY_CURRENT_USER\\", re.I | re.S)),
    ("vb", re.compile(br"^\s*(?:Imports\s+\w+|Module\s+\w+|Public\s+Class\s+\w+|Sub\s+Main\s*\()", re.I | re.M)),
    ("eps", re.compile(br"^%!PS-Adobe-[^\n]*EPSF", re.I)),
    ("ps", re.compile(br"^%!PS-Adobe-", re.I)),
]

#these are the paterns for the network related things
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|info|biz|io|co|uk|tr|de|fr|ru|cn|jp|au)\b", re.I)


def make_result(path, exists):
#make one plain result dictionary per file, this function is used to helpl with generting the outputs
    return {
        "path": str(path),
        "exists": exists,
        "detected_type": "unknown",
        "description": DESCRIPTION_BY_TYPE["unknown"],
        "size": None,
        "extension": "",
        "extension_matches": None,
        "notes": [],
        "indicators": {},
        "errors": [],
    }


def read_prefix(path, limit=2_000_000):
#read enough bytes for signatures and normal metadata
    with path.open("rb") as fh:
        return fh.read(limit)


def decode_text(data):
#try common encodings because they might not always be the standrad utf-8
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1", "ignore")


def unique_sorted(items):
#remove duplicate of indicators so the report is not messy
    cleaned = set()
    for item in items:
        if item.strip():
            cleaned.add(item.strip().rstrip(".,;:"))
    return sorted(cleaned)


def is_lnk(data):
#windows shortcut magic value, i got this one from here https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/4d25bbad-09b7-4322-8c0a-521d268481bb
    return len(data) >= 76 and data[:4] == b"\x4c\x00\x00\x00" and data[4:20] == bytes.fromhex("0114020000000000C000000000000046")


def is_sqlite_db(data):
#sqlite has a nice obvious header, then a page size check
    if not data.startswith(b"SQLite format 3\x00") or len(data) < 100:
        return False
    page_size = struct.unpack_from(">H", data, 16)[0]
    if page_size == 1:
        page_size = 65536
    return 512 <= page_size <= 65536 and page_size & (page_size - 1) == 0


def message_header_score(text):
#email and mhtml look like plain text, so count mail-like headers
    headers = set()
    for line in re.split(r"\r?\n", text[:8192]):
        if re.match(r"^[A-Za-z][A-Za-z0-9-]{1,60}:", line):
            headers.add(line.split(":", 1)[0].lower())
    return len(headers & {"from", "to", "subject", "date", "message-id", "mime-version", "content-type", "received", "return-path"})


def is_mhtml_text(text):
#mhtml is basically mime plus html parts
    head = text[:20000]
    if not re.search(r"^mime-version:", head, re.I | re.M) or message_header_score(text) < 2:
        return False
    return bool(
        re.search(r"content-type:\s*multipart/related", head, re.I)
        or (re.search(r"content-type:\s*text/html", head, re.I) and re.search(r"content-location:|content-base:|mhtmlboundary", head, re.I))
    )


def is_eml_text(text):
#normal email should have several mail headers, but not be mhtml
    return message_header_score(text) >= 3 and not is_mhtml_text(text)


def detect_pe_type(data, extension):
#PE covers exe/dll/scr; dll has a flag in the PE header
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return "exe"
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
        if characteristics & 0x2000:
            return "dll"
    except struct.error:
        pass
    return "scr" if extension == ".scr" else "exe"


def zip_name_map(zf):
#lowercase names make matching easier, but keep real names for reading
    names = {}
    for name in zf.namelist():
        names[name.lower()] = name
    return names


def zip_text(zf, names, lower_name):
#read a small xml/text file from a zip if it exists
    real_name = names.get(lower_name.lower())
    if not real_name:
        return ""
    try:
        return zf.read(real_name).decode("utf-8", "ignore")
    except Exception:
        return ""


def detect_ooxml_from_zip(path):
#docx/xlsx/pptx files are zip files with specific folders inside
    notes = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zip_name_map(zf)
            lower = set(names)
            content_types = zip_text(zf, names, "[content_types].xml").lower()
    except zipfile.BadZipFile:
        return None, ["ZIP header found, but archive directory could not be parsed"]

    if "[content_types].xml" not in lower:
        return None, notes

#word files use the word folder macro files usually have vbaProject.bin
    has_word_folder = False
    for name in lower:
        if name.startswith("word/"):
            has_word_folder = True
            break
    if has_word_folder:
        return ("docm" if "word/vbaproject.bin" in lower or "macroenabled" in content_types else "docx"), notes
#excel is the same idea, but under xl
    has_excel_folder = False
    for name in lower:
        if name.startswith("xl/"):
            has_excel_folder = True
            break
    if has_excel_folder:
        return ("xlsm" if "xl/vbaproject.bin" in lower or "macroenabled" in content_types else "xlsx"), notes
#powerpoint also has slideshow vs presentation to think about
    has_powerpoint_folder = False
    for name in lower:
        if name.startswith("ppt/"):
            has_powerpoint_folder = True
            break
    if has_powerpoint_folder:
        has_macro = "ppt/vbaproject.bin" in lower or "macroenabled" in content_types
        is_show = "presentationml.slideshow.main+xml" in content_types
        if has_macro and not is_show:
            return "pptm", notes
        if is_show:
            if has_macro:
                notes.append("Macro-enabled PowerPoint slideshow detected; reporting closest supported slideshow type")
            return "ppsx", notes
        return "pptm" if has_macro else "pptx", notes
    return None, notes


def detect_zip_type(path):
#try office first, then android/java, then plain zip
    subtype, notes = detect_ooxml_from_zip(path)
    if subtype:
        return subtype, notes
    try:
        with zipfile.ZipFile(path) as zf:
            lower = set(zip_name_map(zf))
    except zipfile.BadZipFile:
        return "zip", notes or ["ZIP header found, but archive directory could not be parsed"]
    has_dex_file = False
    for name in lower:
        if name.startswith("classes") and name.endswith(".dex"):
            has_dex_file = True
            break
    if "androidmanifest.xml" in lower and has_dex_file:
        return "apk", notes
    has_class_file = False
    for name in lower:
        if name.endswith(".class"):
            has_class_file = True
            break
    if "meta-inf/manifest.mf" in lower and has_class_file:
        return "jar", notes
    return "zip", notes


def ole_offset(sector, sector_size):
#OLE sectors start after the 512-byte header
    return 512 + sector * sector_size


def parse_ole(data):
#old office files are OLE containers, so we just parse enough to list streams
    parsed = {"names": [], "streams": {}}
    if not data.startswith(OLE_MAGIC) or len(data) < 512:
        return parsed
    try:
        sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        mini_sector_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        first_dir = struct.unpack_from("<i", data, 0x30)[0]
        mini_cutoff = struct.unpack_from("<I", data, 0x38)[0]
        first_mini_fat = struct.unpack_from("<i", data, 0x3C)[0]
        mini_fat_count = struct.unpack_from("<I", data, 0x40)[0]
        fat = []
#the FAT tells us which sectors belong to each stream
        for sector in struct.unpack_from("<109I", data, 0x4C):
            if sector not in {0xFFFFFFFF, 0xFFFFFFFE}:
                pos = ole_offset(sector, sector_size)
                if pos + sector_size <= len(data):
                    fat.extend(struct.unpack("<" + "I" * (sector_size // 4), data[pos : pos + sector_size]))

        def read_chain(start, limit=None):
#follow a normal sector chain
            chunks, seen, sector = [], set(), start
            while sector not in {0xFFFFFFFE, 0xFFFFFFFF} and sector >= 0 and sector not in seen and sector < len(fat):
                seen.add(sector)
                pos = ole_offset(sector, sector_size)
                if pos + sector_size > len(data):
                    break
                chunks.append(data[pos : pos + sector_size])
                if limit and sum(map(len, chunks)) >= limit:
                    break
                sector = fat[sector]
            blob = b"".join(chunks)
            return blob[:limit] if limit else blob

        directory = read_chain(first_dir)
        entries = []
#directory entries have stream names and stream starting sectors
        for pos in range(0, len(directory) - 127, 128):
            entry = directory[pos : pos + 128]
            name_len = struct.unpack_from("<H", entry, 64)[0]
            if 2 <= name_len <= 64:
                name = entry[: name_len - 2].decode("utf-16le", "ignore").strip("\x00")
                if name:
                    entries.append(
                        {
                            "name": name,
                            "type": entry[66],
                            "start": struct.unpack_from("<I", entry, 116)[0],
                            "size": struct.unpack_from("<Q", entry, 120)[0],
                        }
                    )

        parsed["names"] = []
        for entry in entries:
            parsed["names"].append(entry["name"])
#small streams live in the mini stream, which is a little annoying
        root = None
        for entry in entries:
            if entry["type"] == 5:
                root = entry
                break
        mini_stream = read_chain(root["start"], root["size"]) if root else b""
        mini_fat_blob = b""
        sector = first_mini_fat
        for _ in range(mini_fat_count):
            if sector in {0xFFFFFFFE, 0xFFFFFFFF} or sector < 0 or sector >= len(fat):
                break
            pos = ole_offset(sector, sector_size)
            if pos + sector_size > len(data):
                break
            mini_fat_blob += data[pos : pos + sector_size]
            sector = fat[sector]
        mini_fat = list(struct.unpack("<" + "I" * (len(mini_fat_blob) // 4), mini_fat_blob)) if mini_fat_blob else []

        def read_mini_chain(start, limit):
#same idea as read_chain, just with mini sectors
            chunks, seen, sector = [], set(), start
            while sector not in {0xFFFFFFFE, 0xFFFFFFFF} and sector >= 0 and sector not in seen and sector < len(mini_fat):
                seen.add(sector)
                pos = sector * mini_sector_size
                if pos + mini_sector_size > len(mini_stream):
                    break
                chunks.append(mini_stream[pos : pos + mini_sector_size])
                if sum(map(len, chunks)) >= limit:
                    break
                sector = mini_fat[sector]
            return b"".join(chunks)[:limit]

        streams = {}
#only keep stream data we actually might use
        for entry in entries:
            if entry["type"] != 2 or entry["size"] <= 0:
                continue
            size = min(int(entry["size"]), 2_000_000)
            if entry["size"] < mini_cutoff and mini_fat and mini_stream:
                streams[entry["name"]] = read_mini_chain(entry["start"], size)
            else:
                streams[entry["name"]] = read_chain(entry["start"], size)
        parsed["streams"] = streams
    except (struct.error, ValueError):
        pass
    return parsed


def infer_encrypted_ooxml(parsed):
#encrypted docx/xlsx/pptx files are OLE wrappers around a hidden zip
    names = []
    for name in parsed.get("names", []):
        names.append(str(name))
    streams = dict(parsed.get("streams", {}))
    text = "\n".join(names)
    for name in ("\x01CompObj", "\x05SummaryInformation", "\x05DocumentSummaryInformation"):
        text += "\n" + decode_text(streams.get(name, b"")[:200_000])
    text = text.lower()
    clues = []
    family = None
    has_word_text = False
    for word in ("word.document", "microsoft word", "wordprocessing", "msword"):
        if word in text:
            has_word_text = True
            break
    if has_word_text:
        family, detected, possible = "word", "docx", ["docx", "docm"]
        clues.append("Word metadata")
    else:
        has_excel_text = False
        for word in ("excel.sheet", "microsoft excel", "spreadsheet"):
            if word in text:
                has_excel_text = True
                break
        has_powerpoint_text = False
        for word in ("powerpoint", "presentationml"):
            if word in text:
                has_powerpoint_text = True
                break
    if family is None and has_excel_text:
        family, detected, possible = "excel", "xlsx", ["xlsx", "xlsm"]
        clues.append("Excel metadata")
    elif family is None and has_powerpoint_text:
        family, detected, possible = "powerpoint", "pptx", ["pptx", "pptm", "ppsx"]
        clues.append("PowerPoint metadata")
    elif family is None:
        detected, possible = "docx", ["docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ppsx"]

#only claim macros when there is readable evidence outside the encrypted blob
    has_macros = None
    has_macro_text = False
    for word in ("macroenabled", "macro-enabled", "vbaproject", "vba", "docm", "xlsm", "pptm"):
        if word in text:
            has_macro_text = True
            break
    if has_macro_text:
        has_macros = True
        clues.append("macro metadata")
        if family == "word":
            detected = "docm"
        elif family == "excel":
            detected = "xlsm"
        elif family == "powerpoint":
            detected = "pptm"

    slideshow = None
    if family == "powerpoint":
#ppsx is only defensible if readable metadata hints at slideshow
        slideshow = False
        for word in ("powerpoint.show", "slideshow", "slide show", "ppsx"):
            if word in text:
                slideshow = True
                break
        if slideshow and has_macros is not True:
            detected = "ppsx"
            clues.append("slideshow metadata")

    notes = [
        "Encrypted OOXML Office package stream found",
        "EncryptedPackage hides the OOXML ZIP; subtype is inferred from readable OLE metadata",
    ]
    if family is None:
        notes.append("Readable OLE metadata does not prove the Office family; reporting docx as the conservative assignment-compatible Office type")
    if has_macros is None:
        notes.append("No readable pre-encryption macro evidence was found; macro status cannot be proven")

    info = {
        "encrypted": True,
        "password_protected": True,
        "has_macros": has_macros,
        "language_code": None,
        "page_count": None,
        "encrypted_office_package": True,
        "reported_concrete_type": detected,
        "subtype_confidence": "inferred" if family else "uncertain",
        "office_family": family,
        "inferred_from": clues,
        "possible_subtypes": possible,
        "slideshow_evidence": slideshow,
        "notes": notes + ["language_code and page_count cannot be extracted because the OOXML payload is encrypted"],
        "ole_streams_seen": names[:30],
    }
    return detected, info, notes


def detect_ole_type(data):
#figure out old Office vs encrypted OOXML vs installer-ish OLE files
    parsed = parse_ole(data)
    names = set()
    for name in parsed["names"]:
        names.add(name.lower())
    if {"encryptedpackage", "encryptioninfo"} <= names:
        detected, _, notes = infer_encrypted_ooxml(parsed)
        return detected, notes
    if "worddocument" in names:
        return "doc", []
    if "workbook" in names or "book" in names:
        return "xls", []
    if "powerpoint document" in names:
        return "ppt", []
    has_msi_stream = False
    for name in names:
        if name.startswith("!_"):
            has_msi_stream = True
            break
    if names & {"\x05digital signature", "\x05microsoft digital signature", "_stringpool", "_strings", "_tables", "_columns", "_validation"} or has_msi_stream:
        return "msi", []
    has_patch_stream = False
    for name in names:
        if name.startswith("patch"):
            has_patch_stream = True
            break
    if "patchmetadata" in names or has_patch_stream:
        return "msp", []
    has_publisher_stream = False
    for name in names:
        if "publisher" in name:
            has_publisher_stream = True
            break
    if names & {"contents", "quill", "escher", "mspublisherdoc", "publisherdocument"} or has_publisher_stream:
        return "pub", []
    return "doc", ["OLE Compound File detected; exact Office subtype is uncertain"]


def detect_type(path, data):
#main content-based detection function
    ext = path.suffix.lower()
    if path.is_dir() and ext == ".app":
        return "app", []
    if is_lnk(data):
        return "lnk", []
    if is_sqlite_db(data):
        return "db", ["SQLite database header found"]
    if data.startswith(b"MZ"):
        return detect_pe_type(data, ext), []
    if data.startswith(b"%PDF-"):
        return "pdf", []
    if data.startswith(OLE_MAGIC):
        return detect_ole_type(data)
#zip has lots of subtypes, so inspect the central directory
    #this one is from https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return detect_zip_type(path)
    #i found it from https://www.rarlab.com/technote.htm
    if data.startswith((b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01\x00")):
        return "rar", []
    if data.startswith(SEVEN_Z_MAGIC):
        return "7z", []
    if data.startswith((b"CWS", b"FWS", b"ZWS")):
        return "swf", []
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif", []
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", []
    if data.startswith(b"\xff\xd8\xff"):
        return ("jpeg" if ext == ".jpeg" else "jpg"), []
    if data.startswith(b"BM"):
        return "bmp", []
    if data.startswith(b"ITSF"):
        return "chm", []
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso", []
    if data.startswith(b"\x1f\x8b\x08"):
        return "gz", []
    if data.startswith(b"BZh"):
        return "bz2", []
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "class", []
    if data.startswith(b"ID3") or (len(data) > 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
        return "mp3", []
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav", []
    if data.startswith(b"RIFF") and data[8:12] == b"AVI ":
        return "avi", []
    if len(data) > 12 and data[4:8] == b"ftyp":
        return ("mov" if data[8:12].lower() == b"qt  " else "mp4"), []
    if tarfile.is_tarfile(path):
        return "tar", []

#after the binary signatures, try text/script formats
    sample = data[:100_000].lstrip(b"\xef\xbb\xbf")
    first_line = sample.splitlines()[0].strip().lower() if sample.splitlines() else b""
    if first_line.startswith(b"#!") and b"python" in first_line:
        return "py", []
    if first_line.startswith(b"#!") and b"ruby" in first_line:
        return "rb", []
    if first_line.startswith(b"#!") and re.search(br"(?:ba|z|k)?sh\b", first_line):
        return "sh", []

    text_sample = decode_text(sample)
#email  formats come before script regexes
    if is_mhtml_text(text_sample):
        return "mhtml", []
    if is_eml_text(text_sample):
        return "eml", []
    for file_type, pattern in SCRIPT_PATTERNS:
        if pattern.search(sample):
            return file_type, []
    if ext == ".tmp":
        return "tmp", ["Temporary extension with no stronger content signature"]
    if not data:
        return "tmp", ["Empty file"]
    return "unknown", []


def zip_password_protected(path):
#zip stores an encrypted flag on each file entry
    try:
        with zipfile.ZipFile(path) as zf:
            encrypted = []
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    encrypted.append(info.filename)
        return bool(encrypted), encrypted[:20]
    except zipfile.BadZipFile as exc:
        return None, [f"Could not parse ZIP central directory: {exc}"]


def rar_password_info(data):
#we check for rar in this func
    if data.startswith(b"Rar!\x1A\x07\x01\x00"):
        encrypted = b"\x06\xf1\x07\x01" in data[:200_000] or b"\x01\x07\xf1\x06" in data[:200_000]
        return {"password_protected": encrypted, "rar_version": 5, "evidence": ["RAR5 AES marker found"] if encrypted else ["No RAR5 AES marker found in readable prefix"]}
    if data.startswith(b"Rar!\x1A\x07\x00") and len(data) >= 13:
        flags = struct.unpack_from("<H", data, 10)[0]
        encrypted = bool(flags & 0x0080)
        return {"password_protected": encrypted, "rar_version": 4, "evidence": ["RAR4 encrypted headers flag present"] if encrypted else ["RAR4 encrypted headers flag not set"]}
    return {"password_protected": None, "rar_version": None, "evidence": ["RAR version not recognized"]}


def seven_zip_password_info(data):
#7z encryption usually shows up as an AES method id in the header
    info = {"password_protected": None, "evidence": []}
    if not data.startswith(SEVEN_Z_MAGIC) or len(data) < 32:
        return info
    try:
        header_crc = struct.unpack_from("<I", data, 8)[0]
        header_offset = struct.unpack_from("<Q", data, 12)[0]
        header_size = struct.unpack_from("<Q", data, 20)[0]
        header_data_crc = struct.unpack_from("<I", data, 28)[0]
        header_start = 32 + header_offset
        header_end = header_start + header_size
        header = data[header_start:header_end] if header_end <= len(data) else b""
#crc checks are helpful, but I still keep going if they fail
        if zlib.crc32(data[12:32]) & 0xFFFFFFFF != header_crc:
            info["evidence"].append("7z signature header CRC did not validate")
        if header and zlib.crc32(header) & 0xFFFFFFFF != header_data_crc:
            info["evidence"].append("7z next header CRC did not validate")
    except struct.error:
        header = b""

    searchable = header or data[:2_000_000]
#this is the 7z AES-256 method id in either byte order seen in headers
    aes_found = b"\x06\xf1\x07\x01" in searchable or b"\x01\x07\xf1\x06" in searchable
    if aes_found:
        info["password_protected"] = True
        info["evidence"].append("7z AES-256 method ID found")
    elif header:
        info["password_protected"] = False
        info["evidence"].append("7z header was readable and no AES method ID was found")
    else:
        info["password_protected"] = None
        info["evidence"].append("Could not read the complete 7z header, so password protection is uncertain")
    return info


def looks_like_real_ipv4(text):
#this function helps to filter out section numbers in document so they dont get detected as ip addresses since they look similar
    parts = text.split(".")
    small_parts = 0
    for part in parts:
        if int(part) <= 5:
            small_parts += 1
    if small_parts == 4:
        return False
    if int(parts[0]) <= 5 and int(parts[1]) <= 5 and int(parts[2]) <= 5:
        return False
    return True


def extract_network_indicators(text):
#pull out basic network indicators for PDFs and raw text
    ips = []
    for item in IP_RE.findall(text):
        if not looks_like_real_ipv4(item):
            continue
        try:
            ipaddress.ip_address(item)
            ips.append(item)
        except ValueError:
            pass
    return {
        "urls": unique_sorted(URL_RE.findall(text)),
        "ip_addresses": unique_sorted(ips),
        "domains": unique_sorted(DOMAIN_RE.findall(text)),
    }


def analyze_pdf(path, data):
#start with raw bytes so this still works without pypdf
    result = {"password_protected": b"/Encrypt" in data[:2_000_000]}
    result.update(extract_network_indicators(decode_text(data)))
    try:
        logging.getLogger("pypdf").setLevel(logging.ERROR)
        from pypdf import PdfReader  # type: ignore  # Reads PDF encryption and page info in analyze_pdf().

        reader = PdfReader(str(path))
#if pypdf is installed, it gives better encryption/page/text info
        result["password_protected"] = bool(reader.is_encrypted)
        if not reader.is_encrypted:
            extracted_parts = []
            for page in reader.pages:
                extracted_parts.append(page.extract_text() or "")
            extracted = "\n".join(extracted_parts)
            result.update(extract_network_indicators(decode_text(data) + "\n" + extracted))
            result["pages"] = len(reader.pages)
    except ImportError:
        result["pdf_parser"] = "pypdf not installed; used raw byte scan"
    except Exception as exc:
        result["pdf_parser_error"] = str(exc)
    return result


def xml_root(text):
#office metadata is xml bad xml just means no value
    if not text:
        return None
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None


def xml_tag_name(tag):
#strip the namespace part from tags like {namespace}Pages
    return tag.rsplit("}", 1)[-1]


def xml_text(root, wanted):
#find a simple text value by tag name
    if root is None:
        return None
    for elem in root.iter():
        if xml_tag_name(elem.tag) == wanted and elem.text and elem.text.strip():
            return elem.text.strip()
    return None


def xml_int(root, wanted):
#same as xml_text but for numbers like page count
    value = xml_text(root, wanted)
    return int(value) if value and value.isdigit() else None


def analyze_ooxml(path, file_type):
#modern Office files are zip files with XML metadata
    info = {
        "encrypted": False,
        "password_protected": False,
        "has_macros": False,
        "language_code": None,
        "page_count": None,
        "notes": [],
    }
    try:
        with zipfile.ZipFile(path) as zf:
            names = zip_name_map(zf)
            lower = set(names)
    #check for passwrod protected zips in office
            protected, encrypted_entries = zip_password_protected(path)
            info["password_protected"] = protected
            info["encrypted"] = bool(protected)
            info["encrypted_entries"] = encrypted_entries
            info["has_macros"] = False
            for name in lower:
                if name.endswith("vbaproject.bin"):
                    info["has_macros"] = True
                    break

#docProps has the easy metadata when Office saved it
            app = xml_root(zip_text(zf, names, "docProps/app.xml"))
            core = xml_root(zip_text(zf, names, "docProps/core.xml"))
            info["application"] = xml_text(app, "Application")
            info["language_code"] = xml_text(core, "language")
            info["page_count"] = xml_int(app, "Pages")
            info["slide_count"] = xml_int(app, "Slides")
            info["worksheet_count"] = xml_int(app, "Worksheets")
            info["word_count"] = xml_int(app, "Words")

            if not info["language_code"]:
#language is not always in core.xml, so try a few obvious document parts
                xml_candidates = ["word/settings.xml", "xl/workbook.xml", "xl/styles.xml", "ppt/presentation.xml", "ppt/slides/slide1.xml"]
                for name in xml_candidates:
                    match = re.search(r'(?:\b(?:w:|a:)?lang|xml:lang)\s*=\s*["\']([a-z]{2,3}(?:[-_][A-Z]{2})?)["\']', zip_text(zf, names, name), re.I)
                    if match:
                        info["language_code"] = match.group(1).replace("_", "-")
                        break

            protection_sources = {
                "word/settings.xml": ("documentProtection", "writeProtection"),
                "xl/workbook.xml": ("workbookProtection", "fileSharing"),
                "ppt/presentation.xml": ("modifyVerifier", "presentationProtection"),
            }
#these are edit protection markers, not always full encryption
            for name, markers in protection_sources.items():
                text = zip_text(zf, names, name)
                has_marker = False
                for marker in markers:
                    if marker in text:
                        has_marker = True
                        break
                if has_marker:
                    info["password_protected"] = True
                    info["notes"].append(f"Protection marker found in {name}")
#excel can protect individual sheets too
            for name in lower:
                if name.startswith("xl/worksheets/") and name.endswith(".xml") and "sheetProtection" in zip_text(zf, names, name):
                    info["password_protected"] = True
                    info["notes"].append(f"Sheet protection marker found in {name}")
                    break

#PowerPoint does slides, Excel does sheets, so page count is not always literal
            if file_type in {"pptx", "pptm", "ppsx"} and info["page_count"] is None and info["slide_count"] is not None:
                info["page_count"] = info["slide_count"]
                info["notes"].append("PowerPoint slide count is reported as the closest page-count equivalent")
            elif file_type in {"xlsx", "xlsm"} and info["page_count"] is None:
                info["notes"].append("Excel OOXML does not consistently store page count; worksheet_count is the closest extracted equivalent")
            elif file_type in {"docx", "docm"} and info["page_count"] is None:
                info["notes"].append("Word page count was not present in OOXML app properties")
            if not info["language_code"]:
                info["notes"].append("No explicit language metadata was found")
    except zipfile.BadZipFile as exc:
        info["error"] = f"Could not parse OOXML zip: {exc}"
    return info


def parse_property_set(stream):
#old Office summary streams use this propertyset format
    props = {}
    if len(stream) < 48:
        return props
    try:
        section_count = struct.unpack_from("<I", stream, 24)[0]
        for section_index in range(min(section_count, 2)):
#each section has a little table of property ids and offsets
            section_offset = struct.unpack_from("<I", stream, 28 + section_index * 20 + 16)[0]
            prop_count = struct.unpack_from("<I", stream, section_offset + 4)[0]
            entries = []
            for i in range(min(prop_count, 256)):
                if section_offset + 16 + i * 8 <= len(stream):
                    entries.append(struct.unpack_from("<II", stream, section_offset + 8 + i * 8))
            codepage = 1252
#property 1 is usually the codepage for string decoding
            for prop_id, rel_offset in entries:
                pos = section_offset + rel_offset
                if pos + 8 <= len(stream) and prop_id == 1:
                    variant = struct.unpack_from("<I", stream, pos)[0]
                    if variant == 2:
                        codepage = struct.unpack_from("<h", stream, pos + 4)[0]
            for prop_id, rel_offset in entries:
                pos = section_offset + rel_offset
                if pos + 8 > len(stream):
                    continue
                variant = struct.unpack_from("<I", stream, pos)[0]
                value = stream[pos + 4 :]
#only parse the simple value types we actually use
                if variant == 2:
                    props[prop_id] = struct.unpack_from("<h", value, 0)[0]
                elif variant == 3:
                    props[prop_id] = struct.unpack_from("<i", value, 0)[0]
                elif variant == 30 and len(value) >= 4:
                    length = struct.unpack_from("<I", value, 0)[0]
                    raw = value[4 : 4 + max(0, length - 1)]
                    try:
                        props[prop_id] = raw.decode("utf-8" if codepage == 65001 else f"cp{codepage}", "ignore")
                    except LookupError:
                        props[prop_id] = raw.decode("latin-1", "ignore")
                elif variant == 31 and len(value) >= 4:
                    chars = struct.unpack_from("<I", value, 0)[0]
                    props[prop_id] = value[4 : 4 + max(0, chars - 1) * 2].decode("utf-16le", "ignore")
    except (struct.error, ValueError):
        pass
    return props


def analyze_ole_office(data, file_type):
#legacy doc/xls/ppt files use OLE instead of zip
    parsed = parse_ole(data)
    names = list(parsed["names"])
    lower = set()
    for name in names:
        lower.add(name.lower())
    streams = dict(parsed["streams"])

    if {"encryptedpackage", "encryptioninfo"} <= lower:
#this is actually encrypted OOXML inside an OLE wrapper
        _, info, _ = infer_encrypted_ooxml(parsed)
        return info

    props = {}
#summary streams may have pages, codepage, and language-ish values
    for name in ("\x05SummaryInformation", "\x05DocumentSummaryInformation"):
        props.update(parse_property_set(streams.get(name, b"")))

    encrypted = False
    notes = []
#these are simple format-specific encryption checks
    if file_type == "doc" and len(streams.get("WordDocument", b"")) >= 12:
        encrypted = bool(struct.unpack_from("<H", streams["WordDocument"], 0x0A)[0] & 0x0100)
        if encrypted:
            notes.append("Word FIB encryption flag is set")
    if file_type == "xls" and (streams.get("Workbook") or streams.get("Book")):
        workbook = streams.get("Workbook", b"") or streams.get("Book", b"")
        encrypted = b"\x2f\x00" in workbook[:500_000]
        if encrypted:
            notes.append("Excel BIFF FilePass record appears in workbook stream")
    has_encrypt_name = False
    for name in lower:
        if "encrypt" in name:
            has_encrypt_name = True
            break
    if file_type == "ppt" and has_encrypt_name:
        encrypted = True
        notes.append("PowerPoint encryption marker appears in OLE stream names")

    language = None
#some Office property sets store language at these ids
    for prop_id in (26, 27):
        if isinstance(props.get(prop_id), str):
            language = props[prop_id]
            break
    if not language and isinstance(props.get(1), int):
        language = f"codepage-{props[1]}"

    page_count = props.get(14) if isinstance(props.get(14), int) else None
#Excel and PowerPoint do not always have a clean page count here
    if file_type in {"xls", "ppt"} and page_count is None:
        notes.append("Page count is not reliably available in this legacy Office format")
    if not language:
        notes.append("No explicit language metadata was found")

    has_macros = False
    for name in lower:
        if "vba" in name or name in {"_vba_project", "dir"}:
            has_macros = True
            break

    return {
        "encrypted": encrypted,
        "password_protected": encrypted,
        "has_macros": has_macros,
        "language_code": language,
        "page_count": page_count,
        "encrypted_office_package": False,
        "notes": notes,
        "ole_streams_seen": names[:30],
    }


def analyze_archive(file_type, path, data):
#one small wrapper so analyze_path stays readable
    if file_type in {"zip", "jar", "apk", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ppsx"}:
        protected, details = zip_password_protected(path)
        return {"password_protected": protected, "encrypted_entries": details}
    if file_type == "rar":
        return rar_password_info(data)
    if file_type == "7z":
        return seven_zip_password_info(data)
    if file_type in {"gz", "bz2", "tar"}:
        return {"password_protected": False, "note": "This archive format usually does not provide native password encryption"}
    return {}


def extension_matches(extension, detected):
#just for making sure   
    if not extension:
        return False
    if extension in {"jpg", "jpeg"}:
        return detected in {"jpg", "jpeg"}
    return extension == detected


def analyze_path(path):
#analyze one file or app bundle path
    result = make_result(path, path.exists())
    if not path.exists():
        result["errors"].append("File does not exist")
        return result

    result["extension"] = path.suffix.lower().lstrip(".")
    try:
        result["size"] = path.stat().st_size
#read a prefix first so big files do not cost too much
        data = b"" if path.is_dir() else read_prefix(path)
        detected, notes = detect_type(path, data)
#7z header can be near the end, so read the whole file only for 7z
        if detected == "7z" and not path.is_dir() and result["size"] and result["size"] > len(data):
            data = path.read_bytes()

        result["detected_type"] = detected
        result["description"] = DESCRIPTION_BY_TYPE.get(detected, "Known file type")
        result["notes"].extend(notes)
        result["extension_matches"] = extension_matches(result["extension"].lower(), detected.lower())
        if result["extension"] and not result["extension_matches"]:
            result["notes"].append(f"Extension .{result['extension']} does not match detected type {detected}")

        if detected in {"zip", "rar", "7z", "gz", "bz2", "tar", "jar", "apk"}:
            result["indicators"]["archive"] = analyze_archive(detected, path, data)
        if detected == "pdf":
            result["indicators"]["pdf"] = analyze_pdf(path, data)
#Office files get the assignment-required metadata checks
        if detected in {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ppsx"}:
            if data.startswith(OLE_MAGIC):
                result["indicators"]["office"] = analyze_ole_office(data, detected)
            else:
                result["indicators"]["archive"] = analyze_archive(detected, path, data)
                result["indicators"]["office"] = analyze_ooxml(path, detected)
        if detected in {"doc", "xls", "ppt", "msi", "msp", "pub"}:
            result["indicators"]["office"] = analyze_ole_office(data, detected)
    except PermissionError as exc:
        result["errors"].append(f"Permission denied: {exc}")
    except OSError as exc:
        result["errors"].append(str(exc))
    return result


def iter_targets(paths, recursive):
#expand command-line targets
    for raw in paths:
        path = Path(raw)
        if recursive and path.is_dir() and path.suffix.lower() != ".app":
            children = []
            for child in path.rglob("*"):
                if child.is_file() or child.suffix.lower() == ".app":
                    children.append(child)
            for child in sorted(children):
                yield child
        else:
            yield path


def add_text_value(lines, label, value, indent):
#format list and dict values without dumping everything on one ugly line
    space = " " * indent
    if isinstance(value, dict):
        lines.append(f"{space}{label}:")
        if not value:
            lines.append(f"{space}  none")
        for key, inner_value in value.items():
            add_text_value(lines, key, inner_value, indent + 2)
    elif isinstance(value, list):
        lines.append(f"{space}{label}:")
        if not value:
            lines.append(f"{space}  none")
        for item in value:
            lines.append(f"{space}  - {item}")
    else:
        lines.append(f"{space}{label}: {value}")


def html_value(value):
#same idea as the text output, but safe for the html report
    if isinstance(value, dict):
        if not value:
            return "<span class=\"muted\">none</span>"
        parts = ["<dl class=\"mini-list\">"]
        for key, inner_value in value.items():
            parts.append(f"<dt>{html.escape(str(key))}</dt>")
            parts.append(f"<dd>{html_value(inner_value)}</dd>")
        parts.append("</dl>")
        return "".join(parts)
    if isinstance(value, list):
        if not value:
            return "<span class=\"muted\">none</span>"
        parts = ["<ul class=\"value-list\">"]
        for item in value:
            parts.append(f"<li>{html.escape(str(item))}</li>")
        parts.append("</ul>")
        return "".join(parts)
    if value is None:
        return "<span class=\"muted\">none</span>"
    return html.escape(str(value))


def render_text(results):
#plain text output for normal runs
    lines = []
    for result in results:
        lines.append("=" * 72)
        lines.append(f"File: {result['path']}")
        lines.append("-" * 72)
        if not result["exists"]:
            lines.append("Errors:")
            lines.append("  - file does not exist")
            lines.append("")
            continue
        lines.append("Basic info:")
        lines.append(f"  Type:             {result['detected_type']} ({result['description']})")
        lines.append(f"  Size:             {result['size']} bytes")
        if result["extension"]:
            lines.append(f"  Extension:        .{result['extension']}")
            lines.append(f"  Extension match:  {result['extension_matches']}")
        if result["notes"]:
            lines.append("")
            lines.append("Notes:")
            for note in result["notes"]:
                lines.append(f"  - {note}")
        if result["indicators"]:
            lines.append("")
            lines.append("Analysis:")
            for section, values in result["indicators"].items():
                lines.append(f"  {section.capitalize()}:")
                if isinstance(values, dict):
                    if not values:
                        lines.append("    none")
                    for key, value in values.items():
                        add_text_value(lines, key, value, 4)
                else:
                    add_text_value(lines, "value", values, 4)
        if result["errors"]:
            lines.append("")
            lines.append("Errors:")
            for error in result["errors"]:
                lines.append(f"  - {error}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_html_report(results, destination):
#same info as text/json, but easier to read in a browser
    cards = []
    for result in results:
        notes_html = html_value(result["notes"])
        errors_html = html_value(result["errors"])
        indicator_parts = []
        if result["indicators"]:
            for section, values in result["indicators"].items():
                indicator_parts.append(
                    f"<section class=\"sub-block\"><h3>{html.escape(section.capitalize())}</h3>{html_value(values)}</section>"
                )
        else:
            indicator_parts.append("<p class=\"muted\">none</p>")
        cards.append(
            "<article class=\"result-card\">"
            "<div class=\"card-top\">"
            f"<h2>{html.escape(result['path'])}</h2>"
            f"<span class=\"type-pill\">{html.escape(result['detected_type'])}</span>"
            "</div>"
            "<div class=\"summary-grid\">"
            f"<div><span>Description</span><strong>{html.escape(result['description'])}</strong></div>"
            f"<div><span>Size</span><strong>{result['size'] if result['size'] is not None else 'none'}</strong></div>"
            f"<div><span>Extension</span><strong>{html.escape(result['extension'] or 'none')}</strong></div>"
            f"<div><span>Extension match</span><strong>{html.escape(str(result['extension_matches']))}</strong></div>"
            "</div>"
            "<div class=\"detail-grid\">"
            f"<section><h3>Notes</h3>{notes_html}</section>"
            f"<section><h3>Errors</h3>{errors_html}</section>"
            "</div>"
            "<section class=\"analysis-block\"><h3>Analysis</h3>"
            f"{''.join(indicator_parts)}"
            "</section>"
            "</article>"
        )

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Static Analysis Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      background: #f3f6f8;
      color: #1f2933;
    }}
    .page {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px;
    }}
    header {{
      margin-bottom: 22px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 28px;
    }}
    .muted {{
      color: #667085;
    }}
    .result-card {{
      background: white;
      border: 1px solid #d7dee7;
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
    }}
    .card-top {{
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: flex-start;
      border-bottom: 1px solid #e5eaf0;
      padding-bottom: 12px;
      margin-bottom: 14px;
    }}
    h2 {{
      margin: 0;
      font-size: 18px;
      word-break: break-word;
    }}
    h3 {{
      margin: 0 0 8px;
      font-size: 14px;
      color: #334155;
    }}
    .type-pill {{
      background: #e8f1ff;
      color: #1d4f91;
      border: 1px solid #c8dcf7;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 13px;
      white-space: nowrap;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }}
    .summary-grid div {{
      background: #f8fafc;
      border: 1px solid #e5eaf0;
      border-radius: 6px;
      padding: 10px;
    }}
    .summary-grid span {{
      display: block;
      color: #667085;
      font-size: 12px;
      margin-bottom: 4px;
    }}
    .summary-grid strong {{
      font-size: 14px;
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
      margin-bottom: 14px;
    }}
    .analysis-block, .detail-grid section, .sub-block {{
      border: 1px solid #e5eaf0;
      border-radius: 6px;
      padding: 12px;
      background: #fbfcfe;
    }}
    .sub-block {{
      margin-top: 10px;
      background: #ffffff;
    }}
    .value-list {{
      margin: 0;
      padding-left: 20px;
    }}
    .value-list li {{
      margin: 3px 0;
      word-break: break-word;
    }}
    .mini-list {{
      margin: 0;
      display: grid;
      grid-template-columns: minmax(130px, 220px) 1fr;
      gap: 7px 12px;
    }}
    .mini-list dt {{
      color: #475569;
      font-weight: bold;
      word-break: break-word;
    }}
    .mini-list dd {{
      margin: 0;
      word-break: break-word;
    }}
    @media (max-width: 650px) {{
      .page {{ padding: 16px; }}
      .card-top {{ display: block; }}
      .type-pill {{ display: inline-block; margin-top: 10px; }}
      .mini-list {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <header>
      <h1>Static Analysis Report</h1>
      <p class="muted">Generated: {html.escape(now)}</p>
    </header>
    {''.join(cards)}
  </main>
</body>
</html>
"""
    destination.write_text(document, encoding="utf-8")


def parse_args(argv):
#keep the CLI small and predictable
    parser = argparse.ArgumentParser(description="Identify true file types and run basic static checks on suspicious files.")
    #for the path of the file
    parser.add_argument("paths", nargs="+", help="Files or directories to analyze")
    #for the recursive flag in case we need to go inside folders
    parser.add_argument("-r", "--recursive", action="store_true", help="Analyze files inside directories recursively")
    #just for the json format if user wants output like that
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    #in case html is prefered
    parser.add_argument("--html-report", type=Path, help="Write an HTML report for all analyzed files")
    return parser.parse_args(argv)


def main(argv = None):
#main is just parse args, analyze targets, print output
    args = parse_args(argv or sys.argv[1:])
    results = []
    for path in iter_targets(args.paths, args.recursive):
        results.append(analyze_path(path))
    if args.json:
        json_results = []
        for result in results:
            json_results.append(result)
        print(json.dumps(json_results, indent=2, ensure_ascii=False))
    else:
        print(render_text(results), end="")
    if args.html_report:
        write_html_report(results, args.html_report)
        print(f"HTML report written to {args.html_report}")
    has_errors = False
    for result in results:
        if result["errors"]:
            has_errors = True
            break
    if has_errors:
        return 1
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
