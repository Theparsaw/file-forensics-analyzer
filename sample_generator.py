"""
generate_strict_test_samples.py
================================

Strict validation dataset generator for the assignment
    "Assignment 1 Automated Basic Static and Dynamic Analysis Tool - 2026"

This script generates a directory tree of test samples and a JSON manifest
describing the ground truth for every sample. It is intentionally adversarial:
it builds *real* internal structures (ZIP central directories, OOXML parts,
PDF cross-reference tables, OLE/CFBF compound files, PE/COFF stubs, etc.)
so that a file-type analyzer cannot pass merely by sniffing the first few
magic bytes.

Design goals
------------
* Pure Python where feasible. Standard library only.
* When a format cannot be produced strictly (e.g. RAR, 7z, real signed MSI,
  encrypted PDF with real RC4/AES), the script emits the closest honest
  fallback and labels it as ``synthetic_fallback`` in the manifest.
* Deterministic output: a single ``--seed`` value controls all randomness.
* Manifest entries are explicit about *realism_level* and *limitations*.

Usage
-----
    python3 generate_strict_test_samples.py [--out strict_samples] [--seed 1337]

The output layout is::

    strict_samples/
        honest/
        disguised/
        edge_cases/
        feature_checks/
        ground_truth_manifest.json

Author: generated for Parsa's static/dynamic analysis assignment.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import struct
import sys
import time
import zipfile
import zlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Manifest data structures
# ---------------------------------------------------------------------------


@dataclass
class SampleRecord:
    """Ground-truth metadata for a single generated sample."""

    filename: str
    path: str
    displayed_extension: str
    true_type: str
    family: str
    should_detect_as: str
    should_be_disguised: bool = False
    password_protected_expected: bool = False
    encrypted_expected: bool = False
    has_macros_expected: bool = False
    language_code_expected: str | None = None
    page_count_expected: int | None = None
    urls_expected: list[str] = field(default_factory=list)
    ip_addresses_expected: list[str] = field(default_factory=list)
    domains_expected: list[str] = field(default_factory=list)
    notes: str = ""
    generation_method: str = ""
    realism_level: str = "real"  # real | partially_real | synthetic_fallback
    limitations: str = ""


class Manifest:
    """Accumulates SampleRecord entries and writes the manifest JSON."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.records: list[SampleRecord] = []
        self.expected_categories: set[str] = set()
        self.generated_categories: set[str] = set()

    def add(self, rec: SampleRecord) -> None:
        self.records.append(rec)
        self.generated_categories.add(rec.true_type)

    def expect(self, *types: str) -> None:
        self.expected_categories.update(types)

    def write(self) -> Path:
        out = self.root / "ground_truth_manifest.json"
        payload = {
            "generator": "generate_strict_test_samples.py",
            "generated_at": int(time.time()),
            "root": str(self.root),
            "sample_count": len(self.records),
            "samples": [asdict(r) for r in self.records],
        }
        out.write_text(json.dumps(payload, indent=2))
        return out

    def assert_coverage(self) -> None:
        missing = self.expected_categories - self.generated_categories
        if missing:
            raise RuntimeError(
                "Generation incomplete; missing true_type coverage for: "
                + ", ".join(sorted(missing))
            )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def ensure_dirs(root: Path) -> dict[str, Path]:
    """Create the four bucket directories and return them as a dict."""
    buckets = {
        "honest": root / "honest",
        "disguised": root / "disguised",
        "edge_cases": root / "edge_cases",
        "feature_checks": root / "feature_checks",
    }
    for p in buckets.values():
        p.mkdir(parents=True, exist_ok=True)
    return buckets


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def rel(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


# Fixed timestamp so every ZIP member has the same date/time fields,
# guaranteeing byte-for-byte deterministic output across runs.
_FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def zip_writestr(zf: zipfile.ZipFile, arcname: str, data: bytes | str,
                 compress_type: int = zipfile.ZIP_DEFLATED) -> None:
    """Deterministic ZipFile.writestr: fixes the date and external attrs."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    info = zipfile.ZipInfo(filename=arcname, date_time=_FIXED_ZIP_DATE)
    info.compress_type = compress_type
    info.external_attr = 0o600 << 16
    zf.writestr(info, data)


# ---------------------------------------------------------------------------
# ZIP / OOXML construction
# ---------------------------------------------------------------------------
# We use zipfile for ZIP-family containers. OOXML is just a ZIP with a fixed
# internal layout of XML parts. We hand-write those XML parts so that
# docProps/core.xml and docProps/app.xml can carry the language and page-count
# metadata required by the assignment.


# Minimal OOXML XML fragments. Kept small but valid enough that strict
# OOXML parsers (python-docx, openpyxl, python-pptx) accept them.

_CT_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CT_DOCM = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CT_XLSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CT_XLSM = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CT_PPTX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CT_PPSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml"/>
  <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_RELS_ROOT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""


def _core_xml(lang: str | None, title: str = "Sample Document") -> bytes:
    """docProps/core.xml carries dc:language and dc:title."""
    lang_line = f'  <dc:language>{lang}</dc:language>\n' if lang else ""
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<cp:coreProperties\n'
        '    xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"\n'
        '    xmlns:dc="http://purl.org/dc/elements/1.1/"\n'
        '    xmlns:dcterms="http://purl.org/dc/terms/"\n'
        '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        f'  <dc:title>{title}</dc:title>\n'
        '  <dc:creator>strict_generator</dc:creator>\n'
        f'{lang_line}'
        '</cp:coreProperties>\n'
    )
    return body.encode("utf-8")


def _app_xml_word(pages: int | None) -> bytes:
    """docProps/app.xml for Word: <Pages> drives page-count detection."""
    pages_line = f'  <Pages>{pages}</Pages>\n' if pages is not None else ""
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"\n'
        '            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">\n'
        '  <Application>strict_generator</Application>\n'
        f'{pages_line}'
        '</Properties>\n'
    )
    return body.encode("utf-8")


def _app_xml_generic() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">\n'
        b'  <Application>strict_generator</Application>\n'
        b'</Properties>\n'
    )


def _document_xml(paragraphs: list[str]) -> bytes:
    """Minimal word/document.xml with one paragraph per string."""
    ps = "\n".join(
        f'    <w:p><w:r><w:t xml:space="preserve">{p}</w:t></w:r></w:p>'
        for p in paragraphs
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '  <w:body>\n'
        f'{ps}\n'
        '  </w:body>\n'
        '</w:document>\n'
    )
    return body.encode("utf-8")


def _xlsx_workbook_xml() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"\n'
        b'          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        b'  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>\n'
        b'</workbook>\n'
    )


def _xlsx_workbook_rels() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        b'  <Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        b'Target="worksheets/sheet1.xml"/>\n'
        b'</Relationships>\n'
    )


def _xlsx_sheet_xml(rows: list[list[str]]) -> bytes:
    row_xml = []
    for ri, row in enumerate(rows, start=1):
        cells = "".join(
            f'<c r="{chr(64+ci)}{ri}" t="inlineStr"><is><t>{v}</t></is></c>'
            for ci, v in enumerate(row, start=1)
        )
        row_xml.append(f'<row r="{ri}">{cells}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
        '  <sheetData>\n  '
        + "\n  ".join(row_xml)
        + '\n  </sheetData>\n</worksheet>\n'
    ).encode("utf-8")


def _pptx_presentation_xml() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"\n'
        b'                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        b'  <p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>\n'
        b'</p:presentation>\n'
    )


def _pptx_presentation_rels() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        b'  <Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
        b'Target="slides/slide1.xml"/>\n'
        b'</Relationships>\n'
    )


def _pptx_slide_xml(text: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"\n'
        '       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">\n'
        '  <p:cSld><p:spTree>\n'
        '    <p:sp><p:txBody><a:p><a:r><a:t>' + text + '</a:t></a:r></a:p></p:txBody></p:sp>\n'
        '  </p:spTree></p:cSld>\n'
        '</p:sld>\n'
    ).encode("utf-8")


def _fake_vba_project_bin() -> bytes:
    """
    A real vbaProject.bin is a CFBF compound document containing the VBA
    project streams. Producing a parseable VBA project in pure Python is a
    project unto itself, so we emit a CFBF *header* (so the OLE sniffer
    in the analyzer recognizes it) plus an arbitrary tail. The presence
    of this stream, plus the macro-enabled content type override, is what
    a real-world macro detector keys on for OOXML; the analyzer should
    flag has_macros=True without needing to interpret VBA.
    """
    ole_sig = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    return ole_sig + b"\x00" * 504 + b"VBA_PROJECT_STRUCTURED_STORAGE_FALLBACK"


def build_ooxml(
    target_path: Path,
    *,
    family: str,
    lang: str | None,
    pages: int | None,
    macros: bool,
    paragraphs: list[str] | None = None,
    sheet_rows: list[list[str]] | None = None,
    slide_text: str = "Strict generator slide",
    slideshow: bool = False,
) -> None:
    """
    Build a real OOXML container at *target_path*.

    family is one of: 'word', 'excel', 'powerpoint'.
    """
    paragraphs = paragraphs or ["Hello from the strict generator."]
    sheet_rows = sheet_rows or [["A", "B"], ["1", "2"]]

    with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as z:
        if family == "word":
            ct = _CT_DOCM if macros else _CT_DOCX
            zip_writestr(z, "[Content_Types].xml", ct)
            zip_writestr(z, 
                "_rels/.rels",
                _RELS_ROOT.format(target="word/document.xml"),
            )
            zip_writestr(z, "word/document.xml", _document_xml(paragraphs))
            zip_writestr(z, "docProps/core.xml", _core_xml(lang))
            zip_writestr(z, "docProps/app.xml", _app_xml_word(pages))
            if macros:
                zip_writestr(z, "word/vbaProject.bin", _fake_vba_project_bin())

        elif family == "excel":
            ct = _CT_XLSM if macros else _CT_XLSX
            zip_writestr(z, "[Content_Types].xml", ct)
            zip_writestr(z, 
                "_rels/.rels",
                _RELS_ROOT.format(target="xl/workbook.xml"),
            )
            zip_writestr(z, "xl/workbook.xml", _xlsx_workbook_xml())
            zip_writestr(z, "xl/_rels/workbook.xml.rels", _xlsx_workbook_rels())
            zip_writestr(z, "xl/worksheets/sheet1.xml", _xlsx_sheet_xml(sheet_rows))
            zip_writestr(z, "docProps/core.xml", _core_xml(lang))
            zip_writestr(z, "docProps/app.xml", _app_xml_generic())
            if macros:
                zip_writestr(z, "xl/vbaProject.bin", _fake_vba_project_bin())

        elif family == "powerpoint":
            ct = _CT_PPSX if slideshow else _CT_PPTX
            zip_writestr(z, "[Content_Types].xml", ct)
            zip_writestr(z, 
                "_rels/.rels",
                _RELS_ROOT.format(target="ppt/presentation.xml"),
            )
            zip_writestr(z, "ppt/presentation.xml", _pptx_presentation_xml())
            zip_writestr(z, "ppt/_rels/presentation.xml.rels", _pptx_presentation_rels())
            zip_writestr(z, "ppt/slides/slide1.xml", _pptx_slide_xml(slide_text))
            zip_writestr(z, "docProps/core.xml", _core_xml(lang))
            zip_writestr(z, "docProps/app.xml", _app_xml_generic())

        else:
            raise ValueError(f"unknown family: {family}")


# ---------------------------------------------------------------------------
# PE / COFF construction (exe / dll / scr)
# ---------------------------------------------------------------------------
# We build a *real* minimal PE32 image with a valid DOS header, NT headers,
# section table, and one .text section containing 4 bytes of code. The
# Characteristics and Subsystem fields are tweaked so that a competent
# analyzer can distinguish:
#   exe -> IMAGE_SUBSYSTEM_WINDOWS_GUI, no DLL flag
#   dll -> IMAGE_FILE_DLL set
#   scr -> same shape as exe (the .scr distinction is purely by extension and
#          is the *whole point* of including it as a disguise case)
#
# References:
#   https://learn.microsoft.com/en-us/windows/win32/debug/pe-format


_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_32BIT_MACHINE = 0x0100
_IMAGE_FILE_DLL = 0x2000
_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3


def build_pe(is_dll: bool = False) -> bytes:
    """
    Build a tiny but structurally valid PE32 image.

    The resulting file will not actually run, but it has:
      * a real DOS stub with MZ + e_lfanew
      * a real "PE\\0\\0" signature
      * a real IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER (PE32)
      * one section header for .text
      * raw bytes for the .text section

    That is enough for any reasonable PE parser (pefile, LIEF, file(1)) to
    classify it correctly.
    """
    # ---- DOS header (64 bytes) + tiny DOS stub ----
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    # ---- NT headers ----
    nt_signature = b"PE\x00\x00"

    machine = 0x014C  # IMAGE_FILE_MACHINE_I386
    number_of_sections = 1
    time_date_stamp = 0
    pointer_to_symbol_table = 0
    number_of_symbols = 0
    size_of_optional_header = 224  # PE32 standard size
    characteristics = _IMAGE_FILE_EXECUTABLE_IMAGE | _IMAGE_FILE_32BIT_MACHINE
    if is_dll:
        characteristics |= _IMAGE_FILE_DLL

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    )

    # Optional header (PE32). Magic 0x10B.
    section_alignment = 0x1000
    file_alignment = 0x200
    size_of_image = section_alignment * 2  # headers + one section virtual page
    size_of_headers = file_alignment
    address_of_entry_point = section_alignment  # start of .text in memory
    base_of_code = section_alignment

    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,                # Magic = PE32
        1, 0,                 # Major/Minor linker version
        0x200,                # SizeOfCode
        0,                    # SizeOfInitializedData
        0,                    # SizeOfUninitializedData
        address_of_entry_point,
        base_of_code,
        0,                    # BaseOfData (PE32 only)
        0x400000,             # ImageBase
        section_alignment,
        file_alignment,
        6, 0,                 # Major/Minor OS version
        0, 0,                 # Major/Minor image version
        6, 0,                 # Major/Minor subsystem version
        0,                    # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,                    # CheckSum
        _IMAGE_SUBSYSTEM_WINDOWS_GUI,
        0,                    # DllCharacteristics
        0x100000, 0x1000,     # SizeOf{Stack,Heap}Reserve
        0x100000, 0x1000,     # SizeOf{Stack,Heap}Commit
        0,                    # LoaderFlags
        16,                   # NumberOfRvaAndSizes
    )
    # 16 data directories, all zero
    optional_header += b"\x00" * (8 * 16)

    # ---- Section header for .text ----
    section_name = b".text\x00\x00\x00"
    virtual_size = 0x200
    virtual_address = section_alignment
    size_of_raw_data = file_alignment
    pointer_to_raw_data = file_alignment
    section_characteristics = 0x60000020  # CODE | EXECUTE | READ
    section = struct.pack(
        "<8sIIIIIIHHI",
        section_name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        0, 0, 0, 0,
        section_characteristics,
    )

    headers = dos + nt_signature + file_header + optional_header + section
    # Pad headers to file_alignment
    headers += b"\x00" * (file_alignment - len(headers))

    # ---- Section data: just a RET so the file is not entirely null ----
    text_section = b"\xC3" + b"\x00" * (file_alignment - 1)

    return bytes(headers + text_section)


# ---------------------------------------------------------------------------
# OLE / CFBF construction (doc, xls, ppt, msi, msp, pub)
# ---------------------------------------------------------------------------
# A real fully-featured CFBF (Compound File Binary Format) writer is hundreds
# of lines. We build the minimum that lets a binary identifier classify the
# file as "OLE Compound Document" and recover the CLSID from the root entry,
# which is what most identifiers key on to tell a Word .doc from an Excel
# .xls from an MSI.
#
# Layout (one 512-byte sector each):
#   sector -1:  CFBF header
#   sector  0:  FAT (single-sector FAT for tiny files)
#   sector  1:  Directory stream with Root Entry, with CLSID set
#
# References:
#   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/

# Well-known CLSIDs (mixed-endian as stored on disk: data1/2/3 little-endian,
# data4 raw bytes).
_CLSID_WORD_DOC   = "00020906-0000-0000-C000-000000000046"
_CLSID_EXCEL_XLS  = "00020820-0000-0000-C000-000000000046"
_CLSID_POWERPOINT = "64818D10-4F9B-11CF-86EA-00AA00B929E8"
_CLSID_MSI        = "000C1084-0000-0000-C000-000000000046"
_CLSID_MSP        = "000C1086-0000-0000-C000-000000000046"
_CLSID_PUBLISHER  = "0002123D-0000-0000-C000-000000000046"


def _clsid_to_bytes(clsid: str) -> bytes:
    """
    GUID string -> 16-byte on-disk form.
    First three groups little-endian; last two groups raw.
    """
    parts = clsid.split("-")
    data1 = int(parts[0], 16).to_bytes(4, "little")
    data2 = int(parts[1], 16).to_bytes(2, "little")
    data3 = int(parts[2], 16).to_bytes(2, "little")
    data4 = bytes.fromhex(parts[3] + parts[4])
    return data1 + data2 + data3 + data4


def build_ole(clsid: str, root_name: str = "Root Entry") -> bytes:
    """
    Build a tiny CFBF compound file with a Root Entry whose CLSID is *clsid*.

    Tools like ``file(1)``, libmagic, oletools.olefile, and Python's
    ``olefile`` will recognise the file as an OLE compound document and
    extract the CLSID, which is what differentiates .doc / .xls / .ppt /
    .msi / .msp / .pub at the binary level.
    """
    sector_size = 512
    header = bytearray(sector_size)
    header[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"     # CFBF signature
    header[8:24] = b"\x00" * 16                           # CLSID (unused)
    struct.pack_into("<H", header, 24, 0x003E)            # minor version
    struct.pack_into("<H", header, 26, 0x0003)            # dll version (512-byte sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)            # byte order (little)
    struct.pack_into("<H", header, 30, 9)                 # sector shift = 2**9 = 512
    struct.pack_into("<H", header, 32, 6)                 # mini sector shift = 2**6 = 64
    struct.pack_into("<I", header, 44, 1)                 # number of FAT sectors
    struct.pack_into("<I", header, 48, 1)                 # first directory sector
    struct.pack_into("<I", header, 56, 4096)              # mini stream cutoff
    struct.pack_into("<I", header, 60, 0xFFFFFFFE)        # first mini-FAT sector
    struct.pack_into("<I", header, 64, 0)                 # number of mini-FAT sectors
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)        # first DIFAT sector
    struct.pack_into("<I", header, 72, 0)                 # number of DIFAT sectors
    # DIFAT array (109 entries starting at offset 76). Sector 0 holds the FAT.
    struct.pack_into("<I", header, 76, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 76 + 4 * i, 0xFFFFFFFF)

    # ---- Sector 0: FAT ----
    fat = bytearray(sector_size)
    # FAT[0] = 0xFFFFFFFD (FAT self-marker), FAT[1] = 0xFFFFFFFE (end of dir chain)
    for i in range(0, sector_size, 4):
        struct.pack_into("<I", fat, i, 0xFFFFFFFF)
    struct.pack_into("<I", fat, 0, 0xFFFFFFFD)
    struct.pack_into("<I", fat, 4, 0xFFFFFFFE)

    # ---- Sector 1: Directory sector containing the Root Entry ----
    directory = bytearray(sector_size)
    name_utf16 = root_name.encode("utf-16-le") + b"\x00\x00"
    # Pad/truncate to 64 bytes
    name_field = (name_utf16 + b"\x00" * 64)[:64]
    directory[0:64] = name_field
    struct.pack_into("<H", directory, 64, len(name_utf16))    # name length incl null
    directory[66] = 5                                          # type = root storage
    directory[67] = 1                                          # colour = black
    struct.pack_into("<I", directory, 68, 0xFFFFFFFF)          # left sibling
    struct.pack_into("<I", directory, 72, 0xFFFFFFFF)          # right sibling
    struct.pack_into("<I", directory, 76, 0xFFFFFFFF)          # child
    directory[80:96] = _clsid_to_bytes(clsid)                  # root CLSID
    struct.pack_into("<I", directory, 116, 0xFFFFFFFE)         # starting sector of mini stream
    struct.pack_into("<Q", directory, 120, 0)                  # mini stream size
    # Remaining directory entries: empty
    for slot in range(1, 4):
        off = 128 * slot
        directory[off + 66] = 0                                # type = unallocated

    return bytes(header + fat + directory)


# ---------------------------------------------------------------------------
# PDF construction
# ---------------------------------------------------------------------------
# We hand-write a minimal but valid PDF with a cross-reference table and
# trailer. Multi-page support, embedded text URLs/IPs/domains, and a
# "fake-encrypted" variant (with /Encrypt entry but no real cipher) are all
# supported here.


def build_pdf(pages_text: list[str], *, fake_encrypt: bool = False) -> bytes:
    """
    Build a valid PDF with one page per string in *pages_text*.

    The cross-reference offsets are computed by writing objects into a
    BytesIO and recording their start positions, so the resulting file
    survives a strict xref parser.

    If *fake_encrypt* is True, an /Encrypt entry is added to the trailer
    referencing an Encrypt dict object. Real PDF encryption uses RC4 or AES
    over object streams; we do not implement that. Detectors that key on
    the presence of /Encrypt in the trailer will flag this correctly; tools
    that try to actually decrypt will fail. This is honest and is documented
    in the manifest as ``synthetic_fallback`` for the password-protected
    sample.
    """
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

    offsets: list[int] = []  # index 0 unused (PDF objects are 1-based)

    def write_obj(num: int, body: bytes) -> None:
        while len(offsets) <= num:
            offsets.append(0)
        offsets[num] = buf.tell()
        buf.write(f"{num} 0 obj\n".encode())
        buf.write(body)
        if not body.endswith(b"\n"):
            buf.write(b"\n")
        buf.write(b"endobj\n")

    page_count = len(pages_text)

    # Object 1: Catalog
    write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    # Object 2: Pages root
    kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(page_count))
    write_obj(
        2,
        f"<< /Type /Pages /Count {page_count} /Kids [ {kids} ] >>".encode(),
    )

    # For each page: page object + content stream object
    for i, text in enumerate(pages_text):
        page_obj_num = 3 + 2 * i
        content_obj_num = 4 + 2 * i
        write_obj(
            page_obj_num,
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Contents {content_obj_num} 0 R "
                f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
                f"/BaseFont /Helvetica >> >> >> >>"
            ).encode(),
        )
        # PDF text strings: parentheses need escaping. Keep characters safe.
        safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream_body = (
            "BT\n/F1 12 Tf\n72 720 Td\n("
            + safe
            + ") Tj\nET\n"
        ).encode("latin-1", errors="replace")
        content = (
            b"<< /Length "
            + str(len(stream_body)).encode()
            + b" >>\nstream\n"
            + stream_body
            + b"\nendstream"
        )
        write_obj(content_obj_num, content)

    encrypt_obj_num = None
    if fake_encrypt:
        encrypt_obj_num = len(offsets)
        write_obj(
            encrypt_obj_num,
            (
                b"<< /Filter /Standard /V 1 /R 2 /Length 40 "
                b"/P -4 /O <00> /U <00> >>"
            ),
        )

    # xref
    xref_offset = buf.tell()
    num_objects = len(offsets)  # offsets has a leading 0 placeholder
    buf.write(f"xref\n0 {num_objects}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for i in range(1, num_objects):
        buf.write(f"{offsets[i]:010d} 00000 n \n".encode())

    # trailer
    trailer = f"<< /Size {num_objects} /Root 1 0 R"
    if encrypt_obj_num is not None:
        trailer += f" /Encrypt {encrypt_obj_num} 0 R /ID [<deadbeef> <cafef00d>]"
    trailer += " >>"
    buf.write(b"trailer\n" + trailer.encode() + b"\nstartxref\n")
    buf.write(f"{xref_offset}\n%%EOF\n".encode())
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Plain image, archive, script, mail, db builders
# ---------------------------------------------------------------------------


def build_png(width: int = 4, height: int = 4) -> bytes:
    """Build a trivially valid PNG (single IDAT chunk, no filter)."""
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b""
    for _ in range(height):
        raw += b"\x00" + b"\xFF\x00\x00" * width   # red scanlines
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def build_jpeg() -> bytes:
    """
    Build a minimal JPEG.

    The smallest *truly decodable* JPEG is non-trivial to hand-build because
    of Huffman tables. We embed a known-good 1x1 white JPEG.
    """
    # 1x1 white JPEG, taken from the public domain "smallest valid JPEG"
    # canonical example. Decoded by libjpeg/Pillow/file(1).
    return bytes.fromhex(
        "ffd8ffe000104a46494600010100000100010000ffdb004300080606070605080707"
        "07090908"
        "0a0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c20242e2720222c231c1c283729"
        "2c30313434"
        "1f27393d38323c2e333432ffc0000b080001000101011100ffc4001f000001050101"
        "0101010100"
        "000000000000000102030405060708090a0bffc400b5100002010303020403050504"
        "040000017d"
        "01020300041105122131410613516107227114328191a1082342b1c11552d1f02433"
        "62728"
        "2090a161718191a25262728292a3435363738393a434445464748494a535455565758"
        "595a"
        "636465666768696a737475767778797a838485868788898a92939495969798999aa2"
        "a3a4a5"
        "a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2"
        "e3e4e5"
        "e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda0008010100003f00fbd0ffd9"
    )


def build_gif() -> bytes:
    """Trivial 1x1 GIF87a."""
    # Hand-crafted minimal GIF87a:
    # Header  : "GIF87a"
    # LSD     : 1x1, GCT flag, etc.
    # GCT     : 2 colours (black, white)
    # Image   : 1x1
    return bytes.fromhex(
        "474946383761"          # "GIF87a"
        "01000100"              # 1x1
        "80"                    # GCTF=1, color resolution=0, sorted=0, GCT size=0 (2 entries)
        "0000"                  # background, pixel aspect
        "000000ffffff"          # GCT: black, white
        "2c00000000010001000000"  # Image descriptor (1x1)
        "02024401"              # LZW image data
        "00"                    # block terminator
        "3b"                    # GIF trailer
    )


def build_bmp(width: int = 2, height: int = 2) -> bytes:
    """24-bit uncompressed BMP."""
    row_size = ((width * 3 + 3) // 4) * 4
    pixel_data = b""
    for _ in range(height):
        row = b"\x00\x00\xFF" * width  # red BGR
        row += b"\x00" * (row_size - len(row) % row_size) if len(row) % row_size else b""
        pixel_data += row
    pixel_offset = 54
    file_size = pixel_offset + len(pixel_data)
    file_header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, pixel_offset)
    dib = struct.pack(
        "<IiiHHIIiiII",
        40, width, height, 1, 24, 0, len(pixel_data), 2835, 2835, 0, 0,
    )
    return file_header + dib + pixel_data


def build_wav(seconds: float = 0.05, freq: int = 440, rate: int = 8000) -> bytes:
    """A short PCM WAV tone."""
    import math
    n = int(seconds * rate)
    samples = bytearray()
    for i in range(n):
        v = int(127 * math.sin(2 * math.pi * freq * i / rate)) + 128
        samples.append(v & 0xFF)
    data_chunk = b"data" + struct.pack("<I", len(samples)) + bytes(samples)
    fmt_chunk = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate, 1, 8)
    riff = (
        b"RIFF"
        + struct.pack("<I", 4 + len(fmt_chunk) + len(data_chunk))
        + b"WAVE"
        + fmt_chunk
        + data_chunk
    )
    return riff


def build_mp3() -> bytes:
    """
    Minimal MP3: an ID3v2 header followed by an MPEG-1 Layer III frame
    header. Encoding actual audio would require a Layer III encoder which
    is well beyond scope; the detection target is the header signature.
    """
    id3 = b"ID3\x03\x00\x00" + b"\x00\x00\x00\x00"  # ID3v2.3, size = 0
    # MPEG-1 Layer III, 128 kbps, 44.1 kHz, no padding, stereo, no CRC
    # Frame sync 11 bits all 1, MPEG-1 (11), Layer III (01), no CRC protection (1)
    # -> 0xFF 0xFB ...
    frame = b"\xFF\xFB\x90\x00" + b"\x00" * 415  # 419-byte frame (typical 128k @ 44.1)
    return id3 + frame


def build_mp4() -> bytes:
    """
    Minimal MP4: a single ``ftyp`` box. This is what every MP4 detector
    keys on; no real video track is present, which is honestly noted.
    """
    body = b"isom\x00\x00\x02\x00isomiso2avc1mp41"
    size = 8 + len(body)
    return struct.pack(">I", size) + b"ftyp" + body


def build_mov() -> bytes:
    """Minimal QuickTime MOV: an ``ftyp`` box with the qt brand."""
    body = b"qt  \x00\x00\x02\x00qt  "
    size = 8 + len(body)
    return struct.pack(">I", size) + b"ftyp" + body


def build_avi() -> bytes:
    """Minimal AVI RIFF skeleton sufficient for header sniffing."""
    hdrl = b"LIST" + struct.pack("<I", 4) + b"hdrl"
    movi = b"LIST" + struct.pack("<I", 4) + b"movi"
    payload = b"AVI " + hdrl + movi
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


# ---------------------------------------------------------------------------
# Gzip / bzip2 / tar
# ---------------------------------------------------------------------------


def build_gz(payload: bytes = b"strict generator gzip payload\n") -> bytes:
    import gzip
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(payload)
    return buf.getvalue()


def build_bz2(payload: bytes = b"strict generator bzip2 payload\n") -> bytes:
    import bz2
    return bz2.compress(payload)


def build_tar(name: str = "hello.txt", payload: bytes = b"strict tar payload\n") -> bytes:
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Script / text / structured-text builders
# ---------------------------------------------------------------------------


def build_lnk(target: str = "C:\\\\Windows\\\\System32\\\\cmd.exe") -> bytes:
    """
    Build a minimal Windows .lnk shell-link.

    Full .lnk parsing is governed by MS-SHLLINK. We emit just the ShellLink
    header so a detector sees the canonical GUID
    ``{00021401-0000-0000-C000-000000000046}``. No LinkTargetIDList or
    LinkInfo is included; LinkFlags is 0. This is enough for header-based
    detection and is documented honestly.
    """
    # HeaderSize (76) + LinkCLSID (16) + LinkFlags (4) + FileAttributes (4)
    # + CreationTime (8) + AccessTime (8) + WriteTime (8) + FileSize (4)
    # + IconIndex (4) + ShowCommand (4) + HotKey (2) + Reserved (2+4+4)
    link_clsid = _clsid_to_bytes("00021401-0000-0000-C000-000000000046")
    header = (
        struct.pack("<I", 76)
        + link_clsid
        + struct.pack("<I", 0)                  # LinkFlags = 0
        + struct.pack("<I", 0x20)               # FILE_ATTRIBUTE_ARCHIVE
        + struct.pack("<Q", 0)                  # CreationTime
        + struct.pack("<Q", 0)                  # AccessTime
        + struct.pack("<Q", 0)                  # WriteTime
        + struct.pack("<I", 0)                  # FileSize
        + struct.pack("<I", 0)                  # IconIndex
        + struct.pack("<I", 1)                  # SW_SHOWNORMAL
        + struct.pack("<H", 0)                  # HotKey
        + struct.pack("<H", 0)                  # Reserved1
        + struct.pack("<I", 0)                  # Reserved2
        + struct.pack("<I", 0)                  # Reserved3
    )
    # Add a trailing trivia comment with the target string so a strings(1)
    # scan finds something useful.
    return header + b"# target: " + target.encode()


def build_chm() -> bytes:
    """
    Build a CHM stub: just the ITSF signature and a few required fields.
    Full CHM is huge; the analyzer's reference detector will key on "ITSF".
    Marked synthetic_fallback in the manifest.
    """
    return (
        b"ITSF"
        + struct.pack("<I", 3)            # version
        + struct.pack("<I", 0x60)         # header length
        + b"\x00" * 4                     # unknown
        + struct.pack("<I", int(time.time())) + b"\x00" * 84
    )


def build_swf() -> bytes:
    """Uncompressed SWF stub (signature FWS)."""
    # Header: FWS, version, file length, RECT (frame size), frame rate, count
    # We construct a trivial valid header. Truncated file is fine for sniffing.
    return b"FWS\x08" + struct.pack("<I", 32) + b"\x00" * 24


def build_eps() -> bytes:
    """EPS = PostScript with the EPSF comment."""
    return (
        b"%!PS-Adobe-3.0 EPSF-3.0\n"
        b"%%BoundingBox: 0 0 100 100\n"
        b"%%Creator: strict_generator\n"
        b"%%Title: tiny.eps\n"
        b"newpath 50 50 25 0 360 arc stroke\n"
        b"showpage\n"
        b"%%EOF\n"
    )


def build_ps() -> bytes:
    """PostScript (non-EPSF)."""
    return (
        b"%!PS-Adobe-3.0\n"
        b"%%Creator: strict_generator\n"
        b"/Times-Roman findfont 12 scalefont setfont\n"
        b"72 720 moveto (Strict generator PostScript) show\n"
        b"showpage\n"
    )


def build_rtf(text: str = "Hello from strict RTF.") -> bytes:
    return (
        b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Courier;}}\n"
        + text.encode("latin-1", errors="replace")
        + b"\\par\n}\n"
    )


def build_mhtml(html_body: str) -> bytes:
    """Single-part MHTML."""
    boundary = "----=_strict_generator"
    msg = (
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/related; boundary=\"{boundary}\"\r\n"
        f"Subject: Strict generator MHTML\r\n"
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Transfer-Encoding: 8bit\r\n"
        f"\r\n"
        f"{html_body}\r\n"
        f"--{boundary}--\r\n"
    )
    return msg.encode("utf-8")


def build_eml(html_body: str, subject: str = "Strict eml") -> bytes:
    return (
        f"From: generator@example.com\r\n"
        f"To: analyst@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"\r\n"
        f"{html_body}\r\n"
    ).encode("utf-8")


def build_iso(label: bytes = b"STRICTGEN".ljust(32)) -> bytes:
    """
    Build an ISO-9660 stub: 16 sectors of zero (system area) followed by a
    Primary Volume Descriptor. Sufficient for ``file(1)``-style detection
    via the "CD001" identifier. Marked synthetic_fallback in the manifest.
    """
    sector = 2048
    system_area = b"\x00" * (16 * sector)
    pvd = bytearray(sector)
    pvd[0] = 1                              # type = PVD
    pvd[1:6] = b"CD001"                     # identifier
    pvd[6] = 1                              # version
    pvd[40:72] = label                      # volume identifier
    return system_area + bytes(pvd)


def build_db_sqlite() -> bytes:
    """A genuine empty SQLite database."""
    import sqlite3
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE strict (id INTEGER PRIMARY KEY, note TEXT);")
        conn.execute("INSERT INTO strict(note) VALUES ('hello');")
        conn.commit()
        conn.close()
        return Path(path).read_bytes()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def build_apk(manifest_xml: bytes, dex_bytes: bytes, arsc_bytes: bytes) -> bytes:
    """
    APK = ZIP with AndroidManifest.xml, classes.dex, resources.arsc.

    The contents of those files are *not* parsed by extension-based
    detectors, so we put structurally plausible-looking bytes in them and
    document this as partially_real in the manifest.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "AndroidManifest.xml", manifest_xml)
        zip_writestr(z, "classes.dex", dex_bytes)
        zip_writestr(z, "resources.arsc", arsc_bytes)
        zip_writestr(z, "META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return buf.getvalue()


def build_jar() -> bytes:
    """JAR = ZIP with META-INF/MANIFEST.MF and at least one .class file."""
    buf = io.BytesIO()
    # Minimal .class: 0xCAFEBABE magic + minor/major + constant pool count of 1
    klass = (
        b"\xCA\xFE\xBA\xBE"
        + struct.pack(">H", 0)          # minor version
        + struct.pack(">H", 52)         # major version (Java 8)
        + struct.pack(">H", 1)          # constant_pool_count
        + struct.pack(">H", 0)          # access flags
        + struct.pack(">H", 0)          # this_class
        + struct.pack(">H", 0)          # super_class
        + struct.pack(">H", 0)          # interfaces
        + struct.pack(">H", 0)          # fields
        + struct.pack(">H", 0)          # methods
        + struct.pack(">H", 0)          # attributes
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, 
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nMain-Class: Hello\r\n",
        )
        zip_writestr(z, "Hello.class", klass)
    return buf.getvalue()


def build_zip_password_protected(password: str = "infected") -> bytes:
    """
    Build a ZIP whose central directory entries are flagged as encrypted.

    Python's stdlib ``zipfile`` can READ password-protected ZIPs but cannot
    WRITE them. We construct the archive by hand: a Local File Header with
    the general-purpose bit 0 (encryption) set, a 12-byte traditional
    PKZIP encryption header, and matching Central Directory entries.

    The payload bytes are *not* actually encrypted with PKZIP's stream
    cipher; reproducing that cipher takes ~30 lines, and the goal here is
    to fool detectors that key on the encryption bit and on the
    presence of the encryption header, not to produce a file that real
    unzip will decrypt. The manifest labels this as ``partially_real`` and
    documents the limitation.
    """
    filename = b"secret.txt"
    payload = b"This payload is marked encrypted in the ZIP central directory.\n"

    # Local File Header (encryption bit set, no compression)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    flags = 0x0001  # bit 0 = encrypted
    encryption_header = b"\x00" * 12  # placeholder, real PKZIP would derive this
    file_data = encryption_header + payload
    lfh = (
        b"PK\x03\x04"
        + struct.pack(
            "<HHHHHIIIHH",
            20,                              # version needed
            flags,                           # general purpose bit
            0,                               # compression method = stored
            0, 0,                            # last mod time/date
            crc,
            len(file_data),                  # compressed size
            len(payload),                    # uncompressed size
            len(filename),
            0,                               # extra field length
        )
        + filename
    )
    lfh_offset = 0  # first entry
    body = lfh + file_data

    # Central Directory entry
    cd = (
        b"PK\x01\x02"
        + struct.pack(
            "<HHHHHHIIIHHHHHII",
            20, 20,                          # version made by / needed
            flags,
            0,                               # compression
            0, 0,                            # time/date
            crc,
            len(file_data),
            len(payload),
            len(filename),
            0, 0,                            # extra, comment
            0, 0,                            # disk / int attrs
            0,                               # external attrs
            lfh_offset,
        )
        + filename
    )
    cd_offset = len(body)
    body += cd

    # End of Central Directory
    eocd = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, 1, 1, len(cd), cd_offset, 0
    )
    body += eocd
    return body


# ---------------------------------------------------------------------------
# Sample-emission helpers
# ---------------------------------------------------------------------------
# Each emitter accepts the manifest and the bucket directory, generates one
# or more files, writes them to disk, and registers ground-truth records.
# Emitters are grouped by bucket.


# Reusable text content for feature-validation samples.
_FEATURE_URLS = [
    "https://malware-test.example.com/payload",
    "http://evil.example.org/login.php?id=42",
]
_FEATURE_IPS = ["10.20.30.40", "192.0.2.123"]
_FEATURE_DOMAINS = ["evil.example.org", "malware-test.example.com"]
_FEATURE_TEXT_BLOB = (
    "Contact-us at https://malware-test.example.com/payload or "
    "http://evil.example.org/login.php?id=42. "
    "Beacons resolved to 10.20.30.40 and 192.0.2.123. "
    "Affected domains: evil.example.org and malware-test.example.com."
)


def emit_honest(manifest: Manifest, bucket: Path, root: Path) -> None:
    """Generate samples where extension matches true content."""

    def add(name: str, data: bytes, **kw: Any) -> None:
        p = bucket / name
        write_bytes(p, data)
        manifest.add(
            SampleRecord(
                filename=name,
                path=rel(root, p),
                displayed_extension=name.rsplit(".", 1)[-1],
                **kw,
            )
        )

    # ---- PE family ----
    add(
        "calc.exe",
        build_pe(is_dll=False),
        true_type="exe",
        family="pe",
        should_detect_as="exe",
        notes="Minimal PE32 executable image, Windows GUI subsystem.",
        generation_method="hand-written PE32 with .text section",
        realism_level="real",
    )
    add(
        "kernel32_mini.dll",
        build_pe(is_dll=True),
        true_type="dll",
        family="pe",
        should_detect_as="dll",
        notes="Minimal PE32 with IMAGE_FILE_DLL set.",
        generation_method="hand-written PE32 + DLL characteristic",
        realism_level="real",
    )
    add(
        "screensaver_real.scr",
        build_pe(is_dll=False),
        true_type="scr",
        family="pe",
        should_detect_as="scr",
        notes="A .scr is a PE executable; only extension distinguishes it.",
        generation_method="hand-written PE32 (same as exe)",
        realism_level="real",
    )

    # ---- OOXML family ----
    add(
        "report_en.docx",
        b"",  # placeholder, build below to actual file
        true_type="docx",
        family="ooxml",
        should_detect_as="docx",
        language_code_expected="en-US",
        page_count_expected=3,
        notes="OOXML Word document with language=en-US and Pages=3.",
        generation_method="hand-rolled ZIP with OOXML parts",
        realism_level="real",
    )
    build_ooxml(
        bucket / "report_en.docx",
        family="word",
        lang="en-US",
        pages=3,
        macros=False,
        paragraphs=["English report paragraph one.", "Paragraph two."],
    )

    add(
        "rapor_tr.docx",
        b"",
        true_type="docx",
        family="ooxml",
        should_detect_as="docx",
        language_code_expected="tr-TR",
        page_count_expected=1,
        notes="Turkish-language Word document. Tests dc:language extraction.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    )
    build_ooxml(
        bucket / "rapor_tr.docx",
        family="word",
        lang="tr-TR",
        pages=1,
        macros=False,
        paragraphs=["Türkçe içerikli belge."],
    )

    add(
        "macro_payload.docm",
        b"",
        true_type="docm",
        family="ooxml",
        should_detect_as="docm",
        has_macros_expected=True,
        language_code_expected="en-US",
        page_count_expected=1,
        notes="Macro-enabled Word document. Has word/vbaProject.bin.",
        generation_method="hand-rolled OOXML + CFBF stub for vbaProject.bin",
        realism_level="partially_real",
        limitations="vbaProject.bin is a CFBF stub, not a parseable VBA project.",
    )
    build_ooxml(
        bucket / "macro_payload.docm",
        family="word",
        lang="en-US",
        pages=1,
        macros=True,
        paragraphs=["Document with macros enabled."],
    )

    add(
        "budget.xlsx",
        b"",
        true_type="xlsx",
        family="ooxml",
        should_detect_as="xlsx",
        language_code_expected="en-US",
        notes="OOXML workbook with one worksheet.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    )
    build_ooxml(
        bucket / "budget.xlsx",
        family="excel",
        lang="en-US",
        pages=None,
        macros=False,
        sheet_rows=[["Item", "Qty"], ["foo", "1"], ["bar", "2"]],
    )

    add(
        "auto_open.xlsm",
        b"",
        true_type="xlsm",
        family="ooxml",
        should_detect_as="xlsm",
        has_macros_expected=True,
        notes="Macro-enabled workbook.",
        generation_method="hand-rolled OOXML + CFBF stub for vbaProject.bin",
        realism_level="partially_real",
        limitations="vbaProject.bin is a CFBF stub, not a parseable VBA project.",
    )
    build_ooxml(
        bucket / "auto_open.xlsm",
        family="excel",
        lang="en-US",
        pages=None,
        macros=True,
    )

    add(
        "pitch_deck.pptx",
        b"",
        true_type="pptx",
        family="ooxml",
        should_detect_as="pptx",
        notes="OOXML presentation, one slide.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    )
    build_ooxml(
        bucket / "pitch_deck.pptx",
        family="powerpoint",
        lang=None,
        pages=None,
        macros=False,
        slide_text="Strict generator title slide",
    )

    add(
        "kiosk_loop.ppsx",
        b"",
        true_type="ppsx",
        family="ooxml",
        should_detect_as="ppsx",
        notes=(
            "Slideshow content type. Differs from .pptx only in the override "
            "ContentType for /ppt/presentation.xml."
        ),
        generation_method="hand-rolled OOXML with slideshow content type",
        realism_level="real",
    )
    build_ooxml(
        bucket / "kiosk_loop.ppsx",
        family="powerpoint",
        lang=None,
        pages=None,
        macros=False,
        slideshow=True,
    )

    # ---- Legacy OLE Office ----
    add(
        "legacy_report.doc",
        build_ole(_CLSID_WORD_DOC),
        true_type="doc",
        family="ole",
        should_detect_as="doc",
        notes="CFBF compound file with Word CLSID on the Root Entry.",
        generation_method="hand-written CFBF (header+FAT+root dir)",
        realism_level="partially_real",
        limitations=(
            "No WordDocument stream. Header + CLSID is what binary identifiers "
            "key on; document content cannot be opened by Word."
        ),
    )
    add(
        "legacy_book.xls",
        build_ole(_CLSID_EXCEL_XLS),
        true_type="xls",
        family="ole",
        should_detect_as="xls",
        notes="CFBF compound file with Excel CLSID.",
        generation_method="hand-written CFBF",
        realism_level="partially_real",
        limitations="No Workbook stream; only the CLSID identifies the subtype.",
    )
    add(
        "legacy_show.ppt",
        build_ole(_CLSID_POWERPOINT),
        true_type="ppt",
        family="ole",
        should_detect_as="ppt",
        notes="CFBF compound file with PowerPoint CLSID.",
        generation_method="hand-written CFBF",
        realism_level="partially_real",
        limitations="No PowerPoint Document stream.",
    )
    add(
        "installer_real.msi",
        build_ole(_CLSID_MSI),
        true_type="msi",
        family="ole",
        should_detect_as="msi",
        notes="CFBF with MSI CLSID.",
        generation_method="hand-written CFBF",
        realism_level="partially_real",
        limitations=(
            "Real .msi files carry an embedded Windows Installer database "
            "(tables, summary information stream). Producing one in pure "
            "Python requires reimplementing MSI; out of scope. The CLSID is "
            "correct, which is what file-type sniffers use."
        ),
    )
    add(
        "patch_real.msp",
        build_ole(_CLSID_MSP),
        true_type="msp",
        family="ole",
        should_detect_as="msp",
        notes="CFBF with Windows Installer Patch CLSID.",
        generation_method="hand-written CFBF",
        realism_level="partially_real",
        limitations="No patch payload streams.",
    )
    add(
        "newsletter.pub",
        build_ole(_CLSID_PUBLISHER),
        true_type="pub",
        family="ole",
        should_detect_as="pub",
        notes="CFBF with Microsoft Publisher CLSID.",
        generation_method="hand-written CFBF",
        realism_level="partially_real",
        limitations="No Publisher document streams.",
    )

    # ---- PDF ----
    add(
        "single_page.pdf",
        build_pdf(["Single page PDF generated by strict generator."]),
        true_type="pdf",
        family="pdf",
        should_detect_as="pdf",
        page_count_expected=1,
        notes="Plain one-page PDF.",
        generation_method="hand-written PDF objects+xref",
        realism_level="real",
    )

    # ---- Archives ----
    plain_zip = io.BytesIO()
    with zipfile.ZipFile(plain_zip, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "readme.txt", "Plain ZIP test payload.\n")
        zip_writestr(z, "data/nums.csv", "a,b\n1,2\n3,4\n")
    add(
        "archive_plain.zip",
        plain_zip.getvalue(),
        true_type="zip",
        family="zip",
        should_detect_as="zip",
        notes="Plain unencrypted ZIP with two members.",
        generation_method="zipfile",
        realism_level="real",
    )

    add(
        "image_real.png", build_png(),
        true_type="png", family="image",
        should_detect_as="png",
        notes="Minimal valid PNG with IHDR/IDAT/IEND.",
        generation_method="hand-written PNG chunks",
        realism_level="real",
    )
    add(
        "picture.jpg", build_jpeg(),
        true_type="jpg", family="image",
        should_detect_as="jpg",
        notes="Known-good 1x1 JPEG.",
        generation_method="embedded canonical JPEG bytes",
        realism_level="real",
    )
    add(
        "picture.jpeg", build_jpeg(),
        true_type="jpeg", family="image",
        should_detect_as="jpeg",
        notes="Same content as .jpg with .jpeg extension; tests alias handling.",
        generation_method="embedded canonical JPEG bytes",
        realism_level="real",
    )
    add(
        "animation.gif", build_gif(),
        true_type="gif", family="image",
        should_detect_as="gif",
        notes="GIF87a 1x1.",
        generation_method="hand-written GIF",
        realism_level="real",
    )
    add(
        "bitmap.bmp", build_bmp(),
        true_type="bmp", family="image",
        should_detect_as="bmp",
        notes="24-bit BMP 2x2.",
        generation_method="hand-written BMP",
        realism_level="real",
    )
    svg_bytes = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
        b'<rect width="10" height="10" fill="red"/></svg>\n'
    )
    add(
        "vector.svg", svg_bytes,
        true_type="svg", family="image",
        should_detect_as="svg",
        notes="Plain SVG.",
        generation_method="text",
        realism_level="real",
    )

    # ---- Audio / video ----
    add(
        "tone.wav", build_wav(),
        true_type="wav", family="media",
        should_detect_as="wav",
        notes="Tiny PCM WAV.",
        generation_method="hand-written RIFF/WAVE",
        realism_level="real",
    )
    add(
        "song.mp3", build_mp3(),
        true_type="mp3", family="media",
        should_detect_as="mp3",
        notes="ID3v2 + single MPEG-1 Layer III frame header.",
        generation_method="hand-written ID3+frame header",
        realism_level="partially_real",
        limitations="MP3 frame payload is zero-filled; the frame header is valid.",
    )
    add(
        "clip.mp4", build_mp4(),
        true_type="mp4", family="media",
        should_detect_as="mp4",
        notes="ftyp box only.",
        generation_method="hand-written ftyp",
        realism_level="partially_real",
        limitations="No moov/mdat boxes; sniffers will still match on ftyp.",
    )
    add(
        "clip.mov", build_mov(),
        true_type="mov", family="media",
        should_detect_as="mov",
        notes="QuickTime ftyp.",
        generation_method="hand-written ftyp",
        realism_level="partially_real",
    )
    add(
        "clip.avi", build_avi(),
        true_type="avi", family="media",
        should_detect_as="avi",
        notes="RIFF/AVI skeleton.",
        generation_method="hand-written RIFF",
        realism_level="partially_real",
        limitations="No actual stream data.",
    )

    # ---- Scripts / text / structured-text ----
    add(
        "harmless.js",
        b"// strict generator JS sample\nconsole.log('hello');\n",
        true_type="js", family="script",
        should_detect_as="js",
        generation_method="text",
        realism_level="real",
    )
    add(
        "downloader.vbs",
        b"' VBS sample\r\nWScript.Echo \"strict generator\"\r\n",
        true_type="vbs", family="script",
        should_detect_as="vbs",
        generation_method="text",
        realism_level="real",
    )
    add(
        "script.ps1",
        b"# PowerShell sample\r\nWrite-Host 'strict generator'\r\n",
        true_type="ps1", family="script",
        should_detect_as="ps1",
        generation_method="text",
        realism_level="real",
    )
    add(
        "launcher.bat",
        b"@echo off\r\necho strict generator\r\n",
        true_type="bat", family="script",
        should_detect_as="bat",
        generation_method="text",
        realism_level="real",
    )
    add(
        "shellscript.sh",
        b"#!/bin/sh\necho 'strict generator'\n",
        true_type="sh", family="script",
        should_detect_as="sh",
        generation_method="text",
        realism_level="real",
    )
    add(
        "tool.py",
        b"#!/usr/bin/env python3\nprint('strict generator')\n",
        true_type="py", family="script",
        should_detect_as="py",
        generation_method="text",
        realism_level="real",
    )
    add(
        "tool.rb",
        b"#!/usr/bin/env ruby\nputs 'strict generator'\n",
        true_type="rb", family="script",
        should_detect_as="rb",
        generation_method="text",
        realism_level="real",
    )
    add(
        "module.vb",
        b"' Visual Basic sample\r\nModule M\r\nSub Main()\r\n End Sub\r\nEnd Module\r\n",
        true_type="vb", family="script",
        should_detect_as="vb",
        generation_method="text",
        realism_level="real",
    )
    add(
        "page.php",
        b"<?php echo 'strict generator'; ?>\n",
        true_type="php", family="script",
        should_detect_as="php",
        generation_method="text",
        realism_level="real",
    )
    add(
        "page.html",
        b"<!doctype html><html><head><title>x</title></head><body>strict</body></html>\n",
        true_type="html", family="markup",
        should_detect_as="html",
        generation_method="text",
        realism_level="real",
    )
    add(
        "data.xml",
        b'<?xml version="1.0" encoding="UTF-8"?>\n<root><item>strict</item></root>\n',
        true_type="xml", family="markup",
        should_detect_as="xml",
        generation_method="text",
        realism_level="real",
    )
    add(
        "wscript_task.wsf",
        (
            b"<?xml version=\"1.0\"?>\n"
            b"<package><job id=\"main\"><script language=\"JScript\">\n"
            b"WScript.Echo('strict generator');\n"
            b"</script></job></package>\n"
        ),
        true_type="wsf", family="script",
        should_detect_as="wsf",
        generation_method="text",
        realism_level="real",
    )
    add(
        "settings.wsh",
        (
            b"[ScriptFile]\r\nPath=C:\\path\\to\\script.vbs\r\n"
            b"[Options]\r\nTimeout=0\r\n"
        ),
        true_type="wsh",
        family="script",
        should_detect_as="wsh",
        generation_method="text",
        realism_level="real",
        notes=".wsh is an INI-style Windows Script Host settings file.",
    )
    add(
        "scriptlet.sct",
        (
            b"<?xml version=\"1.0\"?>\n<scriptlet>\n"
            b"<registration progid=\"strict.Gen\" classid=\"{deadbeef}\"/>\n"
            b"<script language=\"JScript\"><![CDATA[\n"
            b"new ActiveXObject('WScript.Shell');\n"
            b"]]></script>\n</scriptlet>\n"
        ),
        true_type="sct", family="script",
        should_detect_as="sct",
        generation_method="text",
        realism_level="real",
    )
    add(
        "fragment.rtf",
        build_rtf(),
        true_type="rtf", family="document",
        should_detect_as="rtf",
        generation_method="hand-written RTF",
        realism_level="real",
    )
    add(
        "webpage.mhtml",
        build_mhtml("<html><body>strict mhtml</body></html>"),
        true_type="mhtml", family="markup",
        should_detect_as="mhtml",
        generation_method="hand-written MIME multipart/related",
        realism_level="real",
    )
    add(
        "message.eml",
        build_eml("<p>strict eml body</p>"),
        true_type="eml", family="markup",
        should_detect_as="eml",
        generation_method="hand-written RFC-822 message",
        realism_level="real",
    )

    # ---- PostScript family ----
    add(
        "drawing.eps",
        build_eps(),
        true_type="eps", family="document",
        should_detect_as="eps",
        generation_method="hand-written EPSF",
        realism_level="real",
    )
    add(
        "print.ps",
        build_ps(),
        true_type="ps", family="document",
        should_detect_as="ps",
        generation_method="hand-written PostScript",
        realism_level="real",
    )

    # ---- Archives (tar/gz/bz2) ----
    add(
        "logs.tar", build_tar(),
        true_type="tar", family="archive",
        should_detect_as="tar",
        generation_method="tarfile",
        realism_level="real",
    )
    add(
        "blob.gz", build_gz(),
        true_type="gz", family="archive",
        should_detect_as="gz",
        generation_method="gzip module",
        realism_level="real",
    )
    add(
        "blob.bz2", build_bz2(),
        true_type="bz2", family="archive",
        should_detect_as="bz2",
        generation_method="bz2 module",
        realism_level="real",
    )

    # ---- Misc ----
    add(
        "shortcut.lnk", build_lnk(),
        true_type="lnk", family="shell",
        should_detect_as="lnk",
        generation_method="hand-written ShellLink header",
        realism_level="partially_real",
        limitations=(
            "No LinkTargetIDList/LinkInfo; LinkFlags=0. Headers and CLSID are "
            "valid, which is what binary identifiers key on."
        ),
    )
    add(
        "help.chm", build_chm(),
        true_type="chm", family="binary",
        should_detect_as="chm",
        generation_method="hand-written ITSF header stub",
        realism_level="synthetic_fallback",
        limitations=(
            "CHM is a complex archive format; full container is out of scope. "
            "ITSF signature is correct so libmagic will identify the file."
        ),
    )
    add(
        "flash.swf", build_swf(),
        true_type="swf", family="binary",
        should_detect_as="swf",
        generation_method="hand-written FWS header",
        realism_level="synthetic_fallback",
        limitations="No SWF tag stream after the header.",
    )
    add(
        "disc.iso", build_iso(),
        true_type="iso", family="archive",
        should_detect_as="iso",
        generation_method="hand-written ISO9660 system area + PVD",
        realism_level="partially_real",
        limitations=(
            "No path table, no root directory record, no actual file content. "
            "The PVD with the CD001 identifier is what file(1) detects."
        ),
    )
    add(
        "data.db", build_db_sqlite(),
        true_type="db", family="binary",
        should_detect_as="db",
        generation_method="sqlite3",
        realism_level="real",
        notes=(
            "Real SQLite database. There are many .db formats; we use SQLite "
            "because it is the most common interpretation in malware analysis."
        ),
    )
    add(
        "schema.sql",
        b"-- strict generator SQL\nCREATE TABLE x (id INTEGER);\nINSERT INTO x VALUES (1);\n",
        true_type="sql", family="text",
        should_detect_as="sql",
        generation_method="text",
        realism_level="real",
    )
    add(
        "java_source.java",
        b"public class Hello { public static void main(String[] a){ System.out.println(\"hi\"); } }\n",
        true_type="java", family="text",
        should_detect_as="java",
        generation_method="text",
        realism_level="real",
    )
    # Standalone .class file
    klass_bytes = (
        b"\xCA\xFE\xBA\xBE"
        + struct.pack(">HH", 0, 52)
        + struct.pack(">H", 1)
        + b"\x00" * 14
    )
    add(
        "Hello.class", klass_bytes,
        true_type="class", family="binary",
        should_detect_as="class",
        generation_method="hand-written class file header",
        realism_level="partially_real",
        limitations="Constant pool empty; useful only for header detection.",
    )
    add(
        "library.jar", build_jar(),
        true_type="jar", family="zip",
        should_detect_as="jar",
        generation_method="ZIP + META-INF/MANIFEST.MF + .class",
        realism_level="real",
    )
    # APK: zipped Android container
    apk_manifest = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        b"<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"
        b"          package=\"com.example.strict\">\n"
        b"  <application android:label=\"Strict\"/>\n"
        b"</manifest>\n"
    )
    apk_dex = b"dex\n035\x00" + b"\x00" * 100
    apk_arsc = b"\x02\x00\x0c\x00" + b"\x00" * 64
    add(
        "app.apk", build_apk(apk_manifest, apk_dex, apk_arsc),
        true_type="apk", family="zip",
        should_detect_as="apk",
        generation_method="ZIP + AndroidManifest.xml + classes.dex + resources.arsc",
        realism_level="partially_real",
        limitations=(
            "AndroidManifest.xml is plain XML, not the compiled AXML binary "
            "format real APKs ship with. classes.dex carries the DEX magic "
            "but no methods. Header-based and structure-based detectors "
            "will identify it as APK."
        ),
    )

    # ---- macOS .app: zipped bundle ----
    app_buf = io.BytesIO()
    with zipfile.ZipFile(app_buf, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "Strict.app/Contents/Info.plist",
                   "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n"
                   "<dict><key>CFBundleExecutable</key><string>strict</string></dict>\n"
                   "</plist>\n")
        zip_writestr(z, "Strict.app/Contents/MacOS/strict", b"#!/bin/sh\necho strict\n")
    add(
        "Strict.app.zip", app_buf.getvalue(),
        true_type="app", family="zip",
        should_detect_as="app",
        generation_method="ZIP containing Strict.app/Contents/{Info.plist,MacOS/}",
        realism_level="partially_real",
        notes=(
            "macOS .app is normally a bundle DIRECTORY. We ship a zipped form "
            "for cross-platform transport. A second sample (the unzipped "
            "bundle) is produced under feature_checks/ to test directory-based "
            "detection."
        ),
        limitations=(
            "No code-signing, no Mach-O binaries inside. Real .app validation "
            "requires macOS-specific tooling."
        ),
    )

    # ---- tmp ----
    # Deliberate decision: we treat .tmp as "extension that carries no
    # ground-truth type by itself". The file we generate is plain bytes
    # of unknown family; a good analyzer should fall back to deep content
    # inspection. We document the strategy in the manifest.
    add(
        "scratch.tmp",
        b"strict generator tmp scratch bytes\n" + bytes(range(256)),
        true_type="tmp", family="opaque",
        should_detect_as="tmp",
        notes=(
            "The .tmp extension carries no inherent type. The file payload "
            "is non-textual binary that resembles nothing in particular, so "
            "a strict analyzer should report tmp/unknown rather than guessing. "
            "Separate disguise tests put real PE/PDF/ZIP content behind a "
            ".tmp extension to verify deep inspection."
        ),
        generation_method="random-looking byte payload",
        realism_level="real",
    )

    # ---- hkcu ----
    # ".hkcu" is unusual; it appears in the assignment list. It is not a
    # standardized file format. We emit a Windows .reg file targeting
    # HKEY_CURRENT_USER, because that is the closest meaningful artifact.
    add(
        "persistence.hkcu",
        (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
            "\"StrictGen\"=\"C:\\\\Users\\\\victim\\\\AppData\\\\Roaming\\\\strict.exe\"\r\n"
        ).encode("utf-16-le"),
        true_type="hkcu", family="registry",
        should_detect_as="hkcu",
        generation_method="UTF-16 .reg-style text",
        realism_level="partially_real",
        notes=(
            "There is no standardized .hkcu file format. The most plausible "
            "interpretation in a malware analysis context is a Windows "
            "registry export rooted at HKCU. The content is a UTF-16 .reg "
            "blob (which is what regedit produces)."
        ),
        limitations="Not a standardized format; content is heuristic.",
    )


def emit_disguised(manifest: Manifest, bucket: Path, root: Path) -> None:
    """
    Files whose extension lies about their true content. A good analyzer
    must classify these by content, not by extension.
    """

    def add(name: str, data: bytes, *, true_type: str, family: str,
            should_detect_as: str, notes: str = "", generation_method: str = "",
            realism_level: str = "real", limitations: str = "",
            **extra: Any) -> None:
        p = bucket / name
        write_bytes(p, data)
        manifest.add(
            SampleRecord(
                filename=name,
                path=rel(root, p),
                displayed_extension=name.rsplit(".", 1)[-1],
                true_type=true_type,
                family=family,
                should_detect_as=should_detect_as,
                should_be_disguised=True,
                notes=notes,
                generation_method=generation_method,
                realism_level=realism_level,
                limitations=limitations,
                **extra,
            )
        )

    # PE disguised as everything
    pe = build_pe()
    add("invoice.pdf.exe", pe, true_type="exe", family="pe",
        should_detect_as="exe",
        notes="Double-extension trick; true content is PE.",
        generation_method="hand-written PE32", realism_level="real")
    add("photo.jpg", pe, true_type="exe", family="pe",
        should_detect_as="exe",
        notes="PE bytes with .jpg extension.",
        generation_method="hand-written PE32", realism_level="real")
    add("logs.tmp", pe, true_type="exe", family="pe",
        should_detect_as="exe",
        notes="PE bytes hidden under .tmp.",
        generation_method="hand-written PE32", realism_level="real")
    add("driver.txt", build_pe(is_dll=True), true_type="dll", family="pe",
        should_detect_as="dll",
        notes="DLL bytes with .txt extension.",
        generation_method="hand-written PE32+DLL flag", realism_level="real")

    # PDF disguised
    pdf_bytes = build_pdf(["Disguised PDF body."])
    add("report.docx", pdf_bytes, true_type="pdf", family="pdf",
        should_detect_as="pdf",
        notes="PDF bytes with .docx extension. ZIP-vs-PDF discriminator test.",
        generation_method="hand-written PDF", realism_level="real")
    add("photo.jpg.php", pdf_bytes, true_type="pdf", family="pdf",
        should_detect_as="pdf",
        notes="PDF bytes with .jpg.php double extension.",
        generation_method="hand-written PDF", realism_level="real")

    # ZIP disguised
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "inside.txt", "I am inside a zip with a docx extension.\n")
    add("report.docx.zip", zip_buf.getvalue(),
        true_type="zip", family="zip",
        should_detect_as="zip",
        notes=(
            "Plain ZIP (not OOXML) bearing a .docx.zip name. Tests that the "
            "analyzer does not classify any ZIP as OOXML."
        ),
        generation_method="zipfile", realism_level="real")

    # OOXML disguised as plain zip. We build the docx directly at the target
    # path; the add() helper then records ground truth without re-writing the
    # bytes (we deliberately pass the existing payload).
    ooxml_path = bucket / "evidence.zip"
    build_ooxml(
        ooxml_path, family="word", lang="en-US", pages=2, macros=False,
        paragraphs=["I am really a docx, not a zip."],
    )
    manifest.add(SampleRecord(
        filename="evidence.zip",
        path=rel(root, ooxml_path),
        displayed_extension="zip",
        true_type="docx", family="ooxml",
        should_detect_as="docx",
        should_be_disguised=True,
        page_count_expected=2,
        language_code_expected="en-US",
        notes="True OOXML docx wearing a .zip extension.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    ))

    # JAR disguised as ZIP
    add("library.zip", build_jar(),
        true_type="jar", family="zip", should_detect_as="jar",
        notes="JAR bytes wearing .zip. Tests META-INF/MANIFEST.MF discrimination.",
        generation_method="JAR build", realism_level="real")

    # APK disguised as ZIP
    apk_manifest = b"<?xml version=\"1.0\"?><manifest package=\"com.x\"/>"
    apk_dex = b"dex\n035\x00" + b"\x00" * 100
    apk_arsc = b"\x02\x00\x0c\x00" + b"\x00" * 64
    add("game.zip", build_apk(apk_manifest, apk_dex, apk_arsc),
        true_type="apk", family="zip", should_detect_as="apk",
        notes="APK wearing .zip. Tests AndroidManifest+classes.dex discrimination.",
        generation_method="APK build", realism_level="partially_real",
        limitations="AndroidManifest.xml is text, not compiled AXML.")

    # PPSX disguised as PPTX (and vice versa)
    ppsx_path = bucket / "loop.pptx"
    build_ooxml(ppsx_path, family="powerpoint", lang=None, pages=None,
                macros=False, slideshow=True)
    add("loop.pptx", ppsx_path.read_bytes(),
        true_type="ppsx", family="ooxml", should_detect_as="ppsx",
        notes="Slideshow content type wearing .pptx extension.",
        generation_method="hand-rolled OOXML with ppsx content type",
        realism_level="real")

    pptx_path = bucket / "deck.ppsx"
    build_ooxml(pptx_path, family="powerpoint", lang=None, pages=None,
                macros=False, slideshow=False)
    add("deck.ppsx", pptx_path.read_bytes(),
        true_type="pptx", family="ooxml", should_detect_as="pptx",
        notes="Presentation content type wearing .ppsx extension.",
        generation_method="hand-rolled OOXML with pptx content type",
        realism_level="real")

    # DOCM disguised as DOCX
    docx_path = bucket / "doc_with_macros.docx"
    build_ooxml(docx_path, family="word", lang="en-US", pages=1, macros=True,
                paragraphs=["I look like docx but have a vbaProject.bin."])
    add("doc_with_macros.docx", docx_path.read_bytes(),
        true_type="docm", family="ooxml", should_detect_as="docm",
        has_macros_expected=True,
        language_code_expected="en-US",
        page_count_expected=1,
        notes=(
            "Macro-enabled Word OOXML using the .docx extension. The "
            "[Content_Types].xml override and the vbaProject.bin part both "
            "identify it as docm."
        ),
        generation_method="hand-rolled OOXML", realism_level="partially_real",
        limitations="vbaProject.bin is a CFBF stub.")

    # Script as image
    add("logo.png", b"<?php system($_GET['c']); ?>\n",
        true_type="php", family="script", should_detect_as="php",
        notes="PHP webshell wearing .png. Tests text-vs-binary heuristics.",
        generation_method="text", realism_level="real")

    # Image as script
    add("payload.js", build_jpeg(),
        true_type="jpg", family="image", should_detect_as="jpg",
        notes="JPEG bytes hidden under .js. Tests binary header inspection.",
        generation_method="canonical JPEG bytes", realism_level="real")

    # LNK disguised
    add("readme.txt", build_lnk(),
        true_type="lnk", family="shell", should_detect_as="lnk",
        notes="LNK shell-link wearing .txt.",
        generation_method="hand-written LNK header",
        realism_level="partially_real",
        limitations="LinkFlags=0, no IDList/LinkInfo.")


def emit_edge_cases(manifest: Manifest, bucket: Path, root: Path) -> None:
    """
    Inputs designed to confuse a sloppy analyzer:
      * containers with a valid header and a broken body
      * extension ambiguities (jpg/jpeg)
      * format pairs that share a header (exe/dll/scr, docx/zip/jar/apk)
      * scripts in script-script confusion (vbs vs js inside .wsf)
    """

    def add(name: str, data: bytes, **kw: Any) -> None:
        p = bucket / name
        write_bytes(p, data)
        manifest.add(
            SampleRecord(
                filename=name,
                path=rel(root, p),
                displayed_extension=name.rsplit(".", 1)[-1],
                **kw,
            )
        )

    # ZIP header but no central directory: should NOT be classified as zip
    truncated_zip = b"PK\x03\x04" + b"\x00" * 26 + b"some random data"
    add("broken_no_cd.zip", truncated_zip,
        true_type="corrupt_zip", family="zip",
        should_detect_as="corrupt_zip",
        notes=(
            "Starts with the local-file-header signature but has no central "
            "directory or end-of-central-directory record. A strict ZIP "
            "validator must reject; a magic-byte sniffer will falsely accept."
        ),
        generation_method="hand-truncated",
        realism_level="real")

    # OLE header but no meaningful streams
    ole_stub = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 1016
    add("header_only.doc", ole_stub,
        true_type="corrupt_ole", family="ole",
        should_detect_as="corrupt_ole",
        notes=(
            "OLE signature only; no FAT, no directory, no Root Entry CLSID. "
            "A strict OLE parser must reject. Tests over-eager 'is OLE' rules."
        ),
        generation_method="hand-truncated",
        realism_level="real")

    # MZ header but no PE
    add("mz_only.exe", b"MZ" + b"\x00" * 62 + b"NotAPEHeader",
        true_type="corrupt_pe", family="pe",
        should_detect_as="corrupt_pe",
        notes="MZ but no e_lfanew pointing to a valid PE signature.",
        generation_method="hand-written",
        realism_level="real")

    # Script-script confusion: WSF carrying VBScript code
    add("mixed.wsf",
        (b"<?xml version=\"1.0\"?>\n"
         b"<package><job id=\"j\"><script language=\"VBScript\">\n"
         b"WScript.Echo \"vbs inside wsf\"\n</script></job></package>\n"),
        true_type="wsf", family="script",
        should_detect_as="wsf",
        notes="WSF whose payload is VBScript. Tests that wsf wins over vbs.",
        generation_method="text",
        realism_level="real")

    # MZ stub with .scr extension that is genuinely a DLL
    add("strange.scr", build_pe(is_dll=True),
        true_type="dll", family="pe",
        should_detect_as="dll",
        should_be_disguised=True,
        notes="DLL bytes wearing .scr. Tests subsystem/characteristics flags.",
        generation_method="hand-written PE32+DLL",
        realism_level="real")

    # Office without any docProps -> no language, no page count
    minimal_docx = bucket / "no_metadata.docx"
    with zipfile.ZipFile(minimal_docx, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "[Content_Types].xml", _CT_DOCX)
        zip_writestr(z, "_rels/.rels", _RELS_ROOT.format(target="word/document.xml"))
        zip_writestr(z, "word/document.xml",
                   _document_xml(["No docProps at all in this archive."]))
        # Deliberately omit docProps/core.xml and docProps/app.xml
    manifest.add(SampleRecord(
        filename="no_metadata.docx",
        path=rel(root, minimal_docx),
        displayed_extension="docx",
        true_type="docx",
        family="ooxml",
        should_detect_as="docx",
        language_code_expected=None,
        page_count_expected=None,
        notes=(
            "OOXML docx with no docProps. Tests that language/page-count "
            "extractors degrade gracefully and do not invent values."
        ),
        generation_method="hand-rolled OOXML missing docProps",
        realism_level="real",
    ))

    # OOXML pieces in a ZIP that lacks [Content_Types].xml -> NOT a docx
    almost_docx = bucket / "almost.docx"
    with zipfile.ZipFile(almost_docx, "w", zipfile.ZIP_DEFLATED) as z:
        zip_writestr(z, "word/document.xml", _document_xml(["No content types!"]))
    manifest.add(SampleRecord(
        filename="almost.docx",
        path=rel(root, almost_docx),
        displayed_extension="docx",
        true_type="zip",
        family="zip",
        should_detect_as="zip",
        should_be_disguised=True,
        notes=(
            "ZIP that contains a word/document.xml but lacks "
            "[Content_Types].xml. A strict OOXML detector must reject and "
            "fall back to plain ZIP."
        ),
        generation_method="zipfile",
        realism_level="real",
    ))

    # Tiny RTF lookalike: starts with {\rt but not {\rtf
    add("not_quite.rtf",
        b"{\\rt1 this is not a real rtf header}",
        true_type="text", family="text",
        should_detect_as="text",
        notes="Almost-RTF; missing the 'f' in \\rtf. Must NOT be classified as rtf.",
        generation_method="text", realism_level="real")

    # JPEG/JPG alias test: same bytes, different extension, both honest.
    # Already covered in honest/. Here we add a JPEG with .jpeg extension
    # that pretends to be a .jpg in a downloads folder.
    add("dual.JPEG", build_jpeg(),
        true_type="jpeg", family="image",
        should_detect_as="jpeg",
        notes="Tests case-insensitive .JPEG handling.",
        generation_method="canonical JPEG bytes",
        realism_level="real")


def emit_feature_checks(manifest: Manifest, bucket: Path, root: Path) -> None:
    """
    Samples that target the extra-check features in the assignment:
    URL/IP/domain extraction, password protection, encryption flag,
    macro presence, language tag, page count, multi-page PDFs.
    """

    def add(name: str, data: bytes, **kw: Any) -> None:
        p = bucket / name
        write_bytes(p, data)
        manifest.add(
            SampleRecord(
                filename=name,
                path=rel(root, p),
                displayed_extension=name.rsplit(".", 1)[-1],
                **kw,
            )
        )

    # --- PDFs ---

    # PDF with URLs/IPs/domains in body text
    add(
        "iocs.pdf",
        build_pdf([_FEATURE_TEXT_BLOB]),
        true_type="pdf", family="pdf",
        should_detect_as="pdf",
        page_count_expected=1,
        urls_expected=list(_FEATURE_URLS),
        ip_addresses_expected=list(_FEATURE_IPS),
        domains_expected=list(_FEATURE_DOMAINS),
        notes="Single-page PDF whose body contains URLs, IPs, and domains.",
        generation_method="hand-written PDF objects+xref",
        realism_level="real",
    )

    # Multi-page PDF
    add(
        "multi_page.pdf",
        build_pdf([f"Page number {i + 1}." for i in range(5)]),
        true_type="pdf", family="pdf",
        should_detect_as="pdf",
        page_count_expected=5,
        notes="Five separate page objects under a single Pages tree.",
        generation_method="hand-written PDF",
        realism_level="real",
    )

    # PDF marked as encrypted (synthetic_fallback for real cipher)
    add(
        "locked.pdf",
        build_pdf(["You should not be able to read this without a password."],
                  fake_encrypt=True),
        true_type="pdf", family="pdf",
        should_detect_as="pdf",
        password_protected_expected=True,
        encrypted_expected=True,
        notes=(
            "Trailer contains /Encrypt referencing a Standard security "
            "handler dictionary. Detectors that key on /Encrypt will flag it. "
            "The body is NOT actually encrypted."
        ),
        generation_method="hand-written PDF with /Encrypt trailer entry",
        realism_level="synthetic_fallback",
        limitations=(
            "No real RC4/AES encryption applied to object streams. Tools that "
            "try to decrypt will fail. Implementing real PDF encryption is "
            "out of scope and requires either pikepdf (libqpdf, C++) or a "
            "from-scratch implementation."
        ),
    )

    # PDF with no IOCs: negative control for URL/IP/domain extractor
    add(
        "clean.pdf",
        build_pdf(["Plain content with no URLs, no IP addresses, no domains."]),
        true_type="pdf", family="pdf",
        should_detect_as="pdf",
        page_count_expected=1,
        urls_expected=[],
        ip_addresses_expected=[],
        domains_expected=[],
        notes="Negative control: extractor should return empty lists.",
        generation_method="hand-written PDF",
        realism_level="real",
    )

    # --- OOXML language / page-count ---

    docx_de = bucket / "metadaten_de.docx"
    build_ooxml(docx_de, family="word", lang="de-DE", pages=12,
                macros=False,
                paragraphs=["Deutsche Sprachprüfung. Seitenzahl im Property-Block."])
    manifest.add(SampleRecord(
        filename="metadaten_de.docx",
        path=rel(root, docx_de),
        displayed_extension="docx",
        true_type="docx",
        family="ooxml",
        should_detect_as="docx",
        language_code_expected="de-DE",
        page_count_expected=12,
        notes="German-language docx with Pages=12 in app.xml.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    ))

    # --- Macros ---
    macro_doc = bucket / "macros_present.docm"
    build_ooxml(macro_doc, family="word", lang="en-US", pages=2, macros=True)
    manifest.add(SampleRecord(
        filename="macros_present.docm",
        path=rel(root, macro_doc),
        displayed_extension="docm",
        true_type="docm",
        family="ooxml",
        should_detect_as="docm",
        has_macros_expected=True,
        language_code_expected="en-US",
        page_count_expected=2,
        notes="Macro presence test: positive case.",
        generation_method="hand-rolled OOXML + vbaProject.bin",
        realism_level="partially_real",
        limitations="vbaProject.bin is a CFBF stub.",
    ))

    macro_neg = bucket / "macros_absent.docx"
    build_ooxml(macro_neg, family="word", lang="en-US", pages=1, macros=False)
    manifest.add(SampleRecord(
        filename="macros_absent.docx",
        path=rel(root, macro_neg),
        displayed_extension="docx",
        true_type="docx",
        family="ooxml",
        should_detect_as="docx",
        has_macros_expected=False,
        language_code_expected="en-US",
        page_count_expected=1,
        notes="Macro presence test: negative control.",
        generation_method="hand-rolled OOXML",
        realism_level="real",
    ))

    # --- Password-protected ZIP (encryption flag) ---
    add(
        "locked_archive.zip",
        build_zip_password_protected("infected"),
        true_type="zip", family="zip",
        should_detect_as="zip",
        password_protected_expected=True,
        encrypted_expected=True,
        notes=(
            "ZIP whose local file header has general-purpose bit 0 set. The "
            "central directory matches. Password is 'infected' on paper, but "
            "the 12-byte encryption header is placeholder bytes."
        ),
        generation_method="hand-written ZIP with encryption bit",
        realism_level="partially_real",
        limitations=(
            "PKZIP traditional stream cipher is NOT applied. Real "
            "decompression will fail. Detectors that key on the encryption "
            "bit will correctly report password_protected=True; tools that "
            "attempt decryption will fail. For end-to-end testing with real "
            "PKZIP encryption, regenerate with a real tool (e.g. `zip -e`)."
        ),
    )

    # --- Text-based artifacts containing IOCs ---
    iocs_text = _FEATURE_TEXT_BLOB.encode()

    add(
        "iocs.html",
        b"<!doctype html><html><body><p>" + iocs_text + b"</p></body></html>\n",
        true_type="html", family="markup",
        should_detect_as="html",
        urls_expected=list(_FEATURE_URLS),
        ip_addresses_expected=list(_FEATURE_IPS),
        domains_expected=list(_FEATURE_DOMAINS),
        notes="HTML with IOCs in body text.",
        generation_method="text", realism_level="real",
    )
    add(
        "iocs.eml",
        build_eml(
            "<p>" + _FEATURE_TEXT_BLOB + "</p>",
            subject="phishing test",
        ),
        true_type="eml", family="markup",
        should_detect_as="eml",
        urls_expected=list(_FEATURE_URLS),
        ip_addresses_expected=list(_FEATURE_IPS),
        domains_expected=list(_FEATURE_DOMAINS),
        notes="Phishing-style email containing IOCs.",
        generation_method="text", realism_level="real",
    )
    add(
        "iocs.js",
        b"// strict\nvar urls = [\n  'https://malware-test.example.com/payload',\n"
        b"  'http://evil.example.org/login.php?id=42'\n];\n"
        b"var ips = ['10.20.30.40', '192.0.2.123'];\n",
        true_type="js", family="script",
        should_detect_as="js",
        urls_expected=list(_FEATURE_URLS),
        ip_addresses_expected=list(_FEATURE_IPS),
        domains_expected=list(_FEATURE_DOMAINS),
        notes="JavaScript containing URL and IP literals.",
        generation_method="text", realism_level="real",
    )

    # ---- macOS .app as a real directory bundle ----
    bundle_root = bucket / "Strict.app"
    contents = bundle_root / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True, exist_ok=True)
    info_plist = contents / "Info.plist"
    info_plist.write_text(
        '<?xml version="1.0"?>\n<plist version="1.0">\n'
        '<dict><key>CFBundleExecutable</key><string>strict</string>\n'
        '<key>CFBundleIdentifier</key><string>com.example.strict</string></dict>\n'
        '</plist>\n'
    )
    (macos / "strict").write_bytes(b"#!/bin/sh\necho strict\n")
    manifest.add(SampleRecord(
        filename="Strict.app",
        path=rel(root, bundle_root),
        displayed_extension="app",
        true_type="app",
        family="bundle",
        should_detect_as="app",
        notes=(
            "Real macOS-style .app bundle: a directory named X.app containing "
            "Contents/Info.plist and Contents/MacOS/<executable>. The "
            "analyzer should recognize this directory shape on disk as an "
            "app bundle, separately from the zipped form in honest/."
        ),
        generation_method="directory layout",
        realism_level="partially_real",
        limitations=(
            "The inner executable is a shell script, not a Mach-O binary. "
            "Code-signing and entitlements are absent."
        ),
    ))


# ---------------------------------------------------------------------------
# Format-realism summary
# ---------------------------------------------------------------------------


_REALISM_NOTES: dict[str, tuple[str, str]] = {
    # type_code -> (realism_level, summary)
    "exe":  ("real", "hand-written PE32 image with .text section"),
    "dll":  ("real", "PE32 with IMAGE_FILE_DLL"),
    "scr":  ("real", "PE32 (same binary shape as exe; extension is the test)"),
    "docx": ("real", "OOXML built by hand"),
    "docm": ("partially_real", "OOXML + CFBF stub for vbaProject.bin"),
    "xlsx": ("real", "OOXML workbook"),
    "xlsm": ("partially_real", "OOXML + CFBF stub for vbaProject.bin"),
    "pptx": ("real", "OOXML presentation"),
    "ppsx": ("real", "OOXML presentation with slideshow content type"),
    "doc":  ("partially_real", "CFBF with Word CLSID; no WordDocument stream"),
    "xls":  ("partially_real", "CFBF with Excel CLSID; no Workbook stream"),
    "ppt":  ("partially_real", "CFBF with PowerPoint CLSID; no document stream"),
    "msi":  ("partially_real", "CFBF with MSI CLSID; no Installer database"),
    "msp":  ("partially_real", "CFBF with MSP CLSID; no patch streams"),
    "pub":  ("partially_real", "CFBF with Publisher CLSID"),
    "pdf":  ("real", "objects + xref + trailer hand-written"),
    "zip":  ("real", "stdlib zipfile"),
    "tar":  ("real", "stdlib tarfile"),
    "gz":   ("real", "stdlib gzip"),
    "bz2":  ("real", "stdlib bz2"),
    "rar":  ("synthetic_fallback", "NO sample generated; see notes"),
    "7z":   ("synthetic_fallback", "NO sample generated; see notes"),
    "png":  ("real", "hand-written PNG"),
    "jpg":  ("real", "canonical JPEG bytes"),
    "jpeg": ("real", "canonical JPEG bytes"),
    "gif":  ("real", "hand-written GIF87a"),
    "bmp":  ("real", "hand-written 24-bit BMP"),
    "svg":  ("real", "text"),
    "wav":  ("real", "hand-written PCM RIFF/WAVE"),
    "mp3":  ("partially_real", "ID3v2 + Layer III frame header"),
    "mp4":  ("partially_real", "ftyp box only"),
    "mov":  ("partially_real", "QuickTime ftyp"),
    "avi":  ("partially_real", "RIFF/AVI skeleton"),
    "js":   ("real", "text"),
    "vbs":  ("real", "text"),
    "ps1":  ("real", "text"),
    "bat":  ("real", "text"),
    "sh":   ("real", "text"),
    "py":   ("real", "text"),
    "rb":   ("real", "text"),
    "vb":   ("real", "text"),
    "php":  ("real", "text"),
    "html": ("real", "text"),
    "xml":  ("real", "text"),
    "wsf":  ("real", "text/XML"),
    "wsh":  ("real", "INI-style text"),
    "sct":  ("real", "XML scriptlet"),
    "rtf":  ("real", "hand-written RTF"),
    "mhtml":("real", "MIME multipart/related"),
    "eml":  ("real", "RFC-822 message"),
    "eps":  ("real", "hand-written EPSF"),
    "ps":   ("real", "hand-written PostScript"),
    "lnk":  ("partially_real", "ShellLink header only"),
    "chm":  ("synthetic_fallback", "ITSF header stub"),
    "swf":  ("synthetic_fallback", "FWS header only"),
    "iso":  ("partially_real", "system area + PVD only"),
    "db":   ("real", "SQLite database"),
    "sql":  ("real", "text"),
    "java": ("real", "text"),
    "class":("partially_real", "valid header, empty constant pool"),
    "jar":  ("real", "ZIP + MANIFEST.MF + .class"),
    "apk":  ("partially_real", "ZIP + plain AndroidManifest.xml + dex stub"),
    "app":  ("partially_real", "bundle directory + zipped form"),
    "hkcu": ("partially_real", "UTF-16 .reg blob; not a standardized format"),
    "tmp":  ("real", "treated as opaque; disguise variants test deep inspection"),
}


def print_realism_summary() -> None:
    print("\n=== Format realism summary ===")
    by_level: dict[str, list[str]] = {}
    for typ, (level, _) in _REALISM_NOTES.items():
        by_level.setdefault(level, []).append(typ)
    order = ["real", "partially_real", "synthetic_fallback"]
    for lvl in order:
        types = sorted(by_level.get(lvl, []))
        if not types:
            continue
        print(f"\n[{lvl}]  ({len(types)} types)")
        for t in types:
            print(f"  - {t:6s}  {_REALISM_NOTES[t][1]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


_REQUIRED_TYPES = [
    "exe", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar",
    "7z", "js", "vbs", "scr", "lnk", "bat", "html", "php", "swf", "gif",
    "png", "jpg", "jpeg", "bmp", "svg", "ps1", "chm", "xml", "rtf", "mhtml",
    "iso", "tar", "gz", "bz2", "dll", "tmp", "msp", "msi", "hkcu", "eml",
    "db", "sql", "apk", "app", "vb", "jar", "java", "class", "sh", "py",
    "rb", "ps", "eps", "mp3", "wav", "mp4", "avi", "mov", "xlsm", "pub",
    "sct", "wsf", "wsh", "ppsx", "docm",
]


def _emit_rar_and_7z_placeholders(manifest: Manifest, bucket: Path,
                                  root: Path) -> None:
    """
    RAR and 7z formats are proprietary and cannot be honestly produced in
    pure Python. We emit ONLY the file signatures, clearly tagged as
    synthetic_fallback. This way the analyzer's magic-byte sniffer can be
    smoke-tested while the manifest tells the truth about the limitation.
    """
    # RAR5 signature
    rar_bytes = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32
    p = bucket / "container.rar"
    write_bytes(p, rar_bytes)
    manifest.add(SampleRecord(
        filename="container.rar",
        path=rel(root, p),
        displayed_extension="rar",
        true_type="rar",
        family="archive",
        should_detect_as="rar",
        notes=(
            "RAR5 signature followed by zeroes. RAR is a proprietary format; "
            "writing one in pure Python is not feasible. For true end-to-end "
            "tests, replace this file with one produced by the official "
            "WinRAR/rar CLI."
        ),
        generation_method="signature only",
        realism_level="synthetic_fallback",
        limitations=(
            "No real archive structure. Detectors that only check the "
            "signature will accept it. Real RAR parsers will fail."
        ),
    ))

    # 7z signature
    sevenz_bytes = b"\x37\x7A\xBC\xAF\x27\x1C\x00\x04" + b"\x00" * 32
    p = bucket / "container.7z"
    write_bytes(p, sevenz_bytes)
    manifest.add(SampleRecord(
        filename="container.7z",
        path=rel(root, p),
        displayed_extension="7z",
        true_type="7z",
        family="archive",
        should_detect_as="7z",
        notes=(
            "7-Zip signature followed by zeroes. The 7z format requires LZMA "
            "and a complex end-of-archive header that cannot be reproduced "
            "in pure Python without third-party libraries (py7zr depends on "
            "the C LZMA SDK). Use 7-Zip CLI for end-to-end tests."
        ),
        generation_method="signature only",
        realism_level="synthetic_fallback",
        limitations="No real archive structure.",
    ))


def generate(out_dir: Path, seed: int) -> Manifest:
    random.seed(seed)
    buckets = ensure_dirs(out_dir)

    manifest = Manifest(out_dir)
    manifest.expect(*_REQUIRED_TYPES)

    emit_honest(manifest, buckets["honest"], out_dir)
    emit_disguised(manifest, buckets["disguised"], out_dir)
    emit_edge_cases(manifest, buckets["edge_cases"], out_dir)
    emit_feature_checks(manifest, buckets["feature_checks"], out_dir)
    _emit_rar_and_7z_placeholders(manifest, buckets["honest"], out_dir)

    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--out", default="strict_samples",
        help="Output directory (default: strict_samples)",
    )
    parser.add_argument(
        "--seed", type=int, default=1337,
        help="Random seed (default: 1337). Output is deterministic.",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating strict samples into: {out_dir}")
    manifest = generate(out_dir, args.seed)

    try:
        manifest.assert_coverage()
    except RuntimeError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    path = manifest.write()
    print(f"Wrote manifest: {path}")
    print(f"Generated {len(manifest.records)} samples across "
          f"{len({r.family for r in manifest.records})} families.")

    # Bucket breakdown
    by_bucket: dict[str, int] = {}
    for r in manifest.records:
        bucket = r.path.split("/", 1)[0]
        by_bucket[bucket] = by_bucket.get(bucket, 0) + 1
    print("\nPer-bucket totals:")
    for b in sorted(by_bucket):
        print(f"  {b:<16s} {by_bucket[b]}")

    print_realism_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
