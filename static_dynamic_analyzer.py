#!/usr/bin/env python3
"""Import-friendly wrapper for the assignment analyzer script."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_SCRIPT = Path(__file__).with_name("analyzer.py")
_SPEC = importlib.util.spec_from_file_location("_assignment_analyzer_impl", _SCRIPT)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Could not load analyzer implementation from {_SCRIPT}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


for _name in dir(_MODULE):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_MODULE, _name)


if __name__ == "__main__":
    raise SystemExit(_MODULE.main())
