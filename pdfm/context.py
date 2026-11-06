"""Options and shared state for one scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pdfm.models import EmbeddedFileInfo, IOC, ScriptInfo


@dataclass
class ScanOptions:
    sandbox: bool = True  # emulate JavaScript in an isolated V8 (needs the "sandbox" extra)
    extract_dir: Path | None = None  # write embedded files here (named by SHA-256, never executed)
    rules_dir: Path | None = None  # extra YARA rules
    max_depth: int = 3  # recursion limit for PDFs embedded in PDFs


@dataclass
class AnalysisContext:
    """Passed to every analyzer: options in, artifacts (beyond findings) out.

    Analyzers run in order, so later ones can use earlier artifacts; the IOC
    analyzer, for example, reads URLs from the JavaScript the sandbox observed.
    """

    options: ScanOptions = field(default_factory=ScanOptions)
    depth: int = 0
    scripts: list[ScriptInfo] = field(default_factory=list)
    script_texts: list[str] = field(default_factory=list)  # every code variant seen, for IOC/YARA scans
    embedded: list[EmbeddedFileInfo] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
