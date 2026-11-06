"""Run the full analysis pipeline on one file."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pdfm.analyzers import streams as stream_analyzer
from pdfm.models import ScanResult
from pdfm.parser.document import PdfDocument, load, load_bytes

ANALYZERS = [stream_analyzer.analyze]


def scan(path: str | Path) -> ScanResult:
    return _run(load(path))


def scan_bytes(data: bytes, name: str = "<memory>") -> ScanResult:
    return _run(load_bytes(data, name))


def _run(doc: PdfDocument) -> ScanResult:
    try:
        findings = list(doc.findings)
        for analyze in ANALYZERS:
            findings += analyze(doc)
        return ScanResult(
            path=doc.name,
            size=len(doc.data),
            md5=hashlib.md5(doc.data).hexdigest(),
            sha256=hashlib.sha256(doc.data).hexdigest(),
            pdf_version=doc.version,
            parse_mode=doc.mode,
            revisions=doc.revisions,
            objects=doc.objects,
            streams=[s.info for s in doc.streams],
            findings=findings,
        )
    finally:
        doc.close()
