"""Run the full analysis pipeline on one file."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pdfm.models import ScanResult
from pdfm.parser import load


def scan(path: str | Path) -> ScanResult:
    doc = load(path)
    try:
        findings = list(doc.findings)
        # Analyzers (keywords, structure, javascript, ...) plug in here in later milestones.
        return ScanResult(
            path=str(doc.path),
            size=len(doc.data),
            md5=hashlib.md5(doc.data).hexdigest(),
            sha256=hashlib.sha256(doc.data).hexdigest(),
            pdf_version=doc.version,
            parse_mode=doc.mode,
            revisions=doc.revisions,
            objects=doc.objects,
            findings=findings,
        )
    finally:
        doc.close()
