"""Run the full analysis pipeline on one file."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pdfm import scoring
from pdfm.analyzers import actions as action_analyzer
from pdfm.analyzers import embedded, iocs, javascript, keywords, structure
from pdfm.analyzers import streams as stream_analyzer
from pdfm.context import AnalysisContext, ScanOptions
from pdfm.models import ActionInfo, ScanResult
from pdfm.parser.document import PdfDocument, load, load_bytes

# Order matters: later analyzers read artifacts (scripts, embedded files) from earlier ones.
ANALYZERS = [
    stream_analyzer.analyze,
    keywords.analyze,
    structure.analyze,
    action_analyzer.analyze,
    javascript.analyze,
    embedded.analyze,
    iocs.analyze,  # last: reads script texts and nested-file results
]


def scan(path: str | Path, options: ScanOptions | None = None) -> ScanResult:
    return _run(load(path), AnalysisContext(options or ScanOptions()))


def scan_bytes(data: bytes, name: str = "<memory>", options: ScanOptions | None = None,
               depth: int = 0) -> ScanResult:
    return _run(load_bytes(data, name), AnalysisContext(options or ScanOptions(), depth=depth))


def _run(doc: PdfDocument, ctx: AnalysisContext) -> ScanResult:
    try:
        findings = list(doc.findings)
        for analyze in ANALYZERS:
            findings += analyze(doc, ctx)
        points = scoring.score(findings)
        counts, _, _ = keywords.count_keywords(doc)
        return ScanResult(
            path=doc.name,
            size=len(doc.data),
            md5=hashlib.md5(doc.data).hexdigest(),
            sha256=hashlib.sha256(doc.data).hexdigest(),
            pdf_version=doc.version,
            parse_mode=doc.mode,
            revisions=doc.revisions,
            verdict=scoring.verdict(points, findings),
            score=points,
            keywords=dict(sorted(counts.items())),
            actions=[ActionInfo(a.trigger, a.type, a.ref, a.on_open) for a in doc.actions],
            scripts=ctx.scripts,
            embedded=ctx.embedded,
            iocs=ctx.iocs,
            objects=doc.objects,
            streams=[s.info for s in doc.streams],
            findings=findings,
        )
    finally:
        doc.close()
