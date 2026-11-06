"""File-level structural anomalies: header placement, trailing data, polyglots, entropy."""

from __future__ import annotations

import re

from pdfm.context import AnalysisContext
from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument
from pdfm.parser.filters import IMAGE_FILTERS

# (magic, description). Checked at the start of the file and of data after %%EOF.
MAGICS = [
    (b"MZ", "Windows executable (MZ)"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive (also JAR/DOCX/XLSX/APK)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 document (legacy Office)"),
    (b"{\\rtf", "RTF document"),
    (b"GIF8", "GIF image"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
]
# Signatures that should never appear in a PDF's structure (outside stream data).
EMBEDDED_SIGNATURES = [
    (re.compile(rb"PK\x05\x06"), "ZIP end-of-central-directory record", Severity.HIGH),
    (re.compile(rb"This program cannot be run in DOS mode"), "Windows executable stub", Severity.HIGH),
    (re.compile(rb"<\s*(html|script|body)\b", re.I), "HTML markup", Severity.MEDIUM),
]
HIGH_ENTROPY = 7.9  # bits/byte; text is ~4.5, compressed or encrypted data approaches 8.0
HIGH_ENTROPY_MIN_SIZE = 4096


def sniff(data: bytes) -> str | None:
    for magic, description in MAGICS:
        if data.startswith(magic):
            return description
    return None


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    findings = []
    data = doc.data

    if doc.header_offset is None:
        findings.append(Finding(
            "NO_PDF_HEADER", Severity.MEDIUM, "No %PDF- header in the first 1024 bytes",
            evidence=sniff(data),
        ))
    elif doc.header_offset > 0:
        prefix = sniff(data)
        findings.append(Finding(
            "POLYGLOT" if prefix else "HEADER_NOT_AT_START",
            Severity.HIGH if prefix else Severity.MEDIUM,
            f"%PDF- header found at offset {doc.header_offset}, not 0"
            + (f"; file starts as a {prefix}" if prefix else ""),
        ))

    if doc.eof_offsets:
        trailing = data[doc.eof_offsets[-1]:]
        content = trailing.strip(b"\r\n\t \x00")
        if content:
            kind = sniff(content)
            findings.append(Finding(
                "DATA_AFTER_EOF",
                Severity.HIGH if kind else (Severity.MEDIUM if len(content) > 64 else Severity.LOW),
                f"{len(content):,} bytes after the last %%EOF" + (f" ({kind})" if kind else ""),
                evidence=repr(content[:40]),
            ))
    else:
        findings.append(Finding("MISSING_EOF", Severity.LOW, "File has no %%EOF marker"))

    skeleton = _outside_streams(doc)
    for pattern, description, severity in EMBEDDED_SIGNATURES:
        m = pattern.search(skeleton)
        if m:
            findings.append(Finding(
                "EMBEDDED_SIGNATURE", severity,
                f"{description} found in the PDF structure outside any stream (polyglot)",
                evidence=repr(m[0]),
            ))

    noisy = []
    for s in doc.streams:
        info = s.info
        if (info.entropy >= HIGH_ENTROPY and info.decoded_size >= HIGH_ENTROPY_MIN_SIZE
                and info.subtype != "Image" and info.stopped_at not in IMAGE_FILTERS
                and not info.font_program and info.dict_type not in ("EmbeddedFile", "XRef")):
            noisy.append(f"{info.ref} ({info.entropy:.2f})")
    if noisy:
        findings.append(Finding(
            "HIGH_ENTROPY_STREAM", Severity.LOW,
            f"{len(noisy)} non-image stream(s) decode to near-random data (packed or encrypted payload?)",
            evidence=", ".join(noisy[:10]),
        ))
    return findings


def _outside_streams(doc: PdfDocument) -> bytes:
    """The file with all raw stream data cut out."""
    parts, pos = [], 0
    for start, end in sorted(o.stream_span for o in doc.raw_objects if o.stream_span):
        if start >= pos:
            parts.append(doc.data[pos:start])
            pos = end
    parts.append(doc.data[pos:])
    return b"".join(parts)
