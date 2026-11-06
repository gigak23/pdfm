"""Findings about stream encoding: decompression bombs, filter abuse, decode errors."""

from __future__ import annotations

from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument
from pdfm.parser.filters import IMAGE_FILTERS, normalize

RATIO_THRESHOLD = 100
RATIO_MIN_OUTPUT = 1024 * 1024


def analyze(doc: PdfDocument) -> list[Finding]:
    findings: list[Finding] = []
    errors, skipped = [], 0

    for s in doc.streams:
        info = s.info
        chain = [normalize(f) for f in info.filters]

        if info.error and info.error.startswith("skipped"):
            skipped += 1
            continue
        if info.truncated:
            findings.append(Finding(
                "DECOMPRESSION_BOMB", Severity.HIGH,
                "Stream expands past the decode limit (decompression bomb)",
                object_ref=info.ref,
                evidence=f"{info.raw_size:,} encoded bytes; {info.error}",
            ))
        elif info.error:
            errors.append(f"{info.ref}: {info.error}")
        elif info.raw_size and info.decoded_size >= RATIO_MIN_OUTPUT \
                and info.decoded_size / info.raw_size > RATIO_THRESHOLD:
            findings.append(Finding(
                "HIGH_COMPRESSION_RATIO", Severity.LOW,
                f"Stream expands {info.decoded_size // info.raw_size}x when decoded",
                object_ref=info.ref,
                evidence=f"{info.raw_size:,} -> {info.decoded_size:,} bytes",
            ))

        if len(chain) >= 3 or len(set(chain)) < len(chain):
            # Legitimate writers use one filter, occasionally two. Stacking hides content from
            # tools that only undo the first layer.
            findings.append(Finding(
                "UNUSUAL_FILTER_CHAIN", Severity.MEDIUM,
                f"Stream uses an unusual chain of {len(chain)} filters",
                object_ref=info.ref, evidence=" -> ".join(chain),
            ))

        if info.stopped_at and info.stopped_at not in IMAGE_FILTERS and info.stopped_at != "Crypt":
            findings.append(Finding(
                "UNKNOWN_FILTER", Severity.MEDIUM,
                f"Stream uses a non-standard filter /{info.stopped_at}",
                object_ref=info.ref,
            ))

    if errors:
        findings.append(Finding(
            "STREAM_DECODE_ERROR", Severity.LOW,
            f"{len(errors)} stream(s) failed to decode cleanly (corrupt or deliberately malformed)",
            evidence="; ".join(errors[:5]),
        ))
    if skipped:
        findings.append(Finding(
            "DECODE_BUDGET_EXHAUSTED", Severity.MEDIUM,
            f"{skipped} stream(s) not decoded because the file's total decode budget ran out",
        ))
    return findings
