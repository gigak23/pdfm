"""Generate harmless PDFs that exercise PDFM's detections.

The files contain structure only, never working payloads. They're built byte by
byte so each fixture is exactly what we intend (pikepdf would normalize away
the oddities we want to test).
"""

from __future__ import annotations

import io
import re

import pikepdf

HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"


def stream(data: bytes, extra: bytes = b"") -> bytes:
    return b"<< /Length %d%s >>\nstream\n" % (len(data), extra) + data + b"\nendstream"


def base_objects(text: bytes = b"Hello from PDFM") -> dict[int, bytes]:
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
           b" /Resources << /Font << /F1 5 0 R >> >> >>",
        4: stream(b"BT /F1 24 Tf 72 720 Td (" + text + b") Tj ET"),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }


def _write_objects(out: bytearray, objects: dict[int, bytes]) -> dict[int, int]:
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    return offsets


def build_pdf(objects: dict[int, bytes], root: int = 1) -> bytes:
    """A complete single-revision PDF with a classic xref table."""
    out = bytearray(HEADER)
    offsets = _write_objects(out, objects)
    size = max(objects) + 1

    xref_at = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f\r\n" % size
    for num in range(1, size):
        if num in offsets:
            out += b"%010d 00000 n\r\n" % offsets[num]
        else:
            out += b"0000000000 00000 f\r\n"
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, root, xref_at)
    return bytes(out)


def append_update(base: bytes, objects: dict[int, bytes], root: int = 1) -> bytes:
    """Append an incremental update that adds or replaces `objects`."""
    prev_xref = int(re.findall(rb"startxref\s+(\d+)", base)[-1])
    prev_size = int(re.findall(rb"/Size\s+(\d+)", base)[-1])
    size = max(prev_size, max(objects) + 1)

    out = bytearray(base)
    offsets = _write_objects(out, objects)
    xref_at = len(out)
    out += b"xref\n"
    for num in sorted(offsets):
        out += b"%d 1\n%010d 00000 n\r\n" % (num, offsets[num])
    out += b"trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        size, root, prev_xref, xref_at)
    return bytes(out)


def build_all() -> dict[str, bytes]:
    clean = build_pdf(base_objects())

    # pikepdf can pack objects into /ObjStm streams for us.
    packed = io.BytesIO()
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        pdf.save(packed, object_stream_mode=pikepdf.ObjectStreamMode.generate)

    # Objects but no xref, trailer, or startxref. qpdf rebuilds the xref but drops the last object.
    no_trailer = bytearray(HEADER)
    _write_objects(no_trailer, base_objects())

    # No xref and no Catalog: qpdf cannot rebuild a trailer at all, which forces the raw fallback.
    no_catalog_objects = base_objects()
    del no_catalog_objects[1]
    no_catalog = bytearray(HEADER)
    _write_objects(no_catalog, no_catalog_objects)

    return {
        "clean.pdf": clean,
        "incremental.pdf": append_update(clean, {4: stream(b"BT /F1 24 Tf 72 720 Td (Revised) Tj ET")}),
        "objstm.pdf": packed.getvalue(),
        "no_trailer.pdf": bytes(no_trailer),
        "no_catalog.pdf": bytes(no_catalog),
        "truncated.pdf": clean[: len(clean) // 2],
    }
