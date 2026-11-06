"""Regex-based object scanner that works on files too broken for pikepdf.

Malicious PDFs are often malformed on purpose (missing trailer, bad xref,
truncated) so that strict parsers give up while lenient readers like Acrobat
still render them. This scanner ignores the xref and trailer entirely and finds
objects by their "N G obj" headers, like pdf-parser.py does.
"""

from __future__ import annotations

import re

from pdfm.models import PdfObject

# (?<!\d) stops "110 0 obj" from also matching as "10 0 obj".
OBJ_HEADER_RE = re.compile(rb"(?<!\d)(\d{1,10})\s+(\d{1,5})\s+obj\b")
TYPE_RE = re.compile(rb"/Type\s*/([A-Za-z0-9_.#-]+)")


def object_offsets(data: bytes) -> dict[tuple[int, int], int]:
    """Map (num, gen) to the byte offset of its header.

    When an object is redefined by an incremental update, the last definition wins,
    which matches how readers resolve it.
    """
    return {(int(m[1]), int(m[2])): m.start() for m in OBJ_HEADER_RE.finditer(data)}


def scan_objects(data: bytes) -> list[PdfObject]:
    matches = list(OBJ_HEADER_RE.finditer(data))
    latest: dict[tuple[int, int], PdfObject] = {}

    for i, m in enumerate(matches):
        # The body runs to "endobj", or to the next header if the file is truncated.
        end = matches[i + 1].start() if i + 1 < len(matches) else len(data)
        body = data[m.end():end]
        cut = body.find(b"endobj")
        if cut != -1:
            body = body[:cut]

        stream_at = body.find(b"stream")
        head = body[:stream_at] if stream_at != -1 else body
        type_match = TYPE_RE.search(head)
        if type_match:
            obj_type = type_match[1].decode("latin-1")
        elif stream_at != -1:
            obj_type = "stream"
        elif head.lstrip().startswith(b"<<"):
            obj_type = "dict"
        else:
            obj_type = "other"

        num, gen = int(m[1]), int(m[2])
        latest[(num, gen)] = PdfObject(
            num=num, gen=gen, type=obj_type, is_stream=stream_at != -1, offset=m.start()
        )

    return sorted(latest.values(), key=lambda o: (o.num, o.gen))
