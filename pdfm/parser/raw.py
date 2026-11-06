"""Regex-based object scanner that works on files too broken for pikepdf.

Malicious PDFs are often malformed on purpose (missing trailer, bad xref,
truncated) so that strict parsers give up while lenient readers like Acrobat
still render them. This scanner ignores the xref and trailer entirely and finds
objects by their "N G obj" headers, like pdf-parser.py does.

Objects are walked in order and stream data is skipped as a unit, so text that
merely looks like "N 0 obj" inside a stream (e.g. an embedded PDF) is not
mistaken for a real object.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from pdfm.models import PdfObject

# (?<!\d) stops "110 0 obj" from also matching as "10 0 obj".
OBJ_HEADER_RE = re.compile(rb"(?<!\d)(\d{1,10})\s+(\d{1,5})\s+obj\b")
# The stream keyword must directly follow the dictionary's closing ">>"; a bare match on
# "stream" would also hit strings like "(Datastream)" and skip over real objects.
STREAM_OR_END_RE = re.compile(rb">>[\x00\t\n\x0c\r ]*(stream)\b|endobj")
NAME_ESCAPE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
FILTER_RE = re.compile(rb"/Filter\s*(\[[^\]]*\]|/[^\s/\[\]<>()]+)")
NAME_TOKEN_RE = re.compile(rb"/([^\s/\[\]<>(){}%]+)")


@dataclass
class RawObject:
    num: int
    gen: int
    offset: int  # offset of the "N G obj" header
    head: bytes  # the object body before any stream data (usually the dictionary)
    stream_span: tuple[int, int] | None = None  # [start, end) of raw stream data in the file

    @property
    def ref(self) -> str:
        return f"{self.num} {self.gen} R"


def decode_name(raw_name: bytes) -> str:
    """Resolve #xx escapes in a PDF name: b"J#61vaScript" -> "JavaScript"."""
    return NAME_ESCAPE_RE.sub(lambda m: bytes([int(m[1], 16)]), raw_name).decode("latin-1")


def name_value(head: bytes, key: bytes) -> str | None:
    """Value of a name-valued key in a raw dictionary, e.g. name_value(head, b"Type")."""
    m = re.search(rb"/" + key + rb"\s*/([^\s/\[\]<>()]+)", head)
    return decode_name(m[1]) if m else None


def filter_names(head: bytes) -> list[str]:
    m = FILTER_RE.search(head)
    if not m:
        return []
    return [decode_name(n) for n in NAME_TOKEN_RE.findall(m[1])]


def iter_objects(data: bytes) -> Iterator[RawObject]:
    """Every object definition in file order, including ones replaced by later revisions."""
    pos = 0
    while m := OBJ_HEADER_RE.search(data, pos):
        start = m.end()
        kw = STREAM_OR_END_RE.search(data, start)
        if kw is None:
            # Truncated object: body runs to the next header or end of file.
            nxt = OBJ_HEADER_RE.search(data, start)
            end = nxt.start() if nxt else len(data)
            yield RawObject(int(m[1]), int(m[2]), m.start(), data[start:end])
            pos = end
            continue

        if kw[0] == b"endobj":
            # A later header before this endobj means the object was never closed.
            nxt = OBJ_HEADER_RE.search(data, start, kw.start())
            end = nxt.start() if nxt else kw.start()
            yield RawObject(int(m[1]), int(m[2]), m.start(), data[start:end])
            pos = end if nxt else kw.end()
            continue

        # Stream object: data starts after the EOL following "stream" and ends at "endstream".
        # /Length is ignored on purpose; attackers set it wrong to confuse parsers.
        nxt = OBJ_HEADER_RE.search(data, start, kw.start())
        if nxt:  # "stream" belongs to a later object; this one has no body terminator
            yield RawObject(int(m[1]), int(m[2]), m.start(), data[start:nxt.start()])
            pos = nxt.start()
            continue
        head_end = kw.start(1)
        stream_start = kw.end()
        if data[stream_start:stream_start + 2] == b"\r\n":
            stream_start += 2
        elif data[stream_start:stream_start + 1] in (b"\n", b"\r"):
            stream_start += 1
        stream_end = data.find(b"endstream", stream_start)
        if stream_end == -1:
            stream_end = len(data)
            pos = len(data)
        else:
            pos = stream_end + len(b"endstream")
            # Trim the EOL that precedes "endstream".
            if data[stream_end - 2:stream_end] == b"\r\n":
                stream_end -= 2
            elif data[stream_end - 1:stream_end] in (b"\n", b"\r"):
                stream_end -= 1
        yield RawObject(int(m[1]), int(m[2]), m.start(), data[start:head_end], (stream_start, stream_end))


def object_offsets(data: bytes) -> dict[tuple[int, int], int]:
    """Map (num, gen) to the byte offset of its header.

    When an object is redefined by an incremental update, the last definition wins,
    which matches how readers resolve it.
    """
    return {(o.num, o.gen): o.offset for o in iter_objects(data)}


def summarize(raw_objects: list[RawObject]) -> list[PdfObject]:
    latest: dict[tuple[int, int], PdfObject] = {}
    for o in raw_objects:
        obj_type = name_value(o.head, b"Type")
        if obj_type is None:
            if o.stream_span:
                obj_type = "stream"
            elif o.head.lstrip().startswith(b"<<"):
                obj_type = "dict"
            else:
                obj_type = "other"
        latest[(o.num, o.gen)] = PdfObject(
            num=o.num, gen=o.gen, type=obj_type, is_stream=o.stream_span is not None, offset=o.offset
        )
    return sorted(latest.values(), key=lambda p: (p.num, p.gen))


def scan_objects(data: bytes) -> list[PdfObject]:
    return summarize(list(iter_objects(data)))
