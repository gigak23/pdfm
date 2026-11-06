"""Load a PDF into a uniform object model.

pikepdf (a wrapper around qpdf) is the primary parser. qpdf quietly repairs many
broken files, so we keep its warnings as findings. If it fails outright, we fall
back to the raw scanner so that a deliberately malformed sample still gets analyzed.
The raw scan always runs too, because comparing the two views exposes objects
hidden from xref-following parsers.
"""

from __future__ import annotations

import bisect
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import pikepdf

from pdfm.models import Finding, PdfObject, Severity
from pdfm.parser import raw, streams
from pdfm.parser.raw import RawObject
from pdfm.parser.streams import DecodedStream

MAX_FILE_SIZE = 200 * 1024 * 1024
HEADER_RE = re.compile(rb"%PDF-(\d\.\d)")
# qpdf prefixes warnings with the input name, e.g. "stream <_io.BytesIO object at 0x...>: "
WARNING_PREFIX_RE = re.compile(r"^stream <[^>]*>:?\s*")


class FileTooLarge(Exception):
    pass


@dataclass
class PdfDocument:
    name: str
    data: bytes
    mode: str  # "pikepdf" or "raw"
    version: str | None
    header_offset: int | None  # where "%PDF-" was found; readers accept it within the first 1 KB
    raw_objects: list[RawObject]  # every definition in the bytes, in file order
    eof_offsets: list[int]  # end offset of each %%EOF marker outside stream data
    objects: list[PdfObject] = field(default_factory=list)
    streams: list[DecodedStream] = field(default_factory=list)
    pdf: pikepdf.Pdf | None = None  # None in raw mode
    findings: list[Finding] = field(default_factory=list)

    @property
    def eof_count(self) -> int:
        return len(self.eof_offsets)

    @property
    def revisions(self) -> int:
        # Each incremental update appends a new xref section ending in %%EOF.
        # Linearized files also contain two %%EOF markers, so treat this as an upper bound.
        return max(self.eof_count, 1)

    def stream(self, num: int, gen: int = 0) -> DecodedStream | None:
        for s in reversed(self.streams):  # latest definition wins
            if s.info.num == num and s.info.gen == gen:
                return s
        return None

    def iter_heads(self) -> Iterator[tuple[str, bytes]]:
        """(object ref, dictionary bytes) for every object definition.

        Covers every revision in the raw bytes plus objects packed inside object
        streams, with names left exactly as written (so #xx escapes are visible).
        """
        for o in self.raw_objects:
            yield o.ref, o.head
        for s in self.streams:
            if s.info.dict_type != "ObjStm":
                continue
            index = streams.objstm_index(s, s.info.objstm_first, s.info.objstm_count)
            for i, (num, start) in enumerate(index):
                end = index[i + 1][1] if i + 1 < len(index) else len(s.data)
                yield f"{num} 0 R", s.data[start:end]

    def close(self) -> None:
        if self.pdf is not None:
            self.pdf.close()


def load(path: str | Path) -> PdfDocument:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_SIZE:
        raise FileTooLarge(f"{path} is larger than {MAX_FILE_SIZE // (1024 * 1024)} MB")
    return load_bytes(path.read_bytes(), str(path))


def load_bytes(data: bytes, name: str = "<memory>") -> PdfDocument:
    if len(data) > MAX_FILE_SIZE:
        raise FileTooLarge(f"{name} is larger than {MAX_FILE_SIZE // (1024 * 1024)} MB")

    raw_objects = list(raw.iter_objects(data))
    header = HEADER_RE.search(data[:1024])
    doc = PdfDocument(
        name=name,
        data=data,
        mode="pikepdf",
        version=header[1].decode() if header else None,
        header_offset=header.start() if header else None,
        raw_objects=raw_objects,
        eof_offsets=_eof_offsets(data, raw_objects),
    )
    offsets = {(o.num, o.gen): o.offset for o in raw_objects}

    try:
        # Open from memory so Windows doesn't keep a lock on the sample file.
        doc.pdf = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError as exc:
        doc.findings.append(Finding(
            "ENCRYPTED_USER_PASSWORD", Severity.MEDIUM,
            "File requires a password to open; content analysis limited to raw scan",
            evidence=WARNING_PREFIX_RE.sub("", str(exc)),
        ))
        _fall_back_to_raw(doc)
    except pikepdf.PdfError as exc:
        doc.findings.append(Finding(
            "PARSE_FALLBACK", Severity.MEDIUM,
            "pikepdf could not parse the file; used raw object scan (often a deliberate evasion)",
            evidence=WARNING_PREFIX_RE.sub("", str(exc)),
        ))
        _fall_back_to_raw(doc)
    else:
        warnings = [WARNING_PREFIX_RE.sub("", w) for w in doc.pdf.get_warnings()]
        if warnings:
            doc.findings.append(Finding(
                "PARSER_REPAIRED", Severity.LOW,
                f"qpdf repaired or worked around {len(warnings)} structural problem(s)",
                evidence="; ".join(warnings[:5]),
            ))

        if "/Root" not in doc.pdf.trailer:
            # qpdf "recovered" the file but found no document catalog, so its view is useless.
            doc.findings.append(Finding(
                "PARSE_FALLBACK", Severity.MEDIUM,
                "No usable trailer or /Root after repair; used raw object scan (often a deliberate evasion)",
            ))
            _fall_back_to_raw(doc)
        else:
            doc.streams = streams.decode_all(doc)
            doc.objects = _walk(doc.pdf, offsets, _objstm_members(doc))
            _flag_unindexed(doc, offsets)

    if doc.eof_count > 1:
        doc.findings.append(Finding(
            "INCREMENTAL_UPDATES", Severity.INFO,
            f"File has {doc.eof_count} %%EOF markers (incremental updates or linearization)",
        ))
    packed = sum(o.in_objstm for o in doc.objects)
    if packed:
        doc.findings.append(Finding(
            "OBJECT_STREAMS", Severity.INFO,
            f"{packed} objects are stored compressed inside object streams (/ObjStm)",
        ))
    return doc


def _eof_offsets(data: bytes, raw_objects: list[RawObject]) -> list[int]:
    """End offsets of %%EOF markers, ignoring any that sit inside stream data."""
    spans = sorted(o.stream_span for o in raw_objects if o.stream_span)
    starts = [s for s, _ in spans]
    out = []
    for m in re.finditer(rb"%%EOF", data):
        i = bisect.bisect_right(starts, m.start()) - 1
        if i >= 0 and m.start() < spans[i][1]:
            continue
        out.append(m.end())
    return out


def _fall_back_to_raw(doc: PdfDocument) -> None:
    if doc.pdf is not None:
        doc.pdf.close()
    doc.pdf = None
    doc.mode = "raw"
    doc.streams = streams.decode_all(doc)
    doc.objects = raw.summarize(doc.raw_objects)

    # Objects inside object streams have no "N G obj" header in the file; list them too.
    known = {o.num for o in doc.objects}
    for ref, head in doc.iter_heads():
        num = int(ref.split()[0])
        if num in known:
            continue
        known.add(num)
        doc.objects.append(PdfObject(
            num=num, gen=0, type=raw.name_value(head, b"Type") or "dict", is_stream=False, in_objstm=True,
        ))
    doc.objects.sort(key=lambda o: (o.num, o.gen))


def _objstm_members(doc: PdfDocument) -> set[int]:
    members: set[int] = set()
    for s in doc.streams:
        if s.info.dict_type == "ObjStm":
            members.update(num for num, _ in streams.objstm_index(s, s.info.objstm_first, s.info.objstm_count))
    return members


def _flag_unindexed(doc: PdfDocument, offsets: dict[tuple[int, int], int]) -> None:
    """Flag objects that exist in the bytes but that qpdf never saw.

    A crafted xref can hide objects from parsers that follow it, while other
    readers that scan the file still find them. Older generations of an object
    that qpdf does know are normal leftovers from editing, so they're skipped.
    """
    seen = {(o.num, o.gen) for o in doc.objects}
    seen_gen = {}
    for num, gen in seen:
        seen_gen[num] = max(gen, seen_gen.get(num, -1))
    hidden = sorted(k for k in set(offsets) - seen if k[1] > seen_gen.get(k[0], -1))
    if not hidden:
        return
    # Editors that delete objects in an incremental update legitimately leave them behind.
    severity = Severity.LOW if doc.eof_count > 1 else Severity.MEDIUM
    doc.findings.append(Finding(
        "UNINDEXED_OBJECTS", severity,
        f"{len(hidden)} object(s) present in the file bytes but not reachable through the xref",
        evidence=", ".join(f"{n} {g} R @ {offsets[(n, g)]}" for n, g in hidden[:20]),
    ))


def _walk(pdf: pikepdf.Pdf, offsets: dict[tuple[int, int], int], packed: set[int]) -> list[PdfObject]:
    objects = []
    for obj in pdf.objects:
        if obj is None:  # pikepdf returns null objects as None
            continue
        num, gen = obj.objgen
        if num == 0:  # direct objects or empty slots have no object number
            continue
        is_stream = isinstance(obj, pikepdf.Stream)
        objects.append(PdfObject(
            num=num,
            gen=gen,
            type=_type_name(obj, is_stream),
            is_stream=is_stream,
            in_objstm=num in packed,
            offset=offsets.get((num, gen)) if num not in packed else None,
        ))
    return sorted(objects, key=lambda o: (o.num, o.gen))


def _type_name(obj: pikepdf.Object, is_stream: bool) -> str:
    if is_stream or isinstance(obj, pikepdf.Dictionary):
        declared = obj.get("/Type")
        if isinstance(declared, pikepdf.Name):
            return str(declared).lstrip("/")
        return "stream" if is_stream else "dict"
    return obj._type_name  # "array", "integer", "string", "null", ...
