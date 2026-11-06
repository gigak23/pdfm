"""Load a PDF into a uniform object model.

pikepdf (a wrapper around qpdf) is the primary parser. qpdf quietly repairs many
broken files, so we keep its warnings as findings. If it fails outright, we fall
back to the raw scanner so that a deliberately malformed sample still gets analyzed.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from pathlib import Path

import pikepdf

from pdfm.models import Finding, PdfObject, Severity
from pdfm.parser import raw

HEADER_RE = re.compile(rb"%PDF-(\d\.\d)")
# qpdf prefixes warnings with the input name, e.g. "stream <_io.BytesIO object at 0x...>: "
WARNING_PREFIX_RE = re.compile(r"^stream <[^>]*>:?\s*")


@dataclass
class PdfDocument:
    path: Path
    data: bytes
    mode: str  # "pikepdf" or "raw"
    version: str | None
    objects: list[PdfObject]
    eof_count: int
    startxref_count: int
    pdf: pikepdf.Pdf | None = None  # None in raw mode
    findings: list[Finding] = field(default_factory=list)

    @property
    def revisions(self) -> int:
        # Each incremental update appends a new xref section ending in %%EOF.
        # Linearized files also contain two %%EOF markers, so treat this as an upper bound.
        return max(self.eof_count, 1)

    def close(self) -> None:
        if self.pdf is not None:
            self.pdf.close()


def load(path: str | Path) -> PdfDocument:
    path = Path(path)
    data = path.read_bytes()

    header = HEADER_RE.search(data[:1024])
    doc = PdfDocument(
        path=path,
        data=data,
        mode="pikepdf",
        version=header[1].decode() if header else None,
        objects=[],
        eof_count=data.count(b"%%EOF"),
        startxref_count=data.count(b"startxref"),
    )
    offsets = raw.object_offsets(data)

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
            doc.objects = _walk(doc.pdf, offsets)
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


def _fall_back_to_raw(doc: PdfDocument) -> None:
    if doc.pdf is not None:
        doc.pdf.close()
    doc.pdf = None
    doc.mode = "raw"
    doc.objects = raw.scan_objects(doc.data)


def _flag_unindexed(doc: PdfDocument, offsets: dict[tuple[int, int], int]) -> None:
    """Flag objects that exist in the bytes but that qpdf never saw.

    A crafted xref can hide objects from parsers that follow it, while other
    readers that scan the file still find them.
    """
    seen = {(o.num, o.gen) for o in doc.objects}
    hidden = sorted(set(offsets) - seen)
    if hidden:
        doc.findings.append(Finding(
            "UNINDEXED_OBJECTS", Severity.MEDIUM,
            f"{len(hidden)} object(s) present in the file bytes but not reachable through the xref",
            evidence=", ".join(f"{n} {g} R @ {offsets[(n, g)]}" for n, g in hidden[:20]),
        ))


def _walk(pdf: pikepdf.Pdf,offsets: dict[tuple[int, int], int]) -> list[PdfObject]:
    packed = _objstm_members(pdf)
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


def _objstm_members(pdf: pikepdf.Pdf) -> set[int]:
    """Object numbers stored inside /ObjStm streams.

    An object stream's decoded data starts with /N pairs of "objnum offset",
    followed by the objects themselves at byte /First.
    """
    members: set[int] = set()
    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Stream) or obj.get("/Type") != pikepdf.Name.ObjStm:
            continue
        try:
            count, first = int(obj.N), int(obj.First)
            pairs = obj.read_bytes()[:first].split()
            members.update(int(n) for n in pairs[0:2 * count:2])
        except (pikepdf.PdfError, ValueError, AttributeError):
            continue  # a malformed object stream is itself suspicious; M3 flags it
    return members
