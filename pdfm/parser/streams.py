"""Decode every stream in a document, safely.

Each stream goes through PDFM's capped decoders first. That gate catches
decompression bombs and works even when qpdf could not parse the file. If the
gate succeeds and pikepdf is available, pikepdf produces the final output,
because it also handles predictors (/DecodeParms) and other edge cases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pikepdf

from pdfm.models import StreamInfo
from pdfm.parser import filters, raw

if TYPE_CHECKING:
    from pdfm.parser.document import PdfDocument

MAX_TOTAL_OUTPUT = 256 * 1024 * 1024  # budget across all streams in one file
IMAGE_SAMPLE_LIMIT = 4 * 1024 * 1024
# Upper bound on decoded image bytes per pixel: 4 color components x 16 bits, plus predictor slack.
IMAGE_BYTES_PER_PIXEL = 9
# FontFile streams carry /Length1 (and Type 1 also /Length2, /Length3); FontFile3 is marked by /Subtype.
FONT_SUBTYPES = {"Type1C", "CIDFontType0C", "OpenType"}


@dataclass
class DecodedStream:
    info: StreamInfo
    data: bytes

    @property
    def ref(self) -> str:
        return self.info.ref


def decode_all(doc: PdfDocument, limit: int = filters.MAX_STREAM_OUTPUT,
               total_limit: int = MAX_TOTAL_OUTPUT) -> list[DecodedStream]:
    sources = _pikepdf_sources(doc.pdf) if doc.pdf is not None else _raw_sources(doc)
    decoded: list[DecodedStream] = []
    budget = total_limit
    for num, gen, head_info, encoded, pike_stream in sources:
        info = StreamInfo(num=num, gen=gen, raw_size=len(encoded or b""), **head_info)
        if encoded is None:
            # Never fall through to pikepdf here: an unread stream has not passed the gate.
            info.error = "could not read raw stream data"
            decoded.append(DecodedStream(info, b""))
            continue
        if budget <= 0:
            info.error = "skipped: total decode budget for this file exhausted"
            decoded.append(DecodedStream(info, b""))
            continue

        # The smallest applicable cap wins; which one it was decides how truncation is reported.
        is_image = info.subtype == "Image"
        caps = {"stream-cap": limit, "budget": budget}
        if is_image:
            if info.image_bound is not None:
                caps["declared-size"] = info.image_bound
            caps["image-sample"] = IMAGE_SAMPLE_LIMIT  # pixels are never analyzed; a sample is enough
        reason, cap = min(caps.items(), key=lambda kv: kv[1])

        result = filters.decode_chain(encoded, info.filters, cap)
        if result.truncated and reason == "image-sample":
            result.truncated, result.error = False, None
            info.partial = True
        elif result.truncated and reason == "budget":
            result.truncated = False
            result.error = "skipped: total decode budget for this file exhausted (partially decoded)"
        elif result.truncated and reason == "declared-size":
            result.error = f"image data exceeds the {cap:,} bytes its /Width and /Height allow"

        data = result.data
        if pike_stream is not None and result.complete and info.filters and not is_image:
            try:
                # Safe: the gate just proved the output fits under the cap.
                data = pike_stream.read_bytes(decode_level=pikepdf.StreamDecodeLevel.specialized)
            except pikepdf.PdfError:
                pass  # keep PDFM's own output
        info.decoded_size = len(data)
        info.complete = result.complete
        info.truncated = result.truncated
        info.error = result.error
        info.stopped_at = result.stopped_at
        info.entropy = round(filters.entropy(data), 3)
        budget -= len(data)
        decoded.append(DecodedStream(info, data))
    return decoded


def objstm_index(stream: DecodedStream, first: int | None, count: int | None) -> list[tuple[int, int]]:
    """(object number, offset into decoded data) for each object inside an /ObjStm."""
    if first is None or count is None:
        return []
    pairs = stream.data[:first].split()
    out = []
    for i in range(0, min(len(pairs), 2 * count) - 1, 2):
        try:
            out.append((int(pairs[i]), first + int(pairs[i + 1])))
        except ValueError:
            break
    return out


def _pikepdf_sources(pdf: pikepdf.Pdf):
    for obj in pdf.objects:
        if obj is None or not isinstance(obj, pikepdf.Stream):
            continue
        num, gen = obj.objgen
        head = _pike_head_info(obj)
        try:
            # Still encoded, but already decrypted: qpdf removes encryption before any filter.
            encoded = obj.read_raw_bytes()
        except pikepdf.PdfError:
            encoded = None
        yield num, gen, head, encoded, obj


def _pike_head_info(obj: pikepdf.Stream) -> dict:
    value = obj.get("/Filter")
    if isinstance(value, pikepdf.Name):
        names = [str(value)]
    elif isinstance(value, pikepdf.Array):
        names = [str(v) for v in value if isinstance(v, pikepdf.Name)]
    else:
        names = []

    def name_or_none(key: str) -> str | None:
        v = obj.get(key)
        return str(v).lstrip("/") if isinstance(v, pikepdf.Name) else None

    def int_or_none(key: str) -> int | None:
        try:
            return int(obj[key]) if key in obj else None
        except (TypeError, ValueError):
            return None

    subtype = name_or_none("/Subtype")
    return {
        "filters": [n.lstrip("/") for n in names],
        "dict_type": name_or_none("/Type"),
        "subtype": subtype,
        "objstm_first": int_or_none("/First"),
        "objstm_count": int_or_none("/N"),
        "font_program": "/Length1" in obj or subtype in FONT_SUBTYPES,
        "image_bound": _image_bound(int_or_none("/Width"), int_or_none("/Height")),
    }


def _image_bound(width: int | None, height: int | None) -> int | None:
    if width is None or height is None or width <= 0 or height <= 0:
        return None
    return width * height * IMAGE_BYTES_PER_PIXEL


def _raw_sources(doc: PdfDocument):
    for o in doc.raw_objects:
        if o.stream_span is None:
            continue
        start, end = o.stream_span
        first = re.search(rb"/First\s+(\d+)", o.head)
        count = re.search(rb"/N\s+(\d+)", o.head)
        subtype = raw.name_value(o.head, b"Subtype")
        width = re.search(rb"/Width\s+(\d+)", o.head)
        height = re.search(rb"/Height\s+(\d+)", o.head)
        info = {
            "filters": raw.filter_names(o.head),
            "dict_type": raw.name_value(o.head, b"Type"),
            "subtype": subtype,
            "objstm_first": int(first[1]) if first else None,
            "objstm_count": int(count[1]) if count else None,
            "font_program": re.search(rb"/Length1\b", o.head) is not None or subtype in FONT_SUBTYPES,
            "image_bound": _image_bound(int(width[1]) if width else None, int(height[1]) if height else None),
        }
        yield o.num, o.gen, info, doc.data[start:end], None
