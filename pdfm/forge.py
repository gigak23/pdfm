"""Generate harmless PDFs that exercise PDFM's detections.

The files contain structure only, never working payloads. They're built byte by
byte so each fixture is exactly what we intend (pikepdf would normalize away
the oddities we want to test).
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import zlib

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


def lzw_encode(data: bytes) -> bytes:
    """PDF-style LZW (MSB-first, EarlyChange=1). Mirrors pdfm.parser.filters.lzw."""
    out = bytearray()
    acc = nbits = 0
    code_len = 9

    def emit(code: int) -> None:
        nonlocal acc, nbits
        acc = (acc << code_len) | code
        nbits += code_len
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
        acc &= (1 << nbits) - 1

    def reset() -> dict[bytes, int]:
        return {bytes([i]): i for i in range(256)}

    table, next_code = reset(), 258
    emit(256)
    w = b""
    for c in data:
        wc = w + bytes([c])
        if wc in table:
            w = wc
            continue
        emit(table[w])
        table[wc] = next_code
        next_code += 1
        # The decoder's table lags one entry behind ours, so it widens codes when it holds
        # next_code - 1 entries; EarlyChange=1 makes that happen one code early.
        if next_code >= (1 << code_len) and code_len < 12:
            code_len += 1
        if next_code >= 4094:
            emit(256)
            table, next_code, code_len = reset(), 258, 9
        w = bytes([c])
    if w:
        emit(table[w])
        next_code += 1
        if next_code >= (1 << code_len) and code_len < 12:
            code_len += 1
    emit(257)
    if nbits:
        out.append((acc << (8 - nbits)) & 0xFF)
    return bytes(out)


def run_length_encode(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i:i + 128]
        out += bytes([len(chunk) - 1]) + chunk
    return bytes(out + b"\x80")


def flate_bomb(size: int = 60 * 1024 * 1024) -> bytes:
    """`size` zero bytes deflated to well under 100 KB, compressed in chunks to keep memory low."""
    c = zlib.compressobj(9)
    block = b"\0" * (1024 * 1024)
    out = bytearray()
    for _ in range(size // len(block)):
        out += c.compress(block)
    return bytes(out + c.flush())


def with_extra(extra: dict[int, bytes]) -> bytes:
    objects = base_objects()
    objects.update(extra)
    return build_pdf(objects)


SAMPLE_TEXT = b"PDFM test stream: nothing to see here. " * 4


def build_all() -> dict[str, bytes]:
    clean = build_pdf(base_objects())

    # pikepdf can pack objects into /ObjStm streams for us.
    packed = io.BytesIO()
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        pdf.save(packed, object_stream_mode=pikepdf.ObjectStreamMode.generate)

    # Owner-password-only encryption: opens without a password, but every string and stream is encrypted.
    def encrypt(**kwargs) -> bytes:
        out = io.BytesIO()
        plain = with_extra({6: stream(zlib.compress(SAMPLE_TEXT), b" /Filter /FlateDecode")})
        with pikepdf.open(io.BytesIO(plain)) as pdf:
            pdf.Root.Extra = pdf.get_object(6, 0)  # referenced, so qpdf keeps it on save
            pdf.save(out, encryption=pikepdf.Encryption(owner="pdfm-owner", user="", **kwargs))
        return out.getvalue()

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
        "encrypted.pdf": encrypt(R=6),
        "encrypted_aes128.pdf": encrypt(R=4, aes=True),
        "encrypted_rc4.pdf": encrypt(R=4, aes=False, metadata=False),
        "no_trailer.pdf": bytes(no_trailer),
        "no_catalog.pdf": bytes(no_catalog),
        "truncated.pdf": clean[: len(clean) // 2],
        # M2: stream encodings
        "chained.pdf": with_extra({6: stream(
            binascii.hexlify(zlib.compress(SAMPLE_TEXT)) + b">",
            b" /Filter [/ASCIIHexDecode /FlateDecode]")}),
        "triple_chain.pdf": with_extra({6: stream(
            base64.a85encode(binascii.hexlify(zlib.compress(SAMPLE_TEXT)) + b">") + b"~>",
            b" /Filter [/ASCII85Decode /ASCIIHexDecode /FlateDecode]")}),
        "lzw_rle.pdf": with_extra({
            6: stream(lzw_encode(SAMPLE_TEXT), b" /Filter /LZWDecode"),
            7: stream(run_length_encode(SAMPLE_TEXT), b" /Filter /RunLengthDecode"),
        }),
        "bomb.pdf": with_extra({6: stream(flate_bomb(), b" /Filter /FlateDecode")}),
    }
