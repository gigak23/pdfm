"""Output-capped decoders for the standard PDF stream filters.

pikepdf decodes streams correctly but without any output limit, so a 100 KB
stream can expand to gigabytes (a decompression bomb). Every stream is first
decoded here with a hard cap; only streams that pass are handed to pikepdf.
These decoders are also the only option in raw mode, when qpdf has given up.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field

MAX_STREAM_OUTPUT = 50 * 1024 * 1024

# Abbreviations are only legal for inline images, but lenient readers accept them anywhere.
ABBREVIATIONS = {
    "Fl": "FlateDecode", "AHx": "ASCIIHexDecode", "A85": "ASCII85Decode",
    "LZW": "LZWDecode", "RL": "RunLengthDecode", "DCT": "DCTDecode", "CCF": "CCITTFaxDecode",
}
# Image codecs: the output is pixels, not anything we analyze, so decoding stops here.
IMAGE_FILTERS = {"DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode"}


class DecodeError(Exception):
    def __init__(self, message: str, partial: bytes = b""):
        super().__init__(message)
        self.partial = partial


class OutputLimitExceeded(DecodeError):
    pass


def _check(out: bytearray, limit: int) -> None:
    if len(out) > limit:
        raise OutputLimitExceeded(f"decoded output exceeds {limit:,} bytes", bytes(out[:limit]))


FLATE_INPUT_CHUNK = 4096


def flate(data: bytes, limit: int) -> bytes:
    error: zlib.error | None = None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):  # retry as raw deflate if the zlib header is bad
        d = zlib.decompressobj(wbits)
        out = bytearray()
        pos = 0
        pending = b""
        try:
            while not d.eof:
                if not pending:
                    if pos >= len(data):
                        break  # input ran out before the end marker: truncated stream
                    # Small input chunks mean a corrupt block only loses its own output.
                    pending = data[pos:pos + FLATE_INPUT_CHUNK]
                    pos += FLATE_INPUT_CHUNK
                # max_length bounds memory: we never inflate more than one byte past the cap.
                # If output fills up, zlib keeps the unprocessed input in unconsumed_tail.
                out += d.decompress(pending, limit - len(out) + 1)
                _check(out, limit)
                pending = d.unconsumed_tail
            return bytes(out)
        except zlib.error as exc:
            if out:  # keep what decoded before the corruption; readers usually do the same
                raise DecodeError(f"corrupt deflate data: {exc}", bytes(out))
            error = exc
    raise DecodeError(f"invalid deflate data: {error}")


def ascii_hex(data: bytes, limit: int) -> bytes:
    text = re.sub(rb"\s+", b"", data.split(b">", 1)[0])
    if len(text) % 2:
        text += b"0"  # the spec says a missing final digit is 0
    try:
        return binascii.unhexlify(text)
    except binascii.Error as exc:
        raise DecodeError(f"invalid hex data: {exc}")


def ascii85(data: bytes, limit: int) -> bytes:
    text = data.strip()
    if text.startswith(b"<~"):
        text = text[2:]
    text = text.split(b"~>", 1)[0]
    try:
        out = base64.a85decode(text, adobe=False, ignorechars=b" \t\n\r\x0b\x0c")
    except ValueError as exc:
        raise DecodeError(f"invalid ASCII85 data: {exc}")
    if len(out) > limit:  # "z" expands 1 byte to 4, so the bound is 4x input
        raise OutputLimitExceeded(f"decoded output exceeds {limit:,} bytes", out[:limit])
    return out


def run_length(data: bytes, limit: int) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        length = data[i]
        if length == 128:  # end of data
            break
        if length < 128:
            out += data[i + 1:i + 2 + length]
            i += length + 2
        else:
            if i + 1 >= len(data):
                break
            out += data[i + 1:i + 2] * (257 - length)
            i += 2
        _check(out, limit)
    return bytes(out)


def lzw(data: bytes, limit: int, early_change: int = 1) -> bytes:
    """LZW as used by PDF: MSB-first codes of 9-12 bits, 256 = clear, 257 = end."""
    out = bytearray()
    table = [bytes([i]) for i in range(256)] + [b"", b""]
    code_len = 9
    prev: bytes | None = None
    buf = bits = 0
    for byte in data:
        buf = (buf << 8) | byte
        bits += 8
        while bits >= code_len:
            bits -= code_len
            code = (buf >> bits) & ((1 << code_len) - 1)
            buf &= (1 << bits) - 1
            if code == 256:
                del table[258:]
                code_len, prev = 9, None
                continue
            if code == 257:
                return bytes(out)
            if code < len(table):
                entry = table[code]
            elif code == len(table) and prev is not None:
                entry = prev + prev[:1]  # the KwKwK case
            else:
                raise DecodeError(f"invalid LZW code {code}", bytes(out))
            out += entry
            _check(out, limit)
            if prev is not None and len(table) < 4096:
                table.append(prev + entry[:1])
            prev = entry
            if len(table) + early_change >= (1 << code_len) and code_len < 12:
                code_len += 1
    return bytes(out)


DECODERS = {
    "FlateDecode": flate,
    "ASCIIHexDecode": ascii_hex,
    "ASCII85Decode": ascii85,
    "RunLengthDecode": run_length,
    "LZWDecode": lzw,
}


@dataclass
class ChainResult:
    data: bytes
    applied: list[str] = field(default_factory=list)
    stopped_at: str | None = None  # first filter we don't decode (image codec, Crypt, unknown)
    error: str | None = None
    truncated: bool = False  # hit the output cap

    @property
    def complete(self) -> bool:
        return self.stopped_at is None and self.error is None


def normalize(name: str) -> str:
    return ABBREVIATIONS.get(name, name)


def decode_chain(data: bytes, filters: list[str], limit: int = MAX_STREAM_OUTPUT) -> ChainResult:
    result = ChainResult(data)
    for name in map(normalize, filters):
        decoder = DECODERS.get(name)
        if decoder is None:
            result.stopped_at = name
            break
        try:
            result.data = decoder(result.data, limit)
            result.applied.append(name)
        except OutputLimitExceeded as exc:
            result.data, result.error, result.truncated = exc.partial, f"{name}: {exc}", True
            break
        except DecodeError as exc:
            result.data, result.error = exc.partial, f"{name}: {exc}"
            break
    return result


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: ~4.5 for text, ~8.0 for compressed or encrypted data."""
    if not data:
        return 0.0
    total = len(data)
    return abs(-sum(c / total * math.log2(c / total) for c in Counter(data).values()))  # abs: avoid -0.0
