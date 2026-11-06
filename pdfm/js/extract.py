"""Find every piece of JavaScript in a document.

Sources, in the order a reader would run them:
1. Actions reachable from a trigger (OpenAction, document-level scripts, page,
   annotation and form-field events), resolved in parser/actions.py.
2. /JS keys that no trigger reaches. A reader won't run these directly, but
   other scripts can (e.g. via getAnnots or exportDataObject), and they're a
   common place to stash payload code.
3. XFA form <script> blocks.
In raw mode (pikepdf failed), /JS values are pulled straight out of the bytes.
"""

from __future__ import annotations

import binascii
import html
import re
from dataclasses import dataclass

import pikepdf

from pdfm.parser.document import PdfDocument

MAX_DEPTH = 16
# /JS, also written with hex escapes (/J#53, /#4aS, ...) to dodge naive matching.
RAW_JS_KEY_RE = re.compile(rb"/(?:J|#4[Aa])(?:S|#53)(?![A-Za-z0-9#])\s*")
XFA_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.S | re.I)
XFA_AUTORUN_RE = re.compile(r'activity\s*=\s*["\'](?:initialize|docReady|ready|preOpen)["\']', re.I)


@dataclass
class Script:
    ref: str
    trigger: str
    on_open: bool
    code: str


def pdf_text(data: bytes) -> str:
    """Decode a PDF string: UTF-16 or UTF-8 when marked with a BOM, else Latin-1."""
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace")
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    return data.decode("latin-1")


def extract(doc: PdfDocument) -> list[Script]:
    scripts: list[Script] = []
    seen_code: set[str] = set()

    def add(ref: str, trigger: str, on_open: bool, code: str | None) -> None:
        if code and code.strip() and code not in seen_code:
            seen_code.add(code)
            scripts.append(Script(ref, trigger, on_open, code))

    if doc.pdf is None:
        for ref, code in _raw_js(doc):
            add(ref, "raw scan (parser failed)", False, code)
        return scripts

    # Reader order: document-level scripts, then other on-open actions, then event handlers,
    # so the sandbox sees function definitions before their callers.
    def run_order(a) -> int:
        return 0 if a.trigger == "Document-level script" else 1 if a.on_open else 2

    for action in sorted(doc.actions, key=run_order):
        if action.type == "JavaScript":
            add(action.ref, action.trigger, action.on_open, _js_value(doc, action.obj.get("/JS")))
    for ref, value in _all_js_values(doc.pdf):
        add(ref, "not reachable from any trigger", False, _js_value(doc, value))
    for ref, code, on_open in _xfa_scripts(doc):
        add(ref, "XFA form script" + (" (initialize/docReady event)" if on_open else ""), on_open, code)
    return scripts


def _js_value(doc: PdfDocument, value) -> str | None:
    if isinstance(value, pikepdf.String):
        return pdf_text(bytes(value))
    if isinstance(value, pikepdf.Stream):
        stream = doc.stream(*value.objgen)  # PDFM's own capped decode, not an uncapped pikepdf read
        return pdf_text(stream.data) if stream is not None else None
    return None


def _all_js_values(pdf: pikepdf.Pdf):
    """(ref, /JS value) for every dictionary with a /JS key, including nested direct dictionaries."""
    def walk(obj, ref: str, depth: int):
        if depth > MAX_DEPTH:
            return
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            if "/JS" in obj:
                yield ref, obj.get("/JS")
            children = obj.values()
        elif isinstance(obj, pikepdf.Array):
            children = obj
        else:
            return
        for child in children:
            # Indirect children are visited at the top level; following them here could loop.
            if isinstance(child, pikepdf.Object) and not child.is_indirect:
                yield from walk(child, ref, depth + 1)

    for obj in pdf.objects:
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            num, gen = obj.objgen
            yield from walk(obj, f"{num} {gen} R", 0)


def _xfa_scripts(doc: PdfDocument):
    acroform = doc.pdf.Root.get("/AcroForm")
    if not isinstance(acroform, pikepdf.Dictionary) or "/XFA" not in acroform:
        return
    xfa = acroform.XFA
    parts = list(xfa)[1::2] if isinstance(xfa, pikepdf.Array) else [xfa]
    for part in parts:
        if not isinstance(part, pikepdf.Stream):
            continue
        stream = doc.stream(*part.objgen)
        if stream is None:
            continue
        text = stream.data.decode("utf-8", "replace")
        autorun = XFA_AUTORUN_RE.search(text) is not None
        for m in XFA_SCRIPT_RE.finditer(text):
            yield stream.ref, html.unescape(m[1]), autorun


def _raw_js(doc: PdfDocument):
    for ref, head in doc.iter_heads():
        for m in RAW_JS_KEY_RE.finditer(head):
            pos = m.end()
            if head[pos:pos + 1] == b"(":
                yield ref, pdf_text(parse_literal(head, pos))
            elif head[pos:pos + 1] == b"<" and head[pos + 1:pos + 2] != b"<":
                end = head.find(b">", pos)
                hexdata = re.sub(rb"\s+", b"", head[pos + 1:end if end != -1 else len(head)])
                try:
                    yield ref, pdf_text(binascii.unhexlify(hexdata + b"0" * (len(hexdata) % 2)))
                except binascii.Error:
                    continue
            else:
                target = re.match(rb"(\d+)\s+(\d+)\s+R", head[pos:])
                if target:
                    stream = doc.stream(int(target[1]), int(target[2]))
                    if stream is not None:
                        yield f"{target[1].decode()} {target[2].decode()} R", pdf_text(stream.data)


ESCAPES = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12,
           ord("("): 40, ord(")"): 41, ord("\\"): 92}


def parse_literal(data: bytes, pos: int) -> bytes:
    """Parse a PDF literal string starting at the "(" at `pos` (ISO 32000-1 7.3.4.2)."""
    out = bytearray()
    depth = 0
    i = pos
    while i < len(data):
        c = data[i]
        if c == 0x5C:  # backslash
            i += 1
            if i >= len(data):
                break
            e = data[i]
            if e in ESCAPES:
                out.append(ESCAPES[e])
                i += 1
            elif 0x30 <= e <= 0x37:  # up to three octal digits
                j = i
                while j < len(data) and j < i + 3 and 0x30 <= data[j] <= 0x37:
                    j += 1
                out.append(int(data[i:j], 8) & 0xFF)
                i = j
            elif e == 0x0D:  # backslash-newline is a line continuation
                i += 2 if data[i + 1:i + 2] == b"\n" else 1
            elif e == 0x0A:
                i += 1
            else:  # unknown escape: the backslash is ignored
                out.append(e)
                i += 1
            continue
        if c == 0x28:
            depth += 1
            if depth > 1:
                out.append(c)
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out)
            out.append(c)
        else:
            out.append(c)
        i += 1
    return bytes(out)  # unterminated string: return what we have
