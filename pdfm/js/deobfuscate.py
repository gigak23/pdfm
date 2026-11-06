"""Static, regex-based JavaScript deobfuscation.

Each pass undoes one common trick on literal values only, then the passes repeat
until nothing changes. Nothing is executed here. Non-printable results (e.g.
unescape("%u9090...")) are kept as binary payloads for the shellcode check
instead of being pasted back into the code.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field

MAX_ROUNDS = 20
MAX_CODE = 2 * 1024 * 1024

STR = r"""(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
NUM = r"(?:0[xX][0-9a-fA-F]+|\d+)"

# "a" + "b"  (not when the second literal is followed by .prop / [i] / (args), which binds tighter)
CONCAT_RE = re.compile(rf"({STR})\s*\+\s*({STR})(?!\s*[.\[(])")
FROMCHARCODE_RE = re.compile(rf"String\s*\.\s*fromCharCode\s*\(\s*({NUM}(?:\s*,\s*{NUM})*)\s*\)")
UNESCAPE_RE = re.compile(rf"unescape\s*\(\s*({STR})\s*\)")
REVERSE_RE = re.compile(rf"({STR})\s*\.\s*split\s*\(\s*(?:\"\"|'')\s*\)\s*\.\s*reverse\s*\(\s*\)"
                        rf"\s*\.\s*join\s*\(\s*(?:\"\"|'')\s*\)")
REPLACE_RE = re.compile(rf"({STR})\s*\.\s*replace\s*\(\s*/([A-Za-z0-9_!@#%&=:;,~-]+)/g\s*,\s*({STR})\s*\)")
EVAL_LITERAL_RE = re.compile(rf"\beval\s*\(\s*({STR})\s*\)")
ESCAPED_LITERAL_RE = re.compile(rf"{STR}")
PERCENT_RE = re.compile(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})")
JS_ESCAPE_RE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|([0-7]{1,3})|(\r\n|\n|\r)|(.))", re.S)
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v"}

# Techniques that ordinary scripts don't need. Concatenation and escapes count only in bulk.
STRONG_TECHNIQUES = {"fromCharCode", "unescape", "string-reversal", "replace-junk", "eval-literal"}
BULK_THRESHOLD = 10


@dataclass
class Deobfuscated:
    code: str
    techniques: Counter = field(default_factory=Counter)
    payloads: list[bytes] = field(default_factory=list)

    @property
    def obfuscated(self) -> bool:
        return bool(STRONG_TECHNIQUES & set(self.techniques)) or any(
            self.techniques[t] >= BULK_THRESHOLD for t in ("string-concatenation", "escape-sequences"))


def js_unquote(literal: str) -> str:
    def repl(m: re.Match) -> str:
        hx, ucode, u4, octal, newline, other = m.groups()
        if hx:
            return chr(int(hx, 16))
        if ucode:
            cp = int(ucode, 16)
            return chr(cp) if cp <= 0x10FFFF else ""
        if u4:
            return chr(int(u4, 16))
        if octal:
            return chr(int(octal, 8))
        if newline:
            return ""  # line continuation
        return SIMPLE_ESCAPES.get(other, other)
    return JS_ESCAPE_RE.sub(repl, literal[1:-1])


def js_quote(text: str) -> str:
    return json.dumps(text)


def printable(text: str) -> bool:
    if not text:
        return True
    ok = sum(1 for c in text if c in "\t\n\r" or 0x20 <= ord(c) < 0x7F)
    return ok / len(text) >= 0.95


def percent_decode(text: str) -> str:
    return PERCENT_RE.sub(lambda m: chr(int(m[1] or m[2], 16)), text)


def to_memory_bytes(text: str) -> bytes:
    """How a JS string sits in memory (UTF-16LE): what a heap spray actually places."""
    return text.encode("utf-16-le", "surrogatepass")


def deobfuscate(code: str) -> Deobfuscated:
    result = Deobfuscated(code[:MAX_CODE])

    def run(pattern: re.Pattern, technique: str, replace) -> bool:
        changed = False

        def wrapper(m: re.Match) -> str:
            nonlocal changed
            new = replace(m)
            if new is None or new == m[0]:
                return m[0]
            changed = True
            result.techniques[technique] += 1
            return new

        result.code = pattern.sub(wrapper, result.code)
        return changed

    payload_literals: set[str] = set()

    def unescape_call(m: re.Match) -> str | None:
        text = percent_decode(js_unquote(m[1]))
        if printable(text):
            return js_quote(text)
        # Binary result (shellcode, spray filler): keep the call, hand the bytes to the shellcode check.
        if m[1] not in payload_literals:
            payload_literals.add(m[1])
            result.payloads.append(to_memory_bytes(text))
        return None

    def escaped_literal(m: re.Match) -> str | None:
        if "\\x" not in m[0] and "\\u" not in m[0]:
            return None
        text = js_unquote(m[0])
        return js_quote(text) if printable(text) and js_quote(text) != m[0] else None

    for _ in range(MAX_ROUNDS):
        changed = False
        changed |= run(FROMCHARCODE_RE, "fromCharCode",
                       lambda m: js_quote("".join(chr(int(n, 0) & 0x10FFFF) for n in re.findall(NUM, m[1]))))
        changed |= run(UNESCAPE_RE, "unescape", unescape_call)
        changed |= run(ESCAPED_LITERAL_RE, "escape-sequences", escaped_literal)
        changed |= run(CONCAT_RE, "string-concatenation", lambda m: js_quote(js_unquote(m[1]) + js_unquote(m[2])))
        changed |= run(REVERSE_RE, "string-reversal", lambda m: js_quote(js_unquote(m[1])[::-1]))
        changed |= run(REPLACE_RE, "replace-junk",
                       lambda m: js_quote(js_unquote(m[1]).replace(m[2], js_unquote(m[3]))))
        changed |= run(EVAL_LITERAL_RE, "eval-literal", lambda m: js_unquote(m[1]))
        if not changed or len(result.code) > MAX_CODE:
            break
    # Payload detection counts as unescape usage even though the call was kept.
    if result.payloads:
        result.techniques["unescape"] += len(result.payloads)
    return result
