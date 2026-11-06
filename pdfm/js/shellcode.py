"""Heuristics for binary payloads recovered from JavaScript strings.

These are recognizable byte patterns, not emulation: NOP sleds, heap-spray
filler, and the position-finding and API-resolution idioms most x86 shellcode
needs before it can do anything.
"""

from __future__ import annotations

import re

PATTERNS = [
    (re.compile(rb"\x90{32,}"), "NOP sled (32+ x 0x90)"),
    (re.compile(rb"(?:\x0c\x0c\x0c\x0c){8,}"), "0x0c0c0c0c heap-spray filler"),
    (re.compile(rb"(?:\x0a\x0a\x0a\x0a){8,}"), "0x0a0a0a0a heap-spray filler"),
    (re.compile(rb"\xe8\x00\x00\x00\x00"), "call $+5 (GetPC)"),
    (re.compile(rb"\xd9\xee\xd9\x74\x24\xf4"), "fldz / fnstenv (GetPC)"),
    (re.compile(rb"\x64\xa1\x30\x00\x00\x00|\x64\x8b..\x30\x00\x00\x00", re.S), "fs:[0x30] PEB access (API resolution)"),
    (re.compile(rb"\xc1[\xc8-\xcf]\x0d"), "ror reg, 13 (API name hashing)"),
    (re.compile(rb"(?i)kernel32|LoadLibrary|GetProcAddress|URLDownloadToFile|WinExec|VirtualAlloc"),
     "Windows API name"),
]


def indicators(payload: bytes) -> list[str]:
    return [label for pattern, label in PATTERNS if pattern.search(payload)]
