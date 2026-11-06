"""Make sample-derived bytes safe to print.

Raw stream data can contain terminal escape sequences (ESC [ ...) that recolor,
hide, or rewrite what the analyst sees. Everything except newlines and tabs that
isn't printable is replaced.
"""

from __future__ import annotations

import re

_UNSAFE = re.compile(r"[^\x20-\x7e\n\t]")


def printable(data: bytes | str, limit: int | None = None) -> str:
    text = data.decode("latin-1") if isinstance(data, bytes) else data
    if limit is not None and len(text) > limit:
        text = text[:limit] + f"\n... [{len(text) - limit:,} more characters]"
    return _UNSAFE.sub(".", text)
