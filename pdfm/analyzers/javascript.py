"""Extract, deobfuscate and emulate JavaScript, then look for exploit behaviour.

Indicators are matched against three views of each script: the original, the
statically deobfuscated version, and what the sandbox observed (API calls and
code passed to eval). Payload bytes from unescape() go to the shellcode check.
"""

from __future__ import annotations

import hashlib
import re

import pikepdf

from pdfm.context import AnalysisContext
from pdfm.js import sandbox, shellcode
from pdfm.js.deobfuscate import deobfuscate
from pdfm.js.extract import extract, pdf_text
from pdfm.models import Finding, ScriptInfo, Severity
from pdfm.parser.document import PdfDocument

PREVIEW_CHARS = 20_000

# (finding id, pattern, severity, description). Exploit APIs are CRITICAL: there is no
# legitimate reason for a document to call them in these ways.
INDICATORS = [
    ("CVE_2009_0927_COLLAB_GETICON", r"Collab\s*\.\s*getIcon", Severity.CRITICAL,
     "Collab.getIcon, the CVE-2009-0927 stack overflow"),
    ("CVE_2008_2992_UTIL_PRINTF", r"util\s*\.\s*printf\s*\(\s*[\"']%\d{3,}", Severity.CRITICAL,
     "util.printf with a huge field width, the CVE-2008-2992 overflow"),
    ("CVE_2007_5659_COLLECT_EMAIL_INFO", r"Collab\s*\.\s*collectEmailInfo", Severity.CRITICAL,
     "Collab.collectEmailInfo, the CVE-2007-5659 overflow"),
    ("CVE_2009_4324_MEDIA_NEWPLAYER", r"media\s*\.\s*newPlayer", Severity.CRITICAL,
     "media.newPlayer, the CVE-2009-4324 use-after-free"),
    ("CVE_2009_1493_CUSTOM_DICTIONARY", r"spell\s*\.\s*customDictionaryOpen", Severity.CRITICAL,
     "spell.customDictionaryOpen, the CVE-2009-1493 overflow"),
    ("JS_GET_ANNOTS", r"getAnnots\s*\(", Severity.MEDIUM,
     "getAnnots (CVE-2009-1492; also used to read payloads hidden in annotations)"),
    ("JS_HEAP_SPRAY", r"%u0[cC]0[cC]%u0[cC]0[cC]|%u0[aA]0[aA]%u0[aA]0[aA]|%u9090%u9090"
                      r"|\\x0[cC]\\x0[cC]\\x0[cC]\\x0[cC]|\\x90\\x90\\x90\\x90", Severity.CRITICAL,
     "Heap-spray filler pattern"),
    ("JS_SPRAY_LOOP", r"while\s*\(\s*[\w.$]+\.length\s*<\s*(?:0[xX][0-9a-fA-F]{4,}|\d{5,})", Severity.HIGH,
     "Loop that grows a string to a huge size (heap spray)"),
    ("JS_EVAL", r"\beval\s*\(|\bnew\s+Function\s*\(", Severity.MEDIUM, "Dynamic code execution (eval / Function)"),
    ("JS_EXPORT_AND_LAUNCH", r"exportDataObject\s*\([^)]*nLaunch\s*:\s*[12]", Severity.CRITICAL,
     "Embedded file is extracted and launched"),
    ("JS_EXPORT_DATA", r"exportDataObject\s*\(", Severity.HIGH, "Script extracts an embedded file"),
    # LOW: links in vendor PDFs routinely open URLs from script; the URLs land in the IOC list.
    ("JS_NETWORK", r"launchURL\s*\(|getURL\s*\(|submitForm\s*\(|SOAP\s*\.|Net\s*\.\s*HTTP", Severity.LOW,
     "Script contacts a URL"),
]
COMPILED = [(fid, re.compile(p), sev, desc) for fid, p, sev, desc in INDICATORS]


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    scripts = extract(doc)
    if not scripts:
        return []

    runs: list[sandbox.ScriptRun | None] = [None] * len(scripts)
    status = "disabled"
    if ctx.options.sandbox:
        if sandbox.available():
            runs = sandbox.run_scripts([s.code for s in scripts], _doc_info(doc))
            runs += [None] * (len(scripts) - len(runs))  # scripts skipped after a memory blowup
        else:
            status = "unavailable (pip install pdfm[sandbox])"

    findings: list[Finding] = []
    hits: dict[str, list[str]] = {}
    for script, run in zip(scripts, runs):
        deob = deobfuscate(script.code)
        views = [script.code, deob.code]
        payloads = list(deob.payloads)
        if run is not None:
            views += run.calls
            for code in run.evals:  # code built at runtime gets the same static treatment
                inner = deobfuscate(code)
                views += [code, inner.code]
                payloads += inner.payloads
            payloads += run.payloads
        ctx.script_texts += views

        for fid, pattern, _, _ in COMPILED:
            if any(pattern.search(v) for v in views):
                hits.setdefault(fid, []).append(script.ref)

        if deob.obfuscated:
            findings.append(Finding(
                "JS_OBFUSCATED", Severity.HIGH, "JavaScript is obfuscated",
                object_ref=script.ref, evidence=", ".join(f"{t} x{n}" for t, n in deob.techniques.most_common()),
            ))
        for payload in payloads:
            signs = shellcode.indicators(payload)
            if signs:
                findings.append(Finding(
                    "SHELLCODE", Severity.CRITICAL,
                    f"Binary payload built by JavaScript looks like shellcode ({len(payload):,} bytes)",
                    object_ref=script.ref, evidence="; ".join(signs),
                ))
                break
        if run is not None and run.status in ("timeout", "memory limit"):
            findings.append(Finding(
                "SANDBOX_RESOURCE_LIMIT", Severity.HIGH,
                f"Script hit the sandbox {run.status} (typical of heap sprays and anti-analysis loops)",
                object_ref=script.ref,
            ))

        ctx.scripts.append(ScriptInfo(
            ref=script.ref,
            trigger=script.trigger,
            on_open=script.on_open,
            size=len(script.code),
            sha256=hashlib.sha256(script.code.encode("utf-8", "surrogatepass")).hexdigest(),
            techniques=[t for t, _ in deob.techniques.most_common()],
            deobfuscated=deob.code[:PREVIEW_CHARS],
            sandbox=run.status if run is not None else status,
            api_calls=run.calls[:100] if run is not None else [],
        ))

    for fid, pattern, severity, description in COMPILED:
        if fid in hits:
            refs = sorted(set(hits[fid]))
            findings.append(Finding(fid, severity, description, object_ref=refs[0], evidence=", ".join(refs[:10])))
    return findings


def _doc_info(doc: PdfDocument) -> dict[str, str]:
    """Document metadata exposed as this.info: a classic hiding spot for payload strings."""
    info: dict[str, str] = {}
    try:
        for key, value in doc.pdf.docinfo.items():
            if isinstance(value, pikepdf.String):
                text = pdf_text(bytes(value))
                info[key.lstrip("/")] = text
                info[key.lstrip("/").lower()] = text
    except (pikepdf.PdfError, AttributeError):
        pass
    return info
