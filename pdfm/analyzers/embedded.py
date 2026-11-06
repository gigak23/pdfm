"""Embedded files: identify by content, hash, optionally extract, and scan nested PDFs.

File names inside a PDF are attacker-controlled, so the type comes from the
bytes and extracted files are written as <sha256>.bin: never under their
original name, which could be "invoice.pdf.exe" or contain "../" path tricks.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass

import pikepdf

from pdfm.context import AnalysisContext
from pdfm.js.extract import pdf_text
from pdfm.models import EmbeddedFileInfo, Finding, Severity, Verdict
from pdfm.parser.document import PdfDocument

DANGEROUS_EXTENSIONS = {
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "lnk", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "apk", "iso", "img", "vhd", "vhdx", "reg", "docm", "xlsm", "pptm",
    "dotm", "xlam", "sh", "app", "dmg", "elf", "bin", "url", "scf", "library-ms", "chm", "one",
}
# EICAR is assembled at runtime so antivirus doesn't quarantine this source file.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
NESTED_VERDICT_SEVERITY = {Verdict.MALICIOUS: Severity.HIGH, Verdict.SUSPICIOUS: Severity.MEDIUM}


@dataclass
class Identified:
    kind: str
    severity: Severity | None  # None: nothing alarming about the content itself
    finding_id: str | None = None


def identify(data: bytes) -> Identified:
    if EICAR in data[:256]:
        return Identified("EICAR antivirus test file", Severity.HIGH, "EICAR_TEST_FILE")
    if data.startswith(b"MZ"):
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little") if len(data) >= 0x40 else 0
        is_pe = data[e_lfanew:e_lfanew + 4] == b"PE\0\0"
        return Identified("Windows PE executable" if is_pe else "DOS/MZ executable",
                          Severity.CRITICAL, "EMBEDDED_EXECUTABLE")
    if data.startswith(b"\x7fELF"):
        return Identified("ELF executable", Severity.CRITICAL, "EMBEDDED_EXECUTABLE")
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return Identified("Mach-O executable", Severity.CRITICAL, "EMBEDDED_EXECUTABLE")
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return Identified("Windows shortcut (LNK)", Severity.CRITICAL, "EMBEDDED_EXECUTABLE")
    if b"%PDF-" in data[:1024]:
        return Identified("PDF document", None)
    if data.startswith(b"PK\x03\x04"):
        return _identify_zip(data)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data:
            return Identified("OLE2 Office document with VBA macros", Severity.HIGH, "EMBEDDED_MACRO_DOCUMENT")
        return Identified("OLE2 Office document", Severity.LOW, "EMBEDDED_OFFICE_DOCUMENT")
    if data.startswith(b"{\\rt"):
        return Identified("RTF document", Severity.MEDIUM, "EMBEDDED_RTF")
    head = data[:512].lstrip().lower()
    if head.startswith((b"<html", b"<!doctype html", b"<hta:")) or b"<script" in head:
        return Identified("HTML / HTA", Severity.MEDIUM, "EMBEDDED_HTML")
    if head.startswith(b"#!"):
        return Identified("script (shebang)", Severity.MEDIUM, "EMBEDDED_SCRIPT")
    if data[:3] in (b"Rar", b"7z\xbc") or data.startswith(b"\x1f\x8b"):
        return Identified("archive (RAR/7z/gzip)", Severity.LOW, "EMBEDDED_ARCHIVE")
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:4096])
    if data and printable / min(len(data), 4096) > 0.95:
        return Identified("text", None)
    return Identified("unknown binary", None)


def _identify_zip(data: bytes) -> Identified:
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()  # reads the directory only, never decompresses
    except (zipfile.BadZipFile, ValueError, EOFError):
        return Identified("ZIP archive (unreadable)", Severity.LOW, "EMBEDDED_ARCHIVE")
    lower = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lower):
        return Identified("Office document with VBA macros", Severity.HIGH, "EMBEDDED_MACRO_DOCUMENT")
    if "androidmanifest.xml" in lower:
        return Identified("Android APK", Severity.HIGH, "EMBEDDED_EXECUTABLE")
    if "meta-inf/manifest.mf" in lower or any(n.endswith(".class") for n in lower):
        return Identified("Java JAR", Severity.HIGH, "EMBEDDED_EXECUTABLE")
    if "[content_types].xml" in lower:
        kind = next((k for prefix, k in (("word/", "DOCX"), ("xl/", "XLSX"), ("ppt/", "PPTX"))
                     if any(n.startswith(prefix) for n in lower)), "OOXML")
        return Identified(f"Office document ({kind})", None)
    risky = [n for n in names if n.rsplit(".", 1)[-1].lower() in DANGEROUS_EXTENSIONS]
    if risky:
        return Identified(f"ZIP archive containing {', '.join(risky[:3])}", Severity.HIGH, "EMBEDDED_ARCHIVE_RISKY")
    return Identified(f"ZIP archive ({len(names)} files)", Severity.LOW, "EMBEDDED_ARCHIVE")


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for name, stream in _embedded_streams(doc):
        data = stream.data
        ident = identify(data)
        info = EmbeddedFileInfo(
            ref=stream.ref, name=name, size=len(data),
            md5=hashlib.md5(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(), kind=ident.kind,
        )
        label = f"embedded file {name!r}" if name else f"embedded file in {stream.ref}"

        if ident.finding_id:
            findings.append(Finding(ident.finding_id, ident.severity, f"{label} is a {ident.kind}",
                                    object_ref=stream.ref, evidence=f"sha256 {info.sha256}"))
        findings += _name_findings(name, ident, stream.ref)
        if stream.info.truncated:
            findings.append(Finding("EMBEDDED_TRUNCATED", Severity.MEDIUM,
                                    f"{label} exceeds the decode limit; analyzed only the first part",
                                    object_ref=stream.ref))

        if ctx.options.extract_dir is not None:
            ctx.options.extract_dir.mkdir(parents=True, exist_ok=True)
            target = ctx.options.extract_dir / f"{info.sha256}.bin"
            target.write_bytes(data)
            info.extracted_to = str(target)

        if ident.kind == "PDF document":
            findings += _scan_nested(data, label, info, stream.ref, ctx)
        ctx.embedded.append(info)
    return findings


def _name_findings(name: str | None, ident: Identified, ref: str) -> list[Finding]:
    if not name:
        return []
    parts = name.lower().rsplit(".", 2)
    findings = []
    if len(parts) >= 2 and parts[-1] in DANGEROUS_EXTENSIONS and ident.severity != Severity.CRITICAL:
        findings.append(Finding("EMBEDDED_DANGEROUS_NAME", Severity.HIGH,
                                f"Embedded file name {name!r} has a dangerous extension", object_ref=ref))
    if len(parts) == 3 and len(parts[1]) <= 4 and parts[-1] in DANGEROUS_EXTENSIONS:
        findings.append(Finding("DOUBLE_EXTENSION", Severity.HIGH,
                                f"Embedded file name {name!r} hides its real extension", object_ref=ref))
    if re.search(r"[\\/]|\.\.|[‮‏]", name):
        findings.append(Finding("EMBEDDED_NAME_TRICK", Severity.MEDIUM,
                                f"Embedded file name {name!r} contains path or direction-override characters",
                                object_ref=ref))
    return findings


def _scan_nested(data: bytes, label: str, info: EmbeddedFileInfo, ref: str, ctx: AnalysisContext) -> list[Finding]:
    if ctx.depth + 1 > ctx.options.max_depth:
        return [Finding("NESTING_TOO_DEEP", Severity.MEDIUM,
                        f"{label} is a PDF nested beyond depth {ctx.options.max_depth}; not scanned", object_ref=ref)]
    from pdfm import scanner  # imported here: scanner imports this module

    child = scanner.scan_bytes(data, label, ctx.options, depth=ctx.depth + 1)
    info.nested_verdict = child.verdict.value
    lifted = [Finding(f.id, f.severity, f"[{label}] {f.description}",
                      object_ref=f"{ref} > {f.object_ref}" if f.object_ref else ref, evidence=f.evidence)
              for f in child.findings]
    ctx.scripts += child.scripts
    ctx.embedded += child.embedded
    ctx.iocs += child.iocs
    if child.verdict in NESTED_VERDICT_SEVERITY:
        lifted.append(Finding("NESTED_PDF", NESTED_VERDICT_SEVERITY[child.verdict],
                              f"{label} is itself a {child.verdict.value} PDF (score {child.score})", object_ref=ref))
    return lifted


def _embedded_streams(doc: PdfDocument):
    """(file name or None, decoded stream) for every embedded file."""
    named: dict[str, str | None] = {}
    if doc.pdf is not None:
        for obj in doc.pdf.objects:
            if not isinstance(obj, pikepdf.Dictionary) or "/EF" not in obj:
                continue
            ef = obj.EF
            if not isinstance(ef, pikepdf.Dictionary):
                continue
            name = _filespec_name(obj)
            for key in ("/UF", "/F"):
                target = ef.get(key)
                if isinstance(target, pikepdf.Stream):
                    num, gen = target.objgen
                    named.setdefault(f"{num} {gen} R", name)
    for s in doc.streams:
        if s.ref in named or s.info.dict_type == "EmbeddedFile":
            yield named.get(s.ref), s


def _filespec_name(spec: pikepdf.Dictionary) -> str | None:
    for key in ("/UF", "/F", "/DOS", "/Unix", "/Mac"):
        value = spec.get(key)
        if isinstance(value, pikepdf.String):
            return pdf_text(bytes(value))
    return None
