"""Run YARA rules over the raw file, decoded streams, and every JavaScript variant.

Scanning decoded data matters: a rule written for plain text never matches a
Flate-compressed or hex-encoded stream in the raw bytes. Images and font
programs are skipped because their binary data causes false positives (a
flat-gray image is a long run of 0x90 bytes, which looks like a NOP sled).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pdfm.context import AnalysisContext
from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument

try:
    import yara
except ImportError:  # optional dependency: pip install pdfm[yara]
    yara = None

BUNDLED_RULES = Path(__file__).resolve().parent.parent / "rules"
MATCH_TIMEOUT = 10  # seconds per target
SEVERITIES = {s.value: s for s in Severity}


def available() -> bool:
    return yara is not None


def rule_files(extra_dir: Path | None) -> list[Path]:
    files = sorted(BUNDLED_RULES.glob("*.yar"))
    if extra_dir is not None:
        files += sorted(p for p in Path(extra_dir).rglob("*") if p.suffix.lower() in (".yar", ".yara"))
    return files


@lru_cache(maxsize=8)
def _compile(paths: tuple[str, ...]):
    # Namespaces keep identically named rules in different user files from colliding.
    return yara.compile(filepaths={f"ns{i}": p for i, p in enumerate(paths)})


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    if yara is None:
        if ctx.options.rules_dir is not None:
            return [Finding("YARA_UNAVAILABLE", Severity.INFO,
                            "Custom YARA rules given but yara-python is not installed (pip install pdfm[yara])")]
        return []
    try:
        rules = _compile(tuple(str(p) for p in rule_files(ctx.options.rules_dir)))
    except yara.Error as exc:
        return [Finding("YARA_RULE_ERROR", Severity.INFO, "YARA rules failed to compile", evidence=str(exc))]

    targets: list[tuple[str, bytes]] = [("file", doc.data)]
    for s in doc.streams:
        if s.data and s.info.subtype != "Image" and not s.info.font_program:
            targets.append((s.ref, s.data))
    for text in dict.fromkeys(ctx.script_texts):  # de-duplicated, order kept
        targets.append(("JavaScript", text.encode("utf-8", "surrogatepass")))

    hits: dict[str, tuple[object, list[str]]] = {}
    for where, data in targets:
        try:
            matches = rules.match(data=data, timeout=MATCH_TIMEOUT)
        except yara.TimeoutError:
            continue
        for match in matches:
            _, places = hits.setdefault(match.rule, (match, []))
            if where not in places:
                places.append(where)

    findings = []
    for name, (match, places) in hits.items():
        meta = match.meta
        severity = SEVERITIES.get(str(meta.get("severity", "medium")).lower(), Severity.MEDIUM)
        object_ref = next((p for p in places if p.endswith(" R")), None)
        findings.append(Finding(
            f"YARA_{name.upper()}", severity, str(meta.get("description", f"YARA rule {name} matched")),
            object_ref=object_ref, evidence="matched in: " + ", ".join(places[:10]),
        ))
    return findings
