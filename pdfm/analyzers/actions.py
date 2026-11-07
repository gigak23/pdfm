"""Findings about what runs automatically when the document opens, and where Launch actions lead."""

from __future__ import annotations

import re
from collections import defaultdict

import pikepdf

from pdfm.analyzers.embedded import DANGEROUS_EXTENSIONS
from pdfm.analyzers.iocs import LOLBINS, action_targets
from pdfm.context import AnalysisContext
from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument

# JavaScript on open is HIGH, not CRITICAL: vendor manuals (ST, ARM, ...) ship document-level
# scripts. Malicious intent is judged from what the script does (javascript analyzer).
ON_OPEN_RULES = {
    "JavaScript": ("AUTO_RUN_JAVASCRIPT", Severity.HIGH, "JavaScript runs automatically when the file opens"),
    "URI": ("AUTO_OPEN_URL", Severity.MEDIUM, "A URL is opened automatically when the file opens"),
    "SubmitForm": ("AUTO_SUBMIT_FORM", Severity.MEDIUM, "Form data is submitted automatically on open"),
    "GoToR": ("AUTO_REMOTE_GOTO", Severity.MEDIUM, "Another document is opened automatically on open"),
    "GoToE": ("AUTO_REMOTE_GOTO", Severity.MEDIUM, "An embedded document is opened automatically on open"),
    "ImportData": ("AUTO_IMPORT_DATA", Severity.MEDIUM, "External data is imported automatically on open"),
}
# Older documents (e.g. government reports) use Launch to open sibling documents and slides.
DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "html", "htm", "txt", "rtf", "xml", "csv",
    "jpg", "jpeg", "png", "gif", "tif", "tiff", "mp3", "wav", "avi", "mpg", "mpeg", "wmv", "odt", "ods",
}


def launch_kind(targets: list[str]) -> str:
    """'program' (executable, script or shell), 'document', or 'unknown'."""
    if any(LOLBINS.search(t) for t in targets):
        return "program"
    exts = []
    for t in targets:
        name = re.split(r"[\\/]", t.split("#", 1)[0].split("?", 1)[0].strip())[-1]
        exts.append(name.rsplit(".", 1)[-1].lower() if "." in name else "")
    if any(e in DANGEROUS_EXTENSIONS and e not in DOCUMENT_EXTENSIONS for e in exts):
        return "program"
    if exts and all(e in DOCUMENT_EXTENSIONS for e in exts):
        return "document"
    return "unknown"


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    hits: dict[str, list] = defaultdict(list)
    findings = []
    for action in doc.actions:
        if action.type == "Launch":
            findings += _launch_findings(action)
        elif action.on_open and action.type in ON_OPEN_RULES and not _empty_script(action):
            hits[ON_OPEN_RULES[action.type][0]].append(action)

    rules = {rule[0]: rule for rule in ON_OPEN_RULES.values()}
    for finding_id, actions in hits.items():
        _, severity, description = rules[finding_id]
        if len(actions) > 1:
            description += f" ({len(actions)} actions)"
        findings.append(Finding(
            finding_id, severity, description, object_ref=actions[0].ref,
            evidence="; ".join(f"{a.trigger} ({a.ref})" for a in actions[:5]),
        ))
    return findings


def _launch_findings(action) -> list[Finding]:
    targets = action_targets(action.obj)
    kind = launch_kind(targets)
    evidence = f"trigger: {action.trigger}; target: {targets[0][:200] if targets else '(none)'}"
    if action.on_open:
        severity, what = {
            "program": (Severity.CRITICAL, "starts a program"),
            "unknown": (Severity.HIGH, "opens an unidentified target"),
            "document": (Severity.MEDIUM, "opens another document"),
        }[kind]
        return [Finding("AUTO_LAUNCH", severity, f"A Launch action {what} when the file opens",
                        object_ref=action.ref, evidence=evidence)]
    if kind == "program":
        return [Finding("LAUNCH_EXECUTABLE", Severity.HIGH, "A Launch action starts a program or script",
                        object_ref=action.ref, evidence=evidence)]
    return []


def _empty_script(action) -> bool:
    """Document-level scripts with an empty /JS string are common in publisher PDFs and do nothing."""
    js = action.obj.get("/JS")
    return action.type == "JavaScript" and isinstance(js, pikepdf.String) and not bytes(js).strip()
