"""Findings about what runs automatically when the document opens."""

from __future__ import annotations

from collections import defaultdict

from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument

# JavaScript on open is HIGH, not CRITICAL: vendor manuals (ST, ARM, ...) ship document-level
# scripts. Malicious intent is judged from what the script does (javascript analyzer).
ON_OPEN_RULES = {
    "JavaScript": ("AUTO_RUN_JAVASCRIPT", Severity.HIGH, "JavaScript runs automatically when the file opens"),
    "Launch": ("AUTO_LAUNCH", Severity.CRITICAL, "A Launch action (external program) fires when the file opens"),
    "URI": ("AUTO_OPEN_URL", Severity.MEDIUM, "A URL is opened automatically when the file opens"),
    "SubmitForm": ("AUTO_SUBMIT_FORM", Severity.MEDIUM, "Form data is submitted automatically on open"),
    "GoToR": ("AUTO_REMOTE_GOTO", Severity.MEDIUM, "Another document is opened automatically on open"),
    "GoToE": ("AUTO_REMOTE_GOTO", Severity.MEDIUM, "An embedded document is opened automatically on open"),
    "ImportData": ("AUTO_IMPORT_DATA", Severity.MEDIUM, "External data is imported automatically on open"),
}


def analyze(doc: PdfDocument) -> list[Finding]:
    hits: dict[str, list] = defaultdict(list)
    for action in doc.actions:
        if action.on_open and action.type in ON_OPEN_RULES:
            hits[ON_OPEN_RULES[action.type][0]].append(action)

    findings = []
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
