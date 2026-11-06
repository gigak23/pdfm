"""pdfid-style keyword triage, attributed to the objects that contain each keyword.

Unlike pdfid, which counts names across the raw bytes, this scans each object's
dictionary (including objects packed inside compressed object streams) and skips
stream data, so text inside page content can't trigger a hit.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from pdfm.models import Finding, Severity
from pdfm.parser.document import PdfDocument
from pdfm.parser.raw import NAME_TOKEN_RE, decode_name


@dataclass(frozen=True)
class Rule:
    id: str
    names: frozenset[str]
    severity: Severity
    description: str


RULES = [
    Rule("JAVASCRIPT", frozenset({"JS", "JavaScript"}), Severity.HIGH, "Document contains JavaScript"),
    Rule("OPEN_ACTION", frozenset({"OpenAction"}), Severity.LOW,
         "Document defines an action to run when opened"),
    Rule("ADDITIONAL_ACTIONS", frozenset({"AA"}), Severity.LOW,
         "Actions bound to events (page open, field focus, close, print, ...)"),
    Rule("LAUNCH_ACTION", frozenset({"Launch"}), Severity.HIGH, "Launch action can start external programs"),
    # LOW: invoices (ZUGFeRD XML) and portfolios embed files legitimately; the embedded-file
    # analyzer raises the severity when the payload type is dangerous.
    Rule("EMBEDDED_FILE", frozenset({"EmbeddedFile", "EmbeddedFiles"}), Severity.LOW,
         "Document carries embedded files"),
    Rule("URI_ACTION", frozenset({"URI"}), Severity.INFO, "Document links to external URLs"),
    Rule("SUBMIT_FORM", frozenset({"SubmitForm"}), Severity.MEDIUM, "Form data can be sent to a remote server"),
    Rule("IMPORT_DATA", frozenset({"ImportData"}), Severity.MEDIUM, "Action imports data from another file"),
    # LOW: datasheets cross-link with GoToR all the time; UNC targets (NTLM leaks) are flagged separately.
    Rule("REMOTE_GOTO", frozenset({"GoToR", "GoToE"}), Severity.LOW,
         "Action opens another (possibly remote or embedded) document"),
    Rule("RICH_MEDIA", frozenset({"RichMedia"}), Severity.MEDIUM, "Embedded Flash/rich media"),
    Rule("XFA_FORM", frozenset({"XFA"}), Severity.MEDIUM, "XFA form (XML forms can carry scripts)"),
    Rule("ACROFORM", frozenset({"AcroForm"}), Severity.INFO, "Interactive form"),
    Rule("JBIG2", frozenset({"JBIG2Decode"}), Severity.LOW,
         "JBIG2-compressed images (decoder exploited by FORCEDENTRY and others)"),
    Rule("ENCRYPTED", frozenset({"Encrypt"}), Severity.LOW, "Document is encrypted"),
]
NAME_TO_RULE = {name: rule for rule in RULES for name in rule.names}

# Counted for the pdfid-style summary even though they don't produce findings.
EXTRA_COUNTED = {"Page", "ObjStm"}


def count_keywords(doc: PdfDocument) -> tuple[Counter, dict[str, list[str]], list[str]]:
    """Returns (count per name, refs per rule id, obfuscated-name evidence)."""
    counts: Counter = Counter()
    refs: dict[str, list[str]] = defaultdict(list)
    obfuscated: list[str] = []
    for ref, head in doc.iter_heads():
        for m in NAME_TOKEN_RE.finditer(head):
            raw_name = m[1]
            name = decode_name(raw_name)
            rule = NAME_TO_RULE.get(name)
            if rule is None and name not in EXTRA_COUNTED:
                continue
            counts[name] += 1
            if rule is not None and ref not in refs[rule.id]:
                refs[rule.id].append(ref)
            if b"#" in raw_name and rule is not None:
                # Writers have no reason to hex-escape plain letters in these names; it only
                # serves to dodge naive string matching (e.g. /J#61vaScript).
                obfuscated.append(f"/{raw_name.decode('latin-1')} = /{name} in {ref}")
    return counts, refs, obfuscated


def analyze(doc: PdfDocument) -> list[Finding]:
    counts, refs, obfuscated = count_keywords(doc)
    findings = []
    for rule in RULES:
        if rule.id not in refs:
            continue
        total = sum(counts[n] for n in rule.names)
        findings.append(Finding(
            rule.id, rule.severity, f"{rule.description} ({total} occurrence(s))",
            object_ref=refs[rule.id][0], evidence=", ".join(refs[rule.id][:10]),
        ))
    if obfuscated:
        findings.append(Finding(
            "OBFUSCATED_NAME", Severity.HIGH,
            f"{len(obfuscated)} suspicious name(s) hidden with #xx hex escapes",
            evidence="; ".join(obfuscated[:10]),
        ))
    return findings
