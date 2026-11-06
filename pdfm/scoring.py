"""Turn findings into a score and a verdict.

Deliberately simple and explainable: each kind of finding adds points once, by
its highest severity, and two thresholds split benign / suspicious / malicious.
Any CRITICAL finding (e.g. a Launch action on open, a known exploit API) is
enough for "malicious" on its own. Every point traces back to a finding.

Tuned on 392 benign real-world PDFs: vendor manuals legitimately run JavaScript
on open, so that alone reaches "suspicious" but never "malicious".
"""

from __future__ import annotations

from pdfm.models import Finding, Severity, Verdict

WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}
SUSPICIOUS_AT = 4
MALICIOUS_AT = 15

EXIT_CODES = {Verdict.BENIGN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


def score(findings: list[Finding]) -> int:
    # Count each finding type once, so 175 copies of one benign pattern can't add up to "malicious".
    worst: dict[str, int] = {}
    for f in findings:
        worst[f.id] = max(worst.get(f.id, 0), WEIGHTS[f.severity])
    return sum(worst.values())


def verdict(points: int, findings: list[Finding] = ()) -> Verdict:
    if points >= MALICIOUS_AT or any(f.severity == Severity.CRITICAL for f in findings):
        return Verdict.MALICIOUS
    if points >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN
