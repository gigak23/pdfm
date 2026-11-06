"""Indicators of compromise: URLs, domains, IPs, emails, UNC paths, launch targets.

Sources: action targets (URI, Launch, GoToR, SubmitForm, ...), every object
dictionary (catches raw-mode files and odd placements), and every version of
every script, including URLs the sandbox saw being built at runtime. Page text
is deliberately not scanned: a document that merely mentions a URL isn't an IOC.
Output is defanged (hxxp://evil[.]com) so reports can't be clicked by accident.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import pikepdf

from pdfm.context import AnalysisContext
from pdfm.js.extract import pdf_text
from pdfm.models import IOC, Finding, Severity
from pdfm.parser.document import PdfDocument

URL_RE = re.compile(r"(?i)\b(?:https?|ftp|file|smb)://[^\s<>\"'()\\\[\]{}|^`]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# The host must be dotted (domain or IP): only internet-reachable hosts can harvest NTLM hashes,
# and requiring the dot keeps LaTeX line breaks ("\\nCode\...") from looking like UNC paths.
UNC_RE = re.compile(r"\\\\(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?:@SSL)?(?:@\d+)?\\[^\s()<>\"']*")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TRAILING_PUNCT = ".,;:!?'\""
# Living-off-the-land binaries: Launch actions pointing here are how PDFs run commands.
LOLBINS = re.compile(r"(?i)\b(?:cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil|"
                     r"msiexec|schtasks|wmic|curl|bash|sh)(?:\.exe)?\b")
TARGET_ACTIONS = {"URI", "Launch", "GoToR", "GoToE", "SubmitForm", "ImportData"}


def defang(kind: str, value: str) -> str:
    if kind == "url":
        value = re.sub(r"(?i)^http", "hxxp", value)
        value = re.sub(r"(?i)^ftp", "fxp", value)
        scheme, sep, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        return f"{scheme}{sep}{host.replace('.', '[.]')}{slash}{path}"
    if kind in ("domain", "ip"):
        return value.replace(".", "[.]")
    if kind == "email":
        user, _, domain = value.partition("@")
        return f"{user}[@]{domain.replace('.', '[.]')}"
    if kind == "unc":
        host, sep, rest = value[2:].partition("\\")
        return "\\\\" + host.replace(".", "[.]") + sep + rest
    return value


class _Collector:
    def __init__(self) -> None:
        self.iocs: dict[tuple[str, str], IOC] = {}

    def add(self, kind: str, value: str, source: str) -> None:
        value = value.strip()
        if kind == "url":
            value = value.rstrip(TRAILING_PUNCT)
        if value and (kind, value.lower()) not in self.iocs:
            self.iocs[(kind, value.lower())] = IOC(kind, value, defang(kind, value), source)

    def scan_text(self, text: str, source: str, emails: bool = True) -> None:
        for url in URL_RE.findall(text):
            self.add_url(url, source)
        for unc in UNC_RE.findall(text):
            self.add_unc(unc, source)
        if emails:
            for email in EMAIL_RE.findall(text):
                self.add("email", email, source)

    def add_url(self, url: str, source: str) -> None:
        self.add("url", url, source)
        host = urlsplit(url.rstrip(TRAILING_PUNCT)).hostname
        if host:
            self.add("ip" if IP_RE.fullmatch(host) else "domain", host, source)

    def add_unc(self, unc: str, source: str) -> None:
        self.add("unc", unc, source)
        host = unc[2:].split("\\", 1)[0].split("@", 1)[0]
        self.add("ip" if IP_RE.fullmatch(host) else "domain", host, source)


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    col = _Collector()
    findings: list[Finding] = []

    for action in doc.actions:
        if action.type not in TARGET_ACTIONS:
            continue
        source = f"{action.type} action {action.ref}"
        targets = _action_targets(action.obj)
        launched = [t for t in targets if LOLBINS.search(t)] if action.type == "Launch" else []
        if launched:
            findings.append(Finding("LAUNCH_SYSTEM_TOOL", Severity.CRITICAL,
                                    "Launch action runs a system tool used to execute commands",
                                    object_ref=action.ref, evidence=max(launched, key=len)[:300]))
        for target in targets:
            if action.type == "URI" and re.match(r"(?i)\s*(javascript|data|vbscript):", target):
                findings.append(Finding("SCRIPT_URI", Severity.HIGH,
                                        "URI action uses a script or data scheme", object_ref=action.ref,
                                        evidence=target[:200]))
            col.scan_text(target, source)
            if action.type == "Launch" and not URL_RE.search(target) and not UNC_RE.search(target):
                col.add("path", target, source)

    for ref, head in doc.iter_heads():
        # PDF literal strings double their backslashes, so \\host\share is written \\\\host\\share.
        col.scan_text(head.decode("latin-1").replace("\\\\", "\\"), f"object {ref}")

    for text in ctx.script_texts:
        col.scan_text(text, "JavaScript")
        for ip in IP_RE.findall(text):
            if _routable(ip):
                col.add("ip", ip, "JavaScript")

    ctx.iocs += col.iocs.values()

    uncs = [i for i in col.iocs.values() if i.kind == "unc"]
    if uncs:
        findings.append(Finding(
            "UNC_PATH", Severity.HIGH,
            "UNC path to a remote share: opening it can leak the user's NTLM hash (e.g. CVE-2018-4993)",
            evidence="; ".join(i.defanged for i in uncs[:5]),
        ))
    ip_urls = [i for i in col.iocs.values() if i.kind == "url" and IP_RE.fullmatch(urlsplit(i.value).hostname or "")]
    if ip_urls:
        findings.append(Finding("IP_URL", Severity.MEDIUM, "URL points to a raw IP address instead of a domain",
                                evidence="; ".join(i.defanged for i in ip_urls[:5])))
    file_urls = [i for i in col.iocs.values() if i.kind == "url" and i.value.lower().startswith(("file:", "smb:"))]
    if file_urls:
        findings.append(Finding("FILE_URL", Severity.MEDIUM, "URL uses the file: or smb: scheme",
                                evidence="; ".join(i.defanged for i in file_urls[:5])))
    return findings


def _routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_reserved
                or addr.is_multicast or ip.startswith("0."))


def _action_targets(action: pikepdf.Dictionary) -> list[str]:
    """Strings an action points at: /URI, /F (string or file spec), /Win /F and /P, /URL."""
    out: list[str] = []

    def take(value) -> None:
        if isinstance(value, pikepdf.String):
            out.append(pdf_text(bytes(value)))
        elif isinstance(value, pikepdf.Dictionary):
            for key in ("/UF", "/F", "/DOS", "/Unix", "/Mac", "/P"):
                if key in value:
                    take(value[key])

    for key in ("/URI", "/F", "/Win", "/Unix", "/Mac", "/URL"):
        if key in action:
            take(action[key])
    if len(out) >= 2 and "/Win" in action:
        out.append(" ".join(out))  # program + parameters together, for the command-line check
    return out
