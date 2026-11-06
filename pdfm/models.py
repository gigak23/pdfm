"""Core data types shared by the parser, analyzers and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class Finding:
    """One observation produced by the parser or an analyzer.

    Every analyzer returns list[Finding]. Scoring and reporting only consume
    findings, so analyzers never depend on each other.
    """

    id: str
    severity: Severity
    description: str
    object_ref: str | None = None  # e.g. "12 0 R"
    evidence: str | None = None


@dataclass
class PdfObject:
    """Summary of one indirect object in the file."""

    num: int
    gen: int
    type: str  # /Type value if present (e.g. "Page"), else the object kind ("dict", "stream", ...)
    is_stream: bool
    in_objstm: bool = False  # stored compressed inside an /ObjStm rather than at a file offset
    offset: int | None = None  # byte offset of "N G obj" in the file, if found

    @property
    def ref(self) -> str:
        return f"{self.num} {self.gen} R"


@dataclass
class StreamInfo:
    """Metadata about one decoded stream (the decoded bytes live in parser.streams)."""

    num: int
    gen: int
    raw_size: int
    filters: list[str] = field(default_factory=list)
    dict_type: str | None = None
    subtype: str | None = None
    objstm_first: int | None = None
    objstm_count: int | None = None
    font_program: bool = False  # embedded font (Type 1 fonts are eexec-encrypted, so look random)
    image_bound: int | None = None  # max plausible decoded size of an image, from /Width x /Height
    decoded_size: int = 0
    partial: bool = False  # deliberately decoded only a sample (large images)
    complete: bool = False  # every filter in the chain was decoded
    truncated: bool = False  # decoding stopped at the output cap
    stopped_at: str | None = None  # first filter not decoded (image codec, Crypt, unknown)
    error: str | None = None
    entropy: float = 0.0

    @property
    def ref(self) -> str:
        return f"{self.num} {self.gen} R"


@dataclass
class ActionInfo:
    trigger: str  # e.g. "OpenAction", "Page 1 /AA page open", "Link annotation on page 2"
    type: str  # /S value: JavaScript, URI, Launch, SubmitForm, ...
    ref: str
    on_open: bool  # runs without user interaction when the file is opened


@dataclass
class ScriptInfo:
    ref: str
    trigger: str  # what runs it: "OpenAction", "form field x", "XFA", "unreferenced", ...
    on_open: bool
    size: int
    sha256: str
    techniques: list[str] = field(default_factory=list)  # obfuscation undone by the deobfuscator
    deobfuscated: str = ""  # readable version (truncated for the report)
    sandbox: str = "not run"  # "ok", "error: ...", "timeout", "memory limit", "unavailable", "disabled"
    api_calls: list[str] = field(default_factory=list)  # e.g. "app.alert('hi')" observed in the sandbox


@dataclass
class EmbeddedFileInfo:
    ref: str
    name: str | None  # filename from the file specification (attacker-controlled!)
    size: int
    md5: str
    sha1: str
    sha256: str
    kind: str  # detected from content, not from the name
    extracted_to: str | None = None
    nested_verdict: str | None = None  # for embedded PDFs scanned recursively


@dataclass
class IOC:
    kind: str  # url, domain, ip, email, unc
    value: str
    defanged: str
    source: str  # where it was found, e.g. "URI action 12 0 R" or "JavaScript (sandbox)"


@dataclass
class ScanResult:
    path: str
    size: int
    md5: str
    sha256: str
    pdf_version: str | None
    parse_mode: str  # "pikepdf" or "raw"
    revisions: int
    verdict: Verdict = Verdict.BENIGN
    score: int = 0
    keywords: dict[str, int] = field(default_factory=dict)  # pdfid-style counts
    actions: list[ActionInfo] = field(default_factory=list)
    scripts: list[ScriptInfo] = field(default_factory=list)
    embedded: list[EmbeddedFileInfo] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    objects: list[PdfObject] = field(default_factory=list)
    streams: list[StreamInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
