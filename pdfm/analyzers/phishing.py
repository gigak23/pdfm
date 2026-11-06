"""Phishing-lure detection.

Most malicious PDFs today carry no exploit at all: they're a page that looks
like an invoice or a booking confirmation, with a big "View document" button
(or a QR code) leading to a credential-harvesting site. Each signal here is weak
alone, since legitimate flyers have big buttons and legitimate docs have links,
so the strong finding (PHISHING_LURE) needs the lure layout AND a risky link.

Signals:
- risky link destinations (pdfm.urlrisk): free hosting, shorteners, cheap TLDs,
  brand names on domains the brand doesn't own, raw IPs
- lure layout: 1-2 pages, a few external links, a page that's mostly an image
  or a clickable area covering a large part of the page
- social-engineering pop-ups: an on-open script that only shows a message
  ("open this in your browser") next to an external link
- QR codes in page images that encode URLs (decoded with OpenCV, optional)
"""

from __future__ import annotations

import re
import warnings

import pikepdf

from pdfm import urlrisk
from pdfm.analyzers.iocs import defang
from pdfm.context import AnalysisContext
from pdfm.models import IOC, Finding, Severity
from pdfm.parser.document import PdfDocument

try:
    import cv2
    import numpy as np
except ImportError:  # optional dependency: pip install pdfm[qr]
    cv2 = None

# Only URLs a reader can actually be sent to; not every URL that appears in metadata.
ACTIONABLE_SOURCES = ("URI action", "SubmitForm action", "Launch action", "GoToR action", "JavaScript", "QR code")
LURE_MAX_PAGES = 2
LURE_MAX_LINKS = 5
MANY_LINKS = 20
BIG_LINK_FRACTION = 0.08  # clickable area covering 8%+ of the page is a "button", not an inline link
BIG_IMAGE_PIXELS = 100_000
FEW_TEXT_OPS = 25
TEXT_OP_RE = re.compile(rb"[)\]>]\s*(?:Tj|TJ|'|\")")
QR_MAX_PAGES = 5
QR_MAX_IMAGES = 30
QR_MAX_PIXELS = 4_000_000  # decoding goes through pikepdf without PDFM's cap, so keep images small
MESSAGE_ONLY_CALLS = {"app.alert", "app.beep", "app.launchURL", "this.getURL"}

URL_SIGNALS = {
    "brand_impersonation": ("BRAND_IMPERSONATION", Severity.HIGH, "Link uses a brand name on a domain the brand doesn't own"),
    "free_hosting": ("PHISHING_HOSTED_LINK", Severity.MEDIUM, "Link points to free hosting or file sharing favoured by phishing kits"),
    "shortener": ("URL_SHORTENER", Severity.LOW, "Link hides its destination behind a URL shortener"),
    "suspicious_tld": ("SUSPICIOUS_TLD", Severity.LOW, "Link uses a top-level domain popular with throwaway phishing sites"),
}


def analyze(doc: PdfDocument, ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []

    qr_hits = _qr_urls(doc) if doc.pdf is not None else []
    for page_no, text in qr_hits:
        source = f"QR code on page {page_no}"
        if re.match(r"(?i)https?://|www\.", text):
            url = text if "://" in text else "http://" + text
            ctx.iocs.append(IOC("url", url, defang("url", url), source))
    if qr_hits:
        findings.append(Finding(
            "QR_CODE_URL", Severity.MEDIUM, "Page image contains a QR code (quishing moves the link to the reader's phone)",
            evidence="; ".join(f"page {p}: {defang('url', t) if '://' in t else t}"[:200] for p, t in qr_hits[:5]),
        ))

    risky: dict[str, list[str]] = {}
    ip_link = False  # already reported as IP_URL by the IOC analyzer; only feeds the lure decision
    for ioc in ctx.iocs:
        if ioc.kind != "url" or not ioc.source.startswith(ACTIONABLE_SOURCES):
            continue
        for signal, detail in urlrisk.assess(ioc.value).signals.items():
            if signal in URL_SIGNALS:
                risky.setdefault(signal, []).append(f"{ioc.defanged} ({detail.replace('.', '[.]')})")
            ip_link |= signal == "ip_host"
    # A lure has a handful of links. In a book or manual with dozens of links, one blogspot or
    # bit.ly reference is ordinary, so link signals are downgraded and can't add up to a verdict.
    external_links = sum(1 for a in doc.actions if a.type in ("URI", "SubmitForm"))
    crowded = external_links > MANY_LINKS
    for signal, details in risky.items():
        finding_id, severity, description = URL_SIGNALS[signal]
        if crowded:
            severity = Severity.LOW if severity == Severity.HIGH else Severity.INFO
            description += f" (one of {external_links} links, so weighted down)"
        findings.append(Finding(finding_id, severity, description, evidence="; ".join(details[:5])))

    layout = _lure_layout(doc, has_qr=bool(qr_hits))
    if layout:
        findings.append(Finding("PHISHING_LURE_LAYOUT", Severity.MEDIUM,
                                "Short document built like a lure: a few external links on an image-heavy page",
                                evidence=layout))

    message = _lure_message(doc, ctx)
    if message:
        findings.append(Finding("JS_LURE_MESSAGE", Severity.MEDIUM,
                                "Script opens with a pop-up nudging the reader toward an external link",
                                evidence=message[:200]))

    if (layout or message) and (risky or qr_hits or ip_link):
        findings.append(Finding(
            "PHISHING_LURE", Severity.HIGH,
            "Lure-style document whose link leads somewhere a legitimate sender wouldn't use",
            evidence=", ".join(sorted(risky)) or "QR code",
        ))
    return findings


def _pages(doc: PdfDocument) -> list:
    try:
        return list(doc.pdf.pages)
    except (pikepdf.PdfError, TypeError, AttributeError):
        return []


def _lure_layout(doc: PdfDocument, has_qr: bool) -> str | None:
    if doc.pdf is None:
        return None
    pages = _pages(doc)
    if not 1 <= len(pages) <= LURE_MAX_PAGES:
        return None

    links, biggest_link, text_ops, big_images = 0, 0.0, 0, 0
    for page in pages:
        try:
            box = [float(v) for v in page.mediabox]
            page_area = abs((box[2] - box[0]) * (box[3] - box[1])) or 1.0
        except (TypeError, ValueError, IndexError, pikepdf.PdfError):
            page_area = 612 * 792
        for annot in _list(page.obj.get("/Annots")):
            if not isinstance(annot, pikepdf.Dictionary) or not _external_link(annot):
                continue
            links += 1
            try:
                x0, y0, x1, y1 = (float(v) for v in annot.Rect)
                biggest_link = max(biggest_link, abs((x1 - x0) * (y1 - y0)) / page_area)
            except (AttributeError, TypeError, ValueError, pikepdf.PdfError):
                pass
        text_ops += sum(len(TEXT_OP_RE.findall(data)) for data in _content_data(doc, page))
        big_images += sum(1 for _, img in _page_images(page) if _pixels(img) >= BIG_IMAGE_PIXELS)

    # Quishing lures often have no clickable link at all: the QR code is the link.
    if links > LURE_MAX_LINKS or (links == 0 and not has_qr):
        return None
    big_button = biggest_link >= BIG_LINK_FRACTION
    image_page = big_images > 0 and text_ops < FEW_TEXT_OPS
    if not (big_button or image_page):
        return None
    return (f"{len(pages)} page(s), {links} external link(s){' + QR code' if has_qr else ''}, "
            f"largest link covers {biggest_link:.0%} of the page, {big_images} large image(s), {text_ops} text operations")


def _external_link(annot: pikepdf.Dictionary) -> bool:
    action = annot.get("/A")
    return isinstance(action, pikepdf.Dictionary) and action.get("/S") in (pikepdf.Name.URI, pikepdf.Name.SubmitForm,
                                                                           pikepdf.Name.Launch)


def _lure_message(doc: PdfDocument, ctx: AnalysisContext) -> str | None:
    """An on-open script that does nothing but show a message, in a document with an external link."""
    external = any(a.type in ("URI", "SubmitForm") for a in doc.actions)
    for script in ctx.scripts:
        if not script.on_open or not script.api_calls:
            continue
        calls = [c.split("(", 1)[0] for c in script.api_calls]
        if not set(calls) <= MESSAGE_ONLY_CALLS or "app.alert" not in calls:
            continue
        if external or any(c in ("app.launchURL", "this.getURL") for c in calls):
            return next(c for c in script.api_calls if c.startswith("app.alert"))
    return None


def _list(value) -> list:
    return list(value) if isinstance(value, pikepdf.Array) else []


def _content_data(doc: PdfDocument, page) -> list[bytes]:
    contents = page.obj.get("/Contents")
    streams = _list(contents) if isinstance(contents, pikepdf.Array) else [contents]
    out = []
    for s in streams:
        if isinstance(s, pikepdf.Stream):
            decoded = doc.stream(*s.objgen)  # PDFM's capped decode
            if decoded is not None:
                out.append(decoded.data)
    return out


def _page_images(page):
    try:
        xobjects = page.obj.Resources.get("/XObject")
    except (AttributeError, pikepdf.PdfError):
        return []
    if not isinstance(xobjects, pikepdf.Dictionary):
        return []
    return [(name, x) for name, x in xobjects.items()
            if isinstance(x, pikepdf.Stream) and x.get("/Subtype") == pikepdf.Name.Image]


def _pixels(image: pikepdf.Stream) -> int:
    try:
        return int(image.Width) * int(image.Height)
    except (AttributeError, TypeError, ValueError, pikepdf.PdfError):
        return 0


def _qr_urls(doc: PdfDocument) -> list[tuple[int, str]]:
    if cv2 is None:
        return []
    detector = cv2.QRCodeDetector()
    hits, checked = [], 0
    for page_no, page in enumerate(_pages(doc)[:QR_MAX_PAGES], 1):
        for _, image in _page_images(page):
            if checked >= QR_MAX_IMAGES:
                return hits
            if not 400 <= _pixels(image) <= QR_MAX_PIXELS:
                continue
            checked += 1
            try:
                with warnings.catch_warnings():  # pikepdf warns about cosmetic issues (e.g. /Matte masks)
                    warnings.simplefilter("ignore")
                    gray = np.array(pikepdf.PdfImage(image).as_pil_image().convert("L"))
                ok, texts, _, _ = detector.detectAndDecodeMulti(gray)
            except Exception:  # unsupported codec or corrupt image data: skip, never fail the scan
                continue
            if ok:
                hits += [(page_no, t) for t in texts if t]
    return hits
