"""Offline URL risk heuristics for phishing links.

No lookups: everything here works in an air-gapped VM. The lists cover the
patterns seen in current phishing PDFs (free app hosting, file-sharing sites,
shorteners, cheap TLDs, and brand names on domains the brand doesn't own).
Each signal is weak on its own; the phishing analyzer combines them with the
document's layout before calling anything malicious.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

# Free app/static hosting and file sharing that phishing kits favour. Benign documents rarely
# send readers to a bare *.vercel.app or pixeldrain link; big mainstream services (Dropbox,
# Google Drive, GitHub Pages) are left out because legitimate documents link to them constantly.
HOSTING_SUFFIXES = (
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev", "supabase.co",
    "firebasestorage.googleapis.com", "firebaseapp.com", "web.app", "appspot.com", "storage.googleapis.com",
    "blogspot.com", "weebly.com", "wixsite.com", "myftpupload.com", "pixeldrain.com", "4sync.com",
    "mediafire.com", "myqcloud.com", "aliyuncs.com", "glitch.me", "onrender.com", "herokuapp.com",
    "ngrok-free.app", "ngrok.io", "ngrok.app", "trycloudflare.com", "ipfs.io", "dweb.link", "w3s.link",
    "000webhostapp.com", "repl.co", "replit.app", "surge.sh", "framer.app", "framer.website", "webflow.io",
    "godaddysites.com", "square.site", "jimdosite.com", "sites.google.com", "filecloudtrial.com",
    "storageforthecloud.com", "translate.goog",
    # anonymous / temporary file drops
    "storjshare.io", "tempfiles.ninja", "gofile.io", "catbox.moe", "transfer.sh", "file.io", "temp.sh",
    "bashupload.com", "filebin.net", "ufile.io", "pantheonsite.io", "fast-page.org",
)
# A PDF button that downloads one of these is how loader campaigns (Qakbot, IcedID, DarkGate, ...) work.
RISKY_DOWNLOAD_EXTENSIONS = {
    "zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "js", "jse", "vbs", "vbe", "wsf", "hta", "msi", "exe",
    "scr", "lnk", "bat", "cmd", "ps1", "jar", "apk", "dll", "cab", "xz", "gz", "tgz", "ace", "arj", "one",
    "appx", "msix", "url", "library-ms",
}
EXECUTABLE_INNER = re.compile(r"\.(?:exe|scr|js|vbs|hta|msi|lnk|bat|cmd|ps1|jar)\.[a-z0-9]{1,4}$")
# Redirectors whose parameter carries the real destination (DarkGate used doubleclick's adurl=).
REDIRECT_HOSTS = ("doubleclick.net", "google.com", "youtube.com", "bing.com", "linkedin.com", "facebook.com")
REDIRECT_PARAMS = {"adurl", "url", "q", "u", "redirect", "redir", "target", "dest", "destination", "next"}
COMMON_GTLDS = {"com", "net", "org", "info", "biz", "io", "co", "gov", "edu", "app", "dev"}
FILE_EXTENSIONS = {"pdf", "html", "htm", "php", "asp", "aspx", "jsp", "js", "css", "png", "jpg", "jpeg", "gif",
                   "svg", "zip", "exe", "doc", "docx", "xls", "xlsx", "txt", "xml", "json", "cgi", "py", "pl",
                   "sh", "md", "ps", "rs", "xz", "gz", "scr", "rar"}
# Lookalike spellings: rn->m, vv->w, 0->o, 1/l->i, applied to both brand and host before comparing.
LOOKALIKE = str.maketrans({"0": "o", "1": "i", "l": "i"})
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "is.gd", "cutt.ly", "rebrand.ly", "surl.li", "rb.gy", "shorturl.at",
    "s.id", "ow.ly", "tiny.cc", "v.gd", "qrco.de", "short.gy", "bl.ink", "t2m.io", "urlz.fr", "goo.su",
}
SUSPICIOUS_TLDS = {
    "click", "top", "xyz", "site", "online", "icu", "cfd", "sbs", "rest", "buzz", "monster", "quest", "bond",
    "lol", "zip", "mov", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "cyou", "beauty", "hair",
}
# Brand keyword -> registered domains the brand actually uses.
BRANDS: dict[str, tuple[str, ...]] = {
    "booking": ("booking.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com", "sharepoint.com",
                  "outlook.com", "msn.com", "azure.com", "windows.net", "office365.com"),
    "office365": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com", "office365.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com", "1drv.ms", "sharepoint.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobe.io", "acrobat.com", "adobelogin.com", "adobesign.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "netflix": ("netflix.com",),
    "dropbox": ("dropbox.com", "dropboxusercontent.com", "db.tt"),
    "wetransfer": ("wetransfer.com", "we.tl"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "facebook": ("facebook.com", "fb.com", "fb.me"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "wellsfargo": ("wellsfargo.com",),
    "quickbooks": ("intuit.com", "quickbooks.com"),
}
TWO_LEVEL_SUFFIX_SECOND = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}
DOMAIN_IN_TEXT_RE = re.compile(r"([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class UrlRisk:
    url: str
    host: str
    signals: dict[str, str] = field(default_factory=dict)  # signal -> human-readable detail


def registered_domain(host: str) -> str:
    """example.com for a.b.example.com; example.co.uk for a.example.co.uk. (No public-suffix list.)"""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in TWO_LEVEL_SUFFIX_SECOND and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _owned_by(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _brand_tokens(text: str) -> set[str]:
    """Brands that start a token, so "bookings" matches booking but "pineapple" doesn't match apple."""
    tokens = re.split(r"[^a-z0-9]+", text.lower())
    return {brand for brand in BRANDS for tok in tokens if tok.startswith(brand)}


def _lookalike(text: str) -> str:
    return text.replace("rn", "m").replace("vv", "w").translate(LOOKALIKE)


def _public_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_global


def assess(url: str, _depth: int = 0) -> UrlRisk:
    parts = urlsplit(url if "://" in url or url.startswith("//") else "http://" + url)
    host = (parts.hostname or "").lower()
    risk = UrlRisk(url, host)
    if not host:
        return risk
    registered = registered_domain(host)
    path = parts.path.lower()

    # Private and loopback addresses are routers and intranet docs; public raw IPs are not normal links.
    if IP_RE.match(host) and _public_ip(host):
        risk.signals["ip_host"] = host

    last = path.rstrip("/").rsplit("/", 1)[-1]
    ext = last.rsplit(".", 1)[-1] if "." in last else ""
    if ext in RISKY_DOWNLOAD_EXTENSIONS or EXECUTABLE_INNER.search(last):
        risk.signals["download_link"] = last[:80]

    # Government labels in the subdomain of a non-government domain: email.gov.in.example.pl
    sub_labels = host[: -len(registered)].strip(".").split(".") if host != registered else []
    if any(label in ("gov", "mil") for label in sub_labels):
        risk.signals["fake_government"] = host

    # Redirect wrappers: judge the hidden destination, too.
    if any(host == h or host.endswith("." + h) for h in REDIRECT_HOSTS) and _depth == 0:
        for key, values in parse_qs(parts.query).items():
            target = values[0] if values else ""
            if key.lower() in REDIRECT_PARAMS and target.startswith(("http", "//")):
                inner = assess(target, _depth + 1)
                risk.signals["open_redirect"] = f"{host} -> {inner.host or target[:60]}"
                for signal, detail in inner.signals.items():
                    risk.signals.setdefault(signal, f"{detail} (behind redirect)")
                break

    # Another site's domain spelled out in the path, to borrow its credibility:
    # kontaktlines.com/us.kuehne-nagel.com. Full URLs (with ://) are redirects, handled above.
    for candidate in DOMAIN_IN_TEXT_RE.findall(path):
        labels = candidate.split(".")
        tld = labels[-1]
        if tld in FILE_EXTENSIONS or "://" + candidate in url.lower():
            continue
        if (len(labels) >= 3 or tld in COMMON_GTLDS) and registered_domain(candidate) != registered:
            risk.signals["domain_in_path"] = f"{candidate} inside a URL on {host}"
            break
    if any(host == s or host.endswith("." + s) for s in HOSTING_SUFFIXES):
        risk.signals["free_hosting"] = host
    if host in SHORTENERS or registered_domain(host) in SHORTENERS:
        risk.signals["shortener"] = host
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        risk.signals["suspicious_tld"] = "." + host.rsplit(".", 1)[-1]

    # Brand named in the hostname, but the host isn't one the brand owns. The brand's exact name on
    # another TLD (facebook.net, amazon.de) is treated as owned: kits use lookalikes, not the real name.
    for brand in _brand_tokens(host):
        if not _owned_by(host, BRANDS[brand]) and registered.split(".")[0] != brand:
            risk.signals["brand_impersonation"] = f"{brand!r} in host {host}"
    # Lookalike spellings of longer brand names anywhere in the host (loginmlcrosoftonline...).
    # Only when the real spelling is absent, so the exact-match rule above stays in charge.
    folded = _lookalike(host)
    for brand, owned in BRANDS.items():
        if (len(brand) >= 6 and brand not in host and _lookalike(brand) in folded
                and not _owned_by(host, owned)):
            risk.signals["brand_impersonation"] = f"lookalike of {brand!r} in host {host}"
    # A brand's own domain spelled out in the path or query of someone else's site
    # (e.g. evil.vercel.app/?account.booking.com), a common trick to look legitimate.
    if "open_redirect" in risk.signals:
        return risk  # the brand domain in a redirect's parameter is the destination, judged above
    rest = f"{parts.path}?{parts.query}#{parts.fragment}".lower()
    for domain in DOMAIN_IN_TEXT_RE.findall(rest):
        for brand, owned in BRANDS.items():
            if any(domain == d or domain.endswith("." + d) for d in owned) and not _owned_by(host, owned):
                risk.signals["brand_impersonation"] = f"{domain} inside a URL on {host}"
    return risk
