"""Offline URL risk heuristics for phishing links.

No lookups: everything here works in an air-gapped VM. The lists cover the
patterns seen in current phishing PDFs (free app hosting, file-sharing sites,
shorteners, cheap TLDs, and brand names on domains the brand doesn't own).
Each signal is weak on its own; the phishing analyzer combines them with the
document's layout before calling anything malicious.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

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
)
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


def assess(url: str) -> UrlRisk:
    parts = urlsplit(url if "://" in url else "http://" + url)
    host = (parts.hostname or "").lower()
    risk = UrlRisk(url, host)
    if not host:
        return risk

    if IP_RE.match(host):
        risk.signals["ip_host"] = host
    if any(host == s or host.endswith("." + s) for s in HOSTING_SUFFIXES):
        risk.signals["free_hosting"] = host
    if host in SHORTENERS or registered_domain(host) in SHORTENERS:
        risk.signals["shortener"] = host
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        risk.signals["suspicious_tld"] = "." + host.rsplit(".", 1)[-1]

    # Brand named in the hostname, but the host isn't one the brand owns. The brand's exact name on
    # another TLD (facebook.net, amazon.de) is treated as owned: kits use lookalikes, not the real name.
    for brand in _brand_tokens(host):
        if not _owned_by(host, BRANDS[brand]) and registered_domain(host).split(".")[0] != brand:
            risk.signals["brand_impersonation"] = f"{brand!r} in host {host}"
    # A brand's own domain spelled out in the path or query of someone else's site
    # (e.g. evil.vercel.app/?account.booking.com), a common trick to look legitimate.
    rest = f"{parts.path}?{parts.query}#{parts.fragment}".lower()
    for domain in DOMAIN_IN_TEXT_RE.findall(rest):
        for brand, owned in BRANDS.items():
            if any(domain == d or domain.endswith("." + d) for d in owned) and not _owned_by(host, owned):
                risk.signals["brand_impersonation"] = f"{domain} inside a URL on {host}"
    return risk
