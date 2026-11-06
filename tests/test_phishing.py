import pytest

from pdfm import urlrisk
from pdfm.analyzers import phishing
from pdfm.models import Verdict
from pdfm.scanner import scan

needs_qr = pytest.mark.skipif(phishing.cv2 is None, reason="opencv not installed")


def ids(result):
    return {f.id for f in result.findings}


# --- URL heuristics (plain strings, nothing is fetched) --------------------------

@pytest.mark.parametrize("url, signal", [
    ("https://account-bookings.vercel.app/?account.booking.com/#invoice.pdf", "brand_impersonation"),
    ("https://account-bookings.vercel.app/x", "free_hosting"),
    ("https://abcxyz.supabase.co/storage/v1/object/public/x.html", "free_hosting"),
    ("https://firebasestorage.googleapis.com/v0/b/x/o/doc.html", "free_hosting"),
    ("https://surl.li/abcde", "shortener"),
    ("https://www.maneger-accouintr-solutieonst.site/", "suspicious_tld"),
    ("http://secure-docusign.example.net/view", "brand_impersonation"),
    ("http://203.0.113.9/login", "ip_host"),
])
def test_risky_urls(url, signal):
    assert signal in urlrisk.assess(url).signals


@pytest.mark.parametrize("url", [
    "https://www.booking.com/hotel/it/roma.html",
    "https://login.microsoftonline.com/common/oauth2",
    "https://account.docusign.com/sign",
    "https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com",
    "https://en.wikipedia.org/wiki/Pineapple",
    "https://github.com/allenai/allennlp",
    "http://m.mirror.facebook.net/kde/devel/x.pdf",  # brand's own name on another TLD
    "https://www.amazon.de/dp/B000",
])
def test_legitimate_urls_have_no_signals(url):
    assert urlrisk.assess(url).signals == {}


def test_registered_domain():
    assert urlrisk.registered_domain("a.b.example.com") == "example.com"
    assert urlrisk.registered_domain("portal.loja.com.br") == "loja.com.br"


# --- documents ---------------------------------------------------------------------

def test_brand_lure_with_reader_popup_is_malicious(fixtures):
    result = scan(fixtures["phish_brand_lure.pdf"])
    assert {"PHISHING_LURE", "BRAND_IMPERSONATION", "PHISHING_LURE_LAYOUT", "JS_LURE_MESSAGE"} <= ids(result)
    assert result.verdict == Verdict.MALICIOUS


def test_link_only_lure_is_at_least_suspicious(fixtures):
    result = scan(fixtures["phish_link_only.pdf"])
    assert {"PHISHING_LURE", "BRAND_IMPERSONATION"} <= ids(result)
    assert result.verdict != Verdict.BENIGN


def test_legitimate_flyer_with_big_button_stays_benign(fixtures):
    result = scan(fixtures["benign_flyer.pdf"])
    assert "PHISHING_LURE_LAYOUT" in ids(result)  # it is lure-shaped...
    assert "PHISHING_LURE" not in ids(result)  # ...but its link is ordinary
    assert result.verdict == Verdict.BENIGN


def test_schemeless_link_is_extracted(fixtures):
    result = scan(fixtures["schemeless_link.pdf"])
    assert "http://www.pdfm-test.invalid/login" in {i.value for i in result.iocs if i.kind == "url"}


@needs_qr
def test_qr_code_lure(fixtures):
    result = scan(fixtures["qr_lure.pdf"])
    qr = [i for i in result.iocs if i.source.startswith("QR code")]
    assert [i.value for i in qr] == ["https://login-microsoft.pdfm-test.invalid/mfa"]
    assert {"QR_CODE_URL", "BRAND_IMPERSONATION", "PHISHING_LURE"} <= ids(result)
    assert result.verdict == Verdict.MALICIOUS
