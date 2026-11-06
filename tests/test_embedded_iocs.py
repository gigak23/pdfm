import pytest

from pdfm.analyzers.embedded import identify
from pdfm.analyzers.iocs import defang
from pdfm.context import ScanOptions
from pdfm.forge import fake_pe_header, office_zip_with_macro_part, small_zip
from pdfm.models import Severity, Verdict
from pdfm.scanner import scan, scan_bytes


def ids(result):
    return {f.id for f in result.findings}


# --- identification by content ----------------------------------------------------

@pytest.mark.parametrize("data, kind, severity", [
    (fake_pe_header(), "Windows PE executable", Severity.CRITICAL),
    (b"\x7fELF" + b"\0" * 60, "ELF executable", Severity.CRITICAL),
    (office_zip_with_macro_part(), "Office document with VBA macros", Severity.HIGH),
    (small_zip(), "ZIP archive (1 files)", Severity.LOW),
    (b"%PDF-1.7\n", "PDF document", None),
    (b"plain old text\n", "text", None),
])
def test_identify(data, kind, severity):
    ident = identify(data)
    assert (ident.kind, ident.severity) == (kind, severity)


def test_defang():
    assert defang("url", "https://evil.example.com/a.b") == "hxxps://evil[.]example[.]com/a.b"
    assert defang("email", "a.b@evil.com") == "a.b[@]evil[.]com"
    assert defang("unc", "\\\\host.local\\share") == "\\\\host[.]local\\share"


# --- embedded files end to end -------------------------------------------------------

def test_benign_attachment(fixtures):
    result = scan(fixtures["embedded_text.pdf"])
    assert [(e.name, e.kind) for e in result.embedded] == [("notes.txt", "text")]
    assert result.verdict == Verdict.BENIGN


def test_executable_with_double_extension(fixtures):
    result = scan(fixtures["embedded_exe.pdf"])
    assert {"EMBEDDED_EXECUTABLE", "DOUBLE_EXTENSION"} <= ids(result)
    assert result.embedded[0].kind == "Windows PE executable"
    assert result.verdict == Verdict.MALICIOUS


def test_macro_document(fixtures):
    assert "EMBEDDED_MACRO_DOCUMENT" in ids(scan(fixtures["embedded_docm.pdf"]))


def test_nested_pdf_is_scanned_recursively(fixtures):
    result = scan(fixtures["embedded_pdf.pdf"], ScanOptions(sandbox=False))
    assert "CVE_2009_0927_COLLAB_GETICON" in ids(result)  # finding lifted from the inner PDF
    assert "NESTED_PDF" in ids(result)
    assert result.embedded[0].nested_verdict == "malicious"
    assert result.verdict == Verdict.MALICIOUS


def test_nesting_depth_limit(fixtures):
    result = scan(fixtures["embedded_pdf.pdf"], ScanOptions(sandbox=False, max_depth=0))
    assert "NESTING_TOO_DEEP" in ids(result)


def test_eicar_detected_from_memory(forged):
    assert "EICAR_TEST_FILE" in ids(scan_bytes(forged["embedded_eicar.pdf"]))


def test_extraction_uses_hash_names(fixtures, tmp_path):
    result = scan(fixtures["embedded_exe.pdf"], ScanOptions(extract_dir=tmp_path))
    [info] = result.embedded
    assert info.extracted_to.endswith(f"{info.sha256}.bin")
    assert (tmp_path / f"{info.sha256}.bin").read_bytes() == fake_pe_header()
    assert not list(tmp_path.glob("*.exe"))


# --- IOCs -------------------------------------------------------------------------------

def iocs(result, kind):
    return {i.value for i in result.iocs if i.kind == kind}


def test_link_url_and_domain(fixtures):
    result = scan(fixtures["link.pdf"])
    assert iocs(result, "url") == {"https://example.com/login"}
    assert iocs(result, "domain") == {"example.com"}


def test_unc_path_flagged(fixtures):
    result = scan(fixtures["unc_gotor.pdf"])
    assert iocs(result, "unc") == {"\\\\pdfm-test.invalid\\share\\doc.pdf"}
    assert "UNC_PATH" in ids(result)


def test_latex_line_breaks_are_not_unc_paths():
    from pdfm.analyzers.iocs import UNC_RE
    assert not UNC_RE.findall(r"\\nCode\n\n\end{document}")
    assert UNC_RE.findall(r"\\203.0.113.5\share") == [r"\\203.0.113.5\share"]


def test_launch_of_system_tool(fixtures):
    result = scan(fixtures["launch_cmd.pdf"])
    assert {"AUTO_LAUNCH", "LAUNCH_SYSTEM_TOOL"} <= ids(result)
    assert "cmd.exe /c echo pdfm-test" in iocs(result, "path")


def test_ip_url(fixtures):
    result = scan(fixtures["ip_uri.pdf"])
    assert "IP_URL" in ids(result)
    assert iocs(result, "ip") == {"192.0.2.10"}


def test_url_built_at_runtime_by_javascript(fixtures):
    result = scan(fixtures["js_launchurl.pdf"])
    assert "http://pdfm-test.invalid/landing" in iocs(result, "url")
    assert "JS_NETWORK" in ids(result)
