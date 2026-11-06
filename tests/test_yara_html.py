import pytest
from typer.testing import CliRunner

from pdfm.analyzers import yara_scan
from pdfm.cli import app
from pdfm.context import ScanOptions
from pdfm.forge import js_on_open
from pdfm.report import html_out
from pdfm.scanner import scan, scan_bytes

needs_yara = pytest.mark.skipif(not yara_scan.available(), reason="yara-python not installed")


def yara_ids(result):
    return {f.id for f in result.findings if f.id.startswith("YARA_")}


@needs_yara
@pytest.mark.parametrize("name, rule", [
    ("fontmatrix_string.pdf", "YARA_PDFM_CVE_2024_4367_PDFJS_FONTMATRIX"),
    ("xfa_tiff.pdf", "YARA_PDFM_CVE_2010_0188_XFA_TIFF"),
    ("pe_in_stream.pdf", "YARA_PDFM_PE_EXECUTABLE_IN_STREAM"),
    ("swf_stream.pdf", "YARA_PDFM_FLASH_IN_STREAM"),
    ("launch_cmd.pdf", "YARA_PDFM_LAUNCH_SHELL"),
])
def test_bundled_rules(fixtures, name, rule):
    assert rule in yara_ids(scan(fixtures[name], ScanOptions(sandbox=False)))


@needs_yara
def test_spray_rule_matches_script_text(forged):
    assert "YARA_PDFM_UNICODE_SPRAY_FILLER" in yara_ids(scan_bytes(forged["js_spray_pattern.pdf"]))


@needs_yara
@pytest.mark.parametrize("name", ["clean.pdf", "link.pdf", "form_js.pdf", "objstm.pdf", "embedded_text.pdf"])
def test_no_yara_hits_on_benign_fixtures(fixtures, name):
    assert yara_ids(scan(fixtures[name])) == set()


@needs_yara
def test_user_rules_see_decoded_streams(fixtures, tmp_path):
    (tmp_path / "custom.yar").write_text(
        'rule Custom_Hidden_Text { meta: severity = "high" description = "custom" '
        'strings: $a = "nothing to see here" condition: $a }')
    result = scan(fixtures["triple_chain.pdf"], ScanOptions(rules_dir=tmp_path))
    [finding] = [f for f in result.findings if f.id == "YARA_CUSTOM_HIDDEN_TEXT"]
    # Three encoding layers hide the text from the raw bytes; only the decoded stream matches.
    assert finding.severity == "high" and finding.evidence == "matched in: 6 0 R"


# --- HTML report -----------------------------------------------------------------------

def test_html_report_is_inert_even_with_hostile_content():
    hostile = js_on_open(b"var s = '</pre><script>alert(1)</script><img src=x onerror=alert(2)>';")
    page = html_out.render(scan_bytes(hostile))
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "&lt;/pre&gt;&lt;script&gt;" in page


@pytest.mark.parametrize("name, heading", [
    ("clean.pdf", "Findings"), ("clean.pdf", "Objects"), ("js_openaction.pdf", "Actions"),
    ("js_openaction.pdf", "JavaScript"), ("embedded_text.pdf", "Embedded files"),
    ("link.pdf", "Indicators"), ("link.pdf", "Keyword counts"),
])
def test_html_report_contains_sections(fixtures, name, heading):
    page = html_out.render(scan(fixtures[name], ScanOptions(sandbox=False)))
    assert f"<h2>{heading}" in page


def test_cli_writes_html(fixtures, tmp_path):
    out = tmp_path / "report.html"
    result = CliRunner().invoke(app, ["scan", str(fixtures["link.pdf"]), "--json", "--html", str(out)])
    assert result.exit_code == 0
    assert "hxxps://example[.]com/login" in out.read_text(encoding="utf-8")
