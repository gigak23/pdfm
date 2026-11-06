import pytest
from typer.testing import CliRunner

from pdfm.cli import app
from pdfm.models import Finding, Severity, Verdict
from pdfm.scanner import scan
from pdfm.scoring import score, verdict


def ids(result):
    return {f.id for f in result.findings}


@pytest.mark.parametrize("name", [
    "clean.pdf", "incremental.pdf", "objstm.pdf", "chained.pdf", "lzw_rle.pdf", "link.pdf",
    "encrypted.pdf", "encrypted_aes128.pdf", "encrypted_rc4.pdf",
])
def test_benign_fixtures_score_benign(fixtures, name):
    result = scan(fixtures[name])
    assert result.verdict == Verdict.BENIGN, [(f.id, f.severity) for f in result.findings]


def test_javascript_on_open_is_suspicious_on_its_own(fixtures):
    # Vendor manuals run harmless JS on open; "malicious" needs evidence about what the JS does.
    result = scan(fixtures["js_openaction.pdf"])
    assert {"JAVASCRIPT", "OPEN_ACTION", "AUTO_RUN_JAVASCRIPT"} <= ids(result)
    assert result.verdict == Verdict.SUSPICIOUS
    assert [(a.trigger, a.type, a.on_open) for a in result.actions] == [("OpenAction", "JavaScript", True)]


def test_hex_escaped_names_are_decoded_and_flagged(fixtures):
    result = scan(fixtures["obfuscated_name.pdf"])
    assert {"OBFUSCATED_NAME", "JAVASCRIPT", "AUTO_RUN_JAVASCRIPT"} <= ids(result)
    assert result.keywords["JavaScript"] == 1 and result.keywords["JS"] == 1


def test_launch_on_open(fixtures):
    result = scan(fixtures["launch.pdf"])
    assert {"LAUNCH_ACTION", "AUTO_LAUNCH"} <= ids(result)
    assert result.verdict == Verdict.MALICIOUS


def test_form_javascript_is_not_mistaken_for_auto_run(fixtures):
    # JS + OpenAction co-occur, but the OpenAction is just a view destination.
    result = scan(fixtures["form_js.pdf"])
    assert "JAVASCRIPT" in ids(result)
    assert "AUTO_RUN_JAVASCRIPT" not in ids(result)
    assert result.verdict == Verdict.SUSPICIOUS
    assert result.actions[0].trigger.startswith("form field") or "annotation" in result.actions[0].trigger
    assert len(result.actions) == 1  # widget is both annotation and field; counted once


def test_link_annotation_action_is_resolved(fixtures):
    result = scan(fixtures["link.pdf"])
    assert [(a.type, a.on_open) for a in result.actions] == [("URI", False)]


def test_zip_appended_after_eof(fixtures):
    result = scan(fixtures["trailing_zip.pdf"])
    assert {"DATA_AFTER_EOF", "EMBEDDED_SIGNATURE"} <= ids(result)
    assert result.verdict != Verdict.BENIGN


def test_gif_pdf_polyglot(fixtures):
    result = scan(fixtures["gif_prefix.pdf"])
    assert "POLYGLOT" in ids(result)


def test_keywords_inside_object_streams_are_counted(fixtures):
    result = scan(fixtures["objstm.pdf"])
    assert result.keywords["Page"] == 1  # pdfid's default mode can't see inside /ObjStm


def test_scoring_thresholds():
    low = Finding("A", Severity.LOW, "")
    high = Finding("B", Severity.HIGH, "")
    high2 = Finding("C", Severity.HIGH, "")
    medium = Finding("D", Severity.MEDIUM, "")
    critical = Finding("E", Severity.CRITICAL, "")
    assert verdict(score([low]), [low]) == Verdict.BENIGN
    assert verdict(score([high]), [high]) == Verdict.SUSPICIOUS
    assert verdict(score([high, high2, medium]), [high, high2, medium]) == Verdict.MALICIOUS
    assert verdict(score([critical]), [critical]) == Verdict.MALICIOUS


def test_repeated_findings_count_once():
    many = [Finding("SAME", Severity.HIGH, "") for _ in range(175)]
    assert score(many) == 6


def test_fake_stream_keyword_inside_string_does_not_swallow_objects():
    # Regression: "(Datastream)" in a dictionary used to look like a stream start.
    from pdfm.parser.raw import iter_objects
    data = (b"1 0 obj\n<< /Title (Datastream) >>\nendobj\n2 0 obj\n<< /S /JavaScript /JS (x) >>\nendobj\n"
            b"3 0 obj\n<< /Length 3 >>\nstream\nabc\nendstream\nendobj\n")
    assert [o.num for o in iter_objects(data)] == [1, 2, 3]


@pytest.mark.parametrize("name, code", [("clean.pdf", 0), ("form_js.pdf", 1), ("launch.pdf", 2)])
def test_exit_code_reflects_verdict(fixtures, name, code):
    assert CliRunner().invoke(app, ["scan", str(fixtures[name]), "--json"]).exit_code == code
