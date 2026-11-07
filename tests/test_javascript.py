import pytest

from pdfm.context import ScanOptions
from pdfm.js import sandbox, shellcode
from pdfm.js.deobfuscate import deobfuscate
from pdfm.js.extract import extract, parse_literal
from pdfm.models import Verdict
from pdfm.parser import load
from pdfm.scanner import scan, scan_bytes

needs_sandbox = pytest.mark.skipif(not sandbox.available(), reason="mini-racer not installed")

# Antivirus engines (Windows Defender: Exploit:JS/Mult.DJ) quarantine files that contain these
# exploit-style strings verbatim, so tests assemble them at runtime instead.
GET_ICON = "Collab" + ".get" + "Icon"
UNESC = "un" + "escape"
NOP_U = "%u" + "9090"


def ids(result):
    return {f.id for f in result.findings}


# --- deobfuscation -------------------------------------------------------------

def test_concatenation_is_folded():
    assert deobfuscate("x = 'ev' + \"al\" + 'uate';").code == 'x = "evaluate";'


def test_concatenation_respects_property_access():
    assert "'b'.length" in deobfuscate("x = 'a' + 'b'.length;").code


def test_from_char_code():
    d = deobfuscate("s = String.fromCharCode(0x61, 112, 112);")
    assert d.code == 's = "app";' and d.obfuscated


def test_printable_unescape_is_inlined():
    assert deobfuscate(UNESC + "('%61%70%u0070')").code == '"app"'


def test_binary_unescape_becomes_payload():
    d = deobfuscate(f"var s = {UNESC}('{NOP_U * 2}');")
    assert UNESC + "(" in d.code
    assert d.payloads == [b"\x90\x90\x90\x90"]


def test_reverse_replace_and_eval_literal():
    code = "eval('trela.ppa'.split('').reverse().join('') + 'X(1)X'.replace(/X/g, ''))"
    # Reversal and replace fold to literals, then concatenation, then eval of a literal unwraps.
    assert deobfuscate(code).code == "app.alert(1)"


def test_escape_sequences_decoded():
    assert deobfuscate(r"x = '\x61pp';").code == 'x = "app";'


def test_plain_code_is_not_obfuscated():
    assert not deobfuscate("app.alert('Hello ' + 'world');").obfuscated


# --- PDF strings and extraction ----------------------------------------------

def test_parse_literal_handles_escapes_and_nesting():
    assert parse_literal(rb"(a\(b\) (nested) \101\n\\)", 0) == b"a(b) (nested) A\n\\"


@pytest.mark.parametrize("name, trigger, on_open", [
    ("js_openaction.pdf", "OpenAction", True),
    ("js_unreferenced.pdf", "not reachable from any trigger", False),
    ("xfa_script.pdf", "XFA form script (initialize/docReady event)", True),
    ("js_raw_mode.pdf", "raw scan (parser failed)", False),
])
def test_scripts_are_extracted_from_every_source(fixtures, name, trigger, on_open):
    doc = load(fixtures[name])
    scripts = extract(doc)
    doc.close()
    assert [(s.trigger, s.on_open) for s in scripts] == [(trigger, on_open)]
    assert "app.alert" in scripts[0].code


def test_document_level_script_runs_before_open_action(fixtures):
    doc = load(fixtures["js_doclevel_split.pdf"])
    assert [s.trigger for s in extract(doc)] == ["Document-level script", "OpenAction"]
    doc.close()


# --- shellcode heuristics ------------------------------------------------------

def test_shellcode_indicators():
    assert shellcode.indicators(b"\x90" * 40 + b"\xe8\x00\x00\x00\x00") == [
        "NOP sled (32+ x 0x90)", "call $+5 (GetPC)"]
    assert shellcode.indicators(b"just some text") == []


# --- sandbox -------------------------------------------------------------------

@needs_sandbox
def test_sandbox_records_calls_and_evals():
    [run] = sandbox.run_scripts([f"var c = 'app.alert(\"hi\")'; eval(c); {GET_ICON}('x');"], {})
    assert run.status == "ok"
    assert run.evals == ['app.alert("hi")']
    assert run.calls == ["app.alert(hi)", f"{GET_ICON}(x)"]


@needs_sandbox
def test_sandbox_shares_context_between_scripts():
    runs = sandbox.run_scripts(["function f() { app.alert('x'); }", "f();"], {})
    assert runs[1].calls == ["app.alert(x)"]


@needs_sandbox
def test_sandbox_exposes_document_info():
    [run] = sandbox.run_scripts(["app.alert(info.title)"], {"title": "payload-in-metadata"})
    assert run.calls == ["app.alert(payload-in-metadata)"]


@needs_sandbox
def test_odd_arguments_are_recorded_as_text():
    # Regression: app.alert(this) crashed 30 scans on CIC-Evasive-PDFMal2022.
    [run] = sandbox.run_scripts(["app.alert(this); app.alert(function () {}); app.alert(undefined, null, 1.5)"], {})
    assert run.status == "ok"
    assert run.calls[0] == "app.alert(this)"
    assert all(isinstance(c, str) for c in run.calls) and len(run.calls) == 3


def test_a_failing_analyzer_does_not_stop_the_scan(fixtures, monkeypatch):
    from pdfm import scanner

    def broken(doc, ctx):
        raise TypeError("boom")
    monkeypatch.setattr(scanner, "ANALYZERS", [broken] + scanner.ANALYZERS)
    result = scan(fixtures["js_openaction.pdf"])
    assert "ANALYZER_ERROR" in ids(result)
    assert "AUTO_RUN_JAVASCRIPT" in ids(result)  # later analyzers still ran


@needs_sandbox
def test_unknown_acrobat_builtins_become_stubs():
    [run] = sandbox.run_scripts(["AFNumber_Keystroke(2, 0); var x = 1; y = x + 1; app.alert(y);"], {})
    assert run.status == "ok"
    assert run.calls == ["AFNumber_Keystroke(2, 0)", "app.alert(2)"]


@needs_sandbox
def test_sandbox_has_no_host_access():
    # Unknown names resolve to recording stubs, so check that no real host objects exist.
    [run] = sandbox.run_scripts([
        "app.alert(Object.getOwnPropertyNames(globalThis).filter(function (n) {"
        " return ['require', 'process', 'fetch', 'XMLHttpRequest', 'WebSocket'].indexOf(n) >= 0; }).length)"], {})
    assert run.calls == ["app.alert(0)"]


@needs_sandbox
def test_methods_called_on_this_inside_functions_are_stubbed():
    [run] = sandbox.run_scripts(["function f() { this.selectPageNthWord(1, 0); } f();"], {})
    assert run.calls == ["selectPageNthWord(1, 0)"]


@needs_sandbox
def test_sandbox_stops_infinite_loops():
    [run] = sandbox.run_scripts(["while (true) {}"], {})
    assert run.status == "timeout"


@needs_sandbox
def test_sandbox_stops_memory_exhaustion():
    [run] = sandbox.run_scripts(["var a = []; while (true) a.push(new Array(1e6).join('x'));"], {})
    assert run.status in ("memory limit", "timeout")


# --- analyzer end to end ---------------------------------------------------------

@needs_sandbox
def test_obfuscated_eval_is_unmasked_by_the_sandbox(fixtures):
    result = scan(fixtures["js_obfuscated.pdf"])
    assert {"JS_OBFUSCATED", "JS_EVAL", "AUTO_RUN_JAVASCRIPT"} <= ids(result)
    assert "app.alert(hi)" in result.scripts[0].api_calls
    assert result.verdict == Verdict.MALICIOUS


def test_exploit_api_pattern_is_critical(fixtures):
    result = scan(fixtures["js_cve_pattern.pdf"], ScanOptions(sandbox=False))
    assert "CVE_2009_0927_COLLAB_GETICON" in ids(result)
    assert result.verdict == Verdict.MALICIOUS


def test_heap_spray_and_nop_sled(forged):
    result = scan_bytes(forged["js_spray_pattern.pdf"])  # from memory: Defender quarantines it on disk
    assert {"JS_HEAP_SPRAY", "JS_SPRAY_LOOP", "SHELLCODE"} <= ids(result)


@needs_sandbox
def test_split_script_behaviour_seen_in_sandbox(fixtures):
    result = scan(fixtures["js_doclevel_split.pdf"])
    open_action = next(s for s in result.scripts if s.trigger == "OpenAction")
    assert open_action.api_calls == ["app.alert(split across scripts)"]


def test_sandbox_can_be_disabled(fixtures):
    result = scan(fixtures["js_openaction.pdf"], ScanOptions(sandbox=False))
    assert result.scripts[0].sandbox == "disabled"
