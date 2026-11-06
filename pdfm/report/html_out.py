"""Single-file HTML report.

The report shows attacker-controlled content (script code, file names, URLs),
so it is built to be inert: every value is HTML-escaped, the page contains no
JavaScript, and a Content-Security-Policy forbids loading or running anything
even if escaping were ever missed. IOCs are shown defanged.
"""

from __future__ import annotations

from html import escape

from pdfm import __version__
from pdfm.models import ScanResult
from pdfm.report.safe import printable

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'"

STYLE = """
:root { --bg:#fbfbfa; --fg:#1d1d1f; --muted:#6b6b70; --card:#ffffff; --line:#e3e3e0; --code:#f3f3f1;
        --benign:#1f7a3d; --suspicious:#9a6700; --malicious:#b42318;
        --info:#6b6b70; --low:#2f6fab; --medium:#9a6700; --high:#c2410c; --critical:#b42318; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#141416; --fg:#ececee; --muted:#9a9aa1; --card:#1c1c1f; --line:#2e2e33; --code:#232327;
          --benign:#4ade80; --suspicious:#fbbf24; --malicious:#f87171;
          --info:#9a9aa1; --low:#7cb4f0; --medium:#fbbf24; --high:#fb923c; --critical:#f87171; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:32px 0 10px; }
.muted { color:var(--muted); }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin:12px 0; overflow-x:auto; }
.verdict { display:inline-block; padding:4px 12px; border-radius:999px; font-weight:700; letter-spacing:.04em; color:#fff; }
.verdict.benign { background:var(--benign); } .verdict.suspicious { background:var(--suspicious); }
.verdict.malicious { background:var(--malicious); }
table { border-collapse:collapse; width:100%; font-size:14px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
td.mono, .mono { font-family:ui-monospace, "Cascadia Code", Consolas, monospace; font-size:13px; word-break:break-all; }
.sev { font-weight:700; text-transform:uppercase; font-size:12px; }
.sev.info { color:var(--info); } .sev.low { color:var(--low); } .sev.medium { color:var(--medium); }
.sev.high { color:var(--high); } .sev.critical { color:var(--critical); }
pre { background:var(--code); padding:12px; border-radius:8px; overflow-x:auto; white-space:pre-wrap;
      word-break:break-all; font-size:13px; margin:8px 0 0; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px; margin:0; }
dt { color:var(--muted); } dd { margin:0; word-break:break-all; }
details summary { cursor:pointer; color:var(--muted); }
"""


def _e(value) -> str:
    """Escape for HTML and strip control characters."""
    return escape(printable(str(value)), quote=True)


def _table(headers: list[str], rows: list[list[str]], mono: set[int] = frozenset()) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="mono">{c}</td>' if i in mono else f"<td>{c}</td>" for i, c in enumerate(row))
        + "</tr>" for row in rows)
    return f'<div class="card"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render(result: ScanResult) -> str:
    parts: list[str] = []
    v = result.verdict.value
    parts.append(f"""
<h1>PDFM report</h1>
<p class="muted mono">{_e(result.path)}</p>
<div class="card">
  <p><span class="verdict {v}">{v.upper()}</span> &nbsp; score {result.score}</p>
  <dl>
    <dt>Size</dt><dd>{result.size:,} bytes</dd>
    <dt>MD5</dt><dd class="mono">{result.md5}</dd>
    <dt>SHA256</dt><dd class="mono">{result.sha256}</dd>
    <dt>PDF version</dt><dd>{_e(result.pdf_version or "missing header")}</dd>
    <dt>Parser</dt><dd>{_e(result.parse_mode)}</dd>
    <dt>Revisions</dt><dd>{result.revisions}</dd>
    <dt>Objects</dt><dd>{len(result.objects)} ({sum(o.is_stream for o in result.objects)} streams)</dd>
  </dl>
</div>""")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(result.findings, key=lambda f: order[f.severity.value])
    parts.append(f"<h2>Findings ({len(findings)})</h2>")
    if findings:
        parts.append(_table(["Severity", "ID", "Object", "Description"], [
            [f'<span class="sev {f.severity.value}">{f.severity.value}</span>', _e(f.id), _e(f.object_ref or ""),
             _e(f.description) + (f'<div class="muted mono">{_e(f.evidence)}</div>' if f.evidence else "")]
            for f in findings], mono={2}))
    else:
        parts.append('<div class="card">No findings.</div>')

    if result.actions:
        parts.append("<h2>Actions</h2>")
        parts.append(_table(["Trigger", "Type", "Object", "Runs on open"], [
            [_e(a.trigger), _e(a.type), _e(a.ref), "yes" if a.on_open else ""] for a in result.actions[:200]],
            mono={2}))

    if result.scripts:
        parts.append(f"<h2>JavaScript ({len(result.scripts)})</h2>")
        for s in result.scripts[:50]:
            calls = "".join(f"<li class='mono'>{_e(c)}</li>" for c in s.api_calls[:30])
            parts.append(f"""
<div class="card">
  <dl>
    <dt>Object</dt><dd class="mono">{_e(s.ref)}</dd>
    <dt>Trigger</dt><dd>{_e(s.trigger)}{" (runs on open)" if s.on_open else ""}</dd>
    <dt>Size</dt><dd>{s.size:,} chars</dd>
    <dt>SHA256</dt><dd class="mono">{s.sha256}</dd>
    <dt>Obfuscation undone</dt><dd>{_e(", ".join(s.techniques) or "none")}</dd>
    <dt>Sandbox</dt><dd>{_e(s.sandbox)}</dd>
  </dl>
  {f"<p class='muted'>API calls observed in the sandbox:</p><ul>{calls}</ul>" if calls else ""}
  <details{" open" if len(s.deobfuscated) < 3000 else ""}><summary>Deobfuscated code</summary>
  <pre>{_e(s.deobfuscated)}</pre></details>
</div>""")

    if result.embedded:
        parts.append("<h2>Embedded files</h2>")
        parts.append(_table(["Object", "Name", "Detected type", "Size", "SHA256", "Nested verdict"], [
            [_e(e.ref), _e(e.name or ""), _e(e.kind), f"{e.size:,}", _e(e.sha256), _e(e.nested_verdict or "")]
            for e in result.embedded], mono={0, 4}))

    if result.iocs:
        parts.append(f"<h2>Indicators (defanged, {len(result.iocs)})</h2>")
        parts.append(_table(["Type", "Value", "Source"], [
            [_e(i.kind), _e(i.defanged), _e(i.source)] for i in result.iocs[:500]], mono={1}))

    if result.keywords:
        parts.append("<h2>Keyword counts</h2>")
        parts.append(_table(["Keyword", "Count"], [[f"/{_e(k)}", str(n)] for k, n in result.keywords.items()],
                            mono={0}))

    streams = {(s.num, s.gen): s for s in result.streams}
    rows = []
    for o in result.objects[:2000]:
        s = streams.get((o.num, o.gen))
        rows.append([str(o.num), str(o.gen), _e(o.type), "objstm" if o.in_objstm else _e(o.offset or ""),
                     _e(" ".join(s.filters)) if s else "", f"{s.raw_size:,} → {s.decoded_size:,}" if s else "",
                     f"{s.entropy:.2f}" if s else ""])
    parts.append(f"<h2>Objects</h2><details><summary>{len(result.objects)} objects</summary>")
    parts.append(_table(["Obj", "Gen", "Type", "Offset", "Filters", "Size", "Entropy"], rows))
    parts.append("</details>")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PDFM report</title>
<style>{STYLE}</style>
</head>
<body><main>
{"".join(parts)}
<p class="muted">Generated by PDFM {__version__}. Indicators are defanged; this page contains no scripts.</p>
</main></body>
</html>
"""
