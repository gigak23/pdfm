"""Human-readable terminal report.

Everything derived from the sample is escaped before printing: Rich interprets
[brackets] as markup, so a hostile file could otherwise inject styles or break output.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from pdfm.models import ScanResult, Severity, Verdict
from pdfm.report.safe import printable

VERDICT_STYLE = {
    Verdict.BENIGN: "bold green",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.MALICIOUS: "bold white on red",
}
SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def render(result: ScanResult, max_objects: int = 50, console: Console | None = None) -> None:
    console = console or Console()

    streams = sum(o.is_stream for o in result.objects)
    packed = sum(o.in_objstm for o in result.objects)
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("File", escape(result.path))
    summary.add_row("Size", f"{result.size:,} bytes")
    summary.add_row("MD5", result.md5)
    summary.add_row("SHA256", result.sha256)
    summary.add_row("PDF version", result.pdf_version or "[red]missing header[/]")
    summary.add_row("Parser", result.parse_mode)
    summary.add_row("Revisions", str(result.revisions))
    summary.add_row("Objects", f"{len(result.objects)} ({streams} streams, {packed} in object streams)")
    summary.add_row("Verdict", f"[{VERDICT_STYLE[result.verdict]}] {result.verdict.value.upper()} [/] "
                               f"(score {result.score})")
    console.print(Panel(summary, title="PDFM scan", expand=False))

    if result.keywords:
        console.print("[bold]Keywords:[/] " + "  ".join(f"/{k} {v}" for k, v in result.keywords.items()))

    if result.actions:
        actions = Table(title="Actions", title_justify="left")
        for col in ("Trigger", "Type", "Object", "On open"):
            actions.add_column(col)
        for a in result.actions:
            actions.add_row(escape(a.trigger), escape(a.type), a.ref, "[red]yes[/]" if a.on_open else "")
        console.print(actions)

    for script in result.scripts:
        lines = [
            f"[bold]Trigger:[/] {escape(script.trigger)}" + ("  [red](runs on open)[/]" if script.on_open else ""),
            f"[bold]Size:[/] {script.size:,} chars   [bold]SHA256:[/] {script.sha256[:16]}...",
            f"[bold]Sandbox:[/] {escape(script.sandbox)}",
        ]
        if script.techniques:
            lines.append(f"[bold]Obfuscation undone:[/] {escape(', '.join(script.techniques))}")
        if script.api_calls:
            lines.append("[bold]API calls observed:[/]")
            lines += [f"  {escape(printable(c, limit=160))}" for c in script.api_calls[:15]]
        lines.append("[bold]Code (deobfuscated):[/]")
        lines.append(f"[dim]{escape(printable(script.deobfuscated, limit=1500))}[/]")
        console.print(Panel("\n".join(lines), title=f"JavaScript {script.ref}", title_align="left", expand=False))

    if result.objects:
        streams = {(s.num, s.gen): s for s in result.streams}
        table = Table(title="Objects", title_justify="left")
        for col in ("Obj", "Gen", "Type", "Offset", "Filters", "Size", "Entropy"):
            table.add_column(col, justify="right" if col in ("Obj", "Gen", "Offset", "Size", "Entropy") else "left")
        for obj in result.objects[:max_objects]:
            s = streams.get((obj.num, obj.gen))
            offset = "objstm" if obj.in_objstm else ("" if obj.offset is None else str(obj.offset))
            size = entropy = filters = ""
            if s is not None:
                filters = escape(" ".join(s.filters))
                size = f"{s.raw_size:,} -> {s.decoded_size:,}"
                if s.truncated or s.error:
                    size = f"[red]{size}[/]"
                entropy = f"{s.entropy:.2f}"
            table.add_row(str(obj.num), str(obj.gen), escape(obj.type), offset, filters, size, entropy)
        console.print(table)
        hidden = len(result.objects) - max_objects
        if hidden > 0:
            console.print(f"[dim]... {hidden} more objects (use --max-objects to show more)[/]")

    if not result.findings:
        console.print("[green]No findings.[/]")
        return
    findings = Table(title="Findings", title_justify="left")
    for col in ("Severity", "ID", "Object", "Description"):
        findings.add_column(col)
    for f in result.findings:
        description = escape(f.description)
        if f.evidence:
            description += f"\n[dim]{escape(f.evidence)}[/]"
        findings.add_row(
            f"[{SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f.id, escape(f.object_ref or ""), description,
        )
    console.print(findings)
