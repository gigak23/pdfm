"""Human-readable terminal report.

Everything derived from the sample is escaped before printing: Rich interprets
[brackets] as markup, so a hostile file could otherwise inject styles or break output.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from pdfm.models import ScanResult, Severity

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
    console.print(Panel(summary, title="PDFM scan", expand=False))

    if result.objects:
        table = Table(title="Objects", title_justify="left")
        for col in ("Obj", "Gen", "Type", "Stream", "ObjStm", "Offset"):
            table.add_column(col, justify="right" if col in ("Obj", "Gen", "Offset") else "left")
        for obj in result.objects[:max_objects]:
            table.add_row(
                str(obj.num), str(obj.gen), escape(obj.type),
                "yes" if obj.is_stream else "",
                "yes" if obj.in_objstm else "",
                "" if obj.offset is None else str(obj.offset),
            )
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
