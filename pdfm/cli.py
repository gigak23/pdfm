"""Command-line entry point: `pdfm scan`, `pdfm forge`."""

from __future__ import annotations

from pathlib import Path

import typer

from pdfm import forge as forge_lib
from pdfm import scanner
from pdfm.report import json_out, terminal

# Exit codes 0/1/2 are reserved for verdicts (benign/suspicious/malicious) from M3 on.
EXIT_ERROR = 3

app = typer.Typer(
    help="PDFM: static analysis for malicious PDF files.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """PDFM: static analysis for malicious PDF files."""


@app.command()
def scan(
    file: Path = typer.Argument(..., help="PDF file to analyze"),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of the terminal report"),
    max_objects: int = typer.Option(50, help="Max objects to list in the terminal report"),
) -> None:
    """Analyze a PDF file."""
    # Checked by hand rather than with typer's exists=True, which exits with code 2
    # and would collide with the "malicious" verdict code.
    if not file.is_file():
        typer.echo(f"error: {file} is not a file", err=True)
        raise typer.Exit(EXIT_ERROR)
    try:
        result = scanner.scan(file)
    except OSError as exc:
        typer.echo(f"error: cannot read {file}: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)

    if as_json:
        typer.echo(json_out.render(result))
    else:
        terminal.render(result, max_objects=max_objects)


@app.command()
def forge(outdir: Path = typer.Argument(Path("tests/fixtures"), help="Directory to write fixtures to")) -> None:
    """Generate harmless test PDFs that exercise each detection."""
    outdir.mkdir(parents=True, exist_ok=True)
    for name, data in forge_lib.build_all().items():
        (outdir / name).write_bytes(data)
        typer.echo(f"wrote {outdir / name}")
