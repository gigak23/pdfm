"""Command-line entry point: `pdfm scan`, `pdfm forge`."""

from __future__ import annotations

from pathlib import Path

import typer

from pdfm import forge as forge_lib
from pdfm import scanner, scoring
from pdfm.parser.document import FileTooLarge, load
from pdfm.report import json_out, terminal
from pdfm.report.safe import printable

# Exit codes 0/1/2 mean benign/suspicious/malicious (see scoring.EXIT_CODES).
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
    except (OSError, FileTooLarge) as exc:
        typer.echo(f"error: cannot scan {file}: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)

    if as_json:
        typer.echo(json_out.render(result))
    else:
        terminal.render(result, max_objects=max_objects)
    raise typer.Exit(scoring.EXIT_CODES[result.verdict])


@app.command()
def dump(
    file: Path = typer.Argument(..., help="PDF file"),
    obj: int = typer.Argument(..., help="Object number"),
    gen: int = typer.Option(0, help="Generation number"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write decoded bytes to this file instead"),
) -> None:
    """Show one object: its dictionary and decoded stream (like pdf-parser -o N -d)."""
    if not file.is_file():
        typer.echo(f"error: {file} is not a file", err=True)
        raise typer.Exit(EXIT_ERROR)
    doc = load(file)
    try:
        ref = f"{obj} {gen} R"
        heads = [h for r, h in doc.iter_heads() if r == ref]
        stream = doc.stream(obj, gen)
        if not heads and stream is None:
            typer.echo(f"error: object {ref} not found", err=True)
            raise typer.Exit(EXIT_ERROR)
        if out is not None:
            if stream is None:
                typer.echo(f"error: object {ref} has no stream", err=True)
                raise typer.Exit(EXIT_ERROR)
            out.write_bytes(stream.data)
            typer.echo(f"wrote {len(stream.data):,} decoded bytes to {out}")
            return
        if heads:
            typer.echo(printable(heads[-1].strip()))
        if stream is not None:
            info = stream.info
            typer.echo(f"--- stream: filters={info.filters or 'none'} raw={info.raw_size:,} "
                       f"decoded={info.decoded_size:,} entropy={info.entropy}"
                       + (f" error={info.error}" if info.error else ""))
            typer.echo(printable(stream.data, limit=64 * 1024))
    finally:
        doc.close()


@app.command()
def forge(outdir: Path = typer.Argument(Path("tests/fixtures"), help="Directory to write fixtures to")) -> None:
    """Generate harmless test PDFs that exercise each detection."""
    outdir.mkdir(parents=True, exist_ok=True)
    for name, data in forge_lib.build_all().items():
        (outdir / name).write_bytes(data)
        typer.echo(f"wrote {outdir / name}")
