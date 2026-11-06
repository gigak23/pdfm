import json

from typer.testing import CliRunner

from pdfm.cli import EXIT_ERROR, app

runner = CliRunner()


def test_scan_json_output(fixtures):
    result = runner.invoke(app, ["scan", str(fixtures["clean.pdf"]), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["parse_mode"] == "pikepdf"
    assert len(data["sha256"]) == 64
    assert len(data["objects"]) == 5


def test_scan_terminal_output(fixtures):
    result = runner.invoke(app, ["scan", str(fixtures["incremental.pdf"])])
    assert result.exit_code == 0
    assert "INCREMENTAL_UPDATES" in result.output


def test_missing_file_uses_error_exit_code(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "nope.pdf")])
    assert result.exit_code == EXIT_ERROR


def test_forge_writes_fixtures(tmp_path):
    result = runner.invoke(app, ["forge", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "clean.pdf").exists()
