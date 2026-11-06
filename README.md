# PDFM

Static analysis toolkit for malicious PDF files: parses PDF internals, decodes streams,
triages suspicious features, and extracts indicators.

## Quick start

```sh
uv venv --python 3.11
uv pip install -e ".[dev]"
pdfm scan document.pdf          # terminal report
pdfm scan document.pdf --json   # machine-readable output
pdfm forge tests/fixtures       # generate harmless test PDFs
pytest
```

## Safety

- Handle live malware **only inside an isolated VM**. Store samples as zips with the password `infected`.
- Never commit live samples. `samples/` and `*.zip` are git-ignored.
- PDFM never executes the content it analyzes.
