# PDFM

[![tests](https://github.com/gigak23/pdfm/actions/workflows/tests.yml/badge.svg)](https://github.com/gigak23/pdfm/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static analysis for malicious PDF files. PDFM parses PDF internals (including deliberately broken
files), decodes every stream safely, resolves what runs when the document opens, deobfuscates and
emulates embedded JavaScript in an isolated V8 sandbox, inspects embedded files, extracts IOCs, runs
YARA, and produces an explainable verdict as a terminal report, JSON or an inert HTML page.

```text
$ pdfm scan js_cve_pattern.pdf      # a harmless fixture from `pdfm forge`
 Verdict   MALICIOUS (score 23)                                    exit code 2
 high      JAVASCRIPT                     6 0 R  Document contains JavaScript (2 occurrence(s))
 low       OPEN_ACTION                    1 0 R  Document defines an action to run when opened
 high      AUTO_RUN_JAVASCRIPT            6 0 R  JavaScript runs automatically when the file opens
 critical  CVE_2009_0927_COLLAB_GETICON   6 0 R  Collab.getIcon, the CVE-2009-0927 stack overflow
```

## What it does

| Stage | Details |
|---|---|
| **Parsing** | qpdf (via pikepdf) as the primary parser, plus an independent raw object scanner. The two views are compared: objects present in the bytes but hidden from the xref are flagged (`UNINDEXED_OBJECTS`). Files qpdf can't open fall back to the raw scanner. |
| **Stream decoding** | Own output-capped decoders for Flate, ASCIIHex, ASCII85, LZW and RunLength act as a safety gate before pikepdf decodes, which stops decompression bombs. Detects unusual filter chains, non-standard filters and high-entropy payloads. Handles RC4/AES-encrypted files. |
| **Triage** | pdfid-style keyword counts, attributed per object and including objects packed inside compressed object streams. Decodes `#xx` name obfuscation (`/J#61vaScript`). |
| **Action resolution** | Follows OpenAction, document-level scripts, page, annotation and form-field events to the actions they run, so "JavaScript runs on open" is distinguished from "a form field formats a number". |
| **JavaScript** | Extracts scripts from actions, unreferenced `/JS` keys, XFA forms and raw bytes. A static deobfuscator undoes string splitting, `fromCharCode`, `unescape`, escape sequences, reversal and `eval` of literals. The sandbox runs all scripts in one isolated V8 context with recording stubs for the Acrobat API, and reports API calls and runtime-generated code. Flags known exploit APIs, heap sprays and shellcode patterns. |
| **Embedded files** | Identified by content, not name (PE/ELF/Mach-O/LNK, macro Office documents, JAR/APK, archives with risky members). Hashed, optionally extracted as `<sha256>.bin`, and embedded PDFs are scanned recursively. |
| **IOCs** | URLs, domains, IPs, emails, UNC paths (NTLM leak) and Launch targets from actions, object dictionaries and every script variant, including URLs built at runtime. Defanged in output. |
| **Phishing lures** | Most malicious PDFs today carry no exploit, just a fake "View document" button or a QR code. PDFM scores link destinations offline (free hosting, shorteners, cheap TLDs, brand names on domains the brand doesn't own), recognizes lure layouts (short, image-heavy, big clickable area), "open this in your browser" pop-ups, and decodes QR codes in page images. |
| **YARA** | Bundled rules (CVE-2024-4367 PDF.js FontMatrix, CVE-2010-0188 XFA TIFF, PE or Flash inside streams, spray filler, packers) plus your own via `--rules`. Matched against decoded streams and scripts, not just the raw bytes. |
| **Reporting** | Explainable score and verdict (exit codes 0/1/2), Rich terminal report, stable JSON, and a self-contained HTML report with no scripts and a strict CSP. |

## Install

Requires Python 3.11+.

```sh
git clone https://github.com/gigak23/pdfm && cd pdfm
uv venv --python 3.11
uv pip install -e ".[all]"      # sandbox (mini-racer) + YARA (yara-python) + QR decoding (OpenCV)
# or: pip install -e ".[all]";  add ".[dev]" for the test suite
```

The core works without the extras: the JavaScript sandbox, YARA and QR decoding are skipped if
their packages aren't installed.

## Usage

```sh
pdfm scan sample.pdf                     # terminal report
pdfm scan sample.pdf --json              # machine-readable, for pipelines
pdfm scan sample.pdf --html report.html  # self-contained, script-free HTML report
pdfm scan sample.pdf --extract out/      # write embedded files as out/<sha256>.bin
pdfm scan sample.pdf --rules my_rules/   # add your own YARA rules
pdfm scan sample.pdf --no-sandbox        # static analysis only
pdfm dump sample.pdf 12                  # show object 12 and its decoded stream (like pdf-parser -o 12 -d)
pdfm forge tests/fixtures                # generate harmless PDFs that trigger each detection
```

Exit codes: `0` benign, `1` suspicious, `2` malicious, `3` error, so it slots into scripts and CI:

```sh
pdfm scan attachment.pdf --json > result.json || echo "needs review"
```

## How scoring works

Every finding has a severity, and each finding *type* adds points once: info 0, low 1, medium 3,
high 6, critical 10. A score of 4 or more is **suspicious**. A score of 15 or more, **or any critical
finding**, is **malicious**. Every point traces back to a finding shown in the report.

The weights were tuned so that legitimate-but-unusual documents don't read as malicious. Vendor
datasheets that run JavaScript on open land on "suspicious". "Malicious" needs evidence about what the
content *does*: an exploit API, a Launch of `cmd.exe`, an embedded executable, obfuscated `eval`.

## Results so far

- **171 tests**, run on Linux and Windows in CI: every detector has positive and negative cases, built from forged, harmless PDFs (`pdfm forge`).
- **Benign real-world corpus** (397 PDFs: textbooks, lecture slides, vendor manuals, forms, government documents):
  **0 malicious verdicts**, 15 suspicious (all contain JavaScript or are malformed), 0 crashes, median 56 ms per file.
  Reproduce with `python tools/benchmark.py DIR --label benign`.
- **Real malware, held-out test** (394 MalwareBazaar PDFs never seen during development, analyzed in
  an offline REMnux VM): **54% flagged**, 22% rated malicious, 0 crashes. Most of today's malicious
  PDFs are exploit-free phishing and malware-loader lures; on the first development batch, adding the
  phishing analyzer raised detection from 29% to 49%. Full method, datasets and caveats:
  [docs/EVALUATION.md](docs/EVALUATION.md).

## Design decisions (the tool is attack surface too)

A tool that parses hostile files has to be robust against them:

- **Decompression bombs:** every stream is decoded through PDFM's own capped decoders first, with a
  50 MB per-stream and 256 MB per-file budget. Images are only sampled, but flagged if they decode
  past their declared `/Width x /Height`.
- **Parser differentials:** two independent parsers, with disagreement reported as a finding instead of hidden.
- **JavaScript sandbox:** bare V8 (no filesystem, network, `require` or `process`) with no Python
  callbacks exposed, a 3 s timeout per script and a 256 MB memory cap.
- **Output safety:** terminal output strips control characters (no escape-sequence injection). The
  HTML report escapes everything, contains no JavaScript, and sets `Content-Security-Policy:
  default-src 'none'`. IOCs are defanged.
- **Extraction:** embedded files are written as `<sha256>.bin`, never under their attacker-chosen
  name (`invoice.pdf.exe`, `../../x`).
- **Antivirus:** some test fixtures contain exploit-like *patterns* (not working exploits), and Windows
  Defender quarantines them on disk. Tests keep those fixtures in memory, and signature strings in
  source and rule files are assembled at runtime or written as hex.

## Safety

- Analyze live malware **only inside an isolated VM** (for example REMnux). Store samples as
  zips with password `infected`.
- Never commit live samples: `samples/` and `*.zip` are git-ignored.
- All fixtures in this repo are generated by `pdfm forge` and are harmless: scripts only call
  `app.alert`, the "executable" is a header with no code, and hosts use the reserved `.invalid` TLD
  and TEST-NET IP ranges.

## Limitations

- Static analysis plus JS emulation is not a full reader: exploits in image codecs (JBIG2, JPX,
  fonts) are flagged only by heuristics, not detected precisely.
- The sandbox emulates the Acrobat API with stubs. Scripts that check for specific return values may
  take a different path than in a real reader.
- The deobfuscator is regex-based and handles common literal-level tricks, not arbitrary computed strings
  (the sandbox covers some of those by capturing `eval` arguments).
- In raw-fallback mode, action resolution (which trigger runs what) isn't available; keyword triage
  and JavaScript extraction still work.

## Roadmap

- **Measure detection:** benchmark against MalwareBazaar PDF samples and the CIC-Evasive-PDFMal2022
  dataset inside a VM, and publish detection and false-positive rates.
- **ML layer:** a gradient-boosting classifier on PDFM's features (keyword counts, structure, JS
  indicators), combined with the rule score.
- **LLM layer:** an analyst summary and MITRE ATT&CK mapping generated from the findings JSON (never
  the raw file), with prompt-injection defenses: the LLM can't change the score.
- **Disarm:** `pdfm disarm in.pdf out.pdf` to strip active content.

## Project layout

```text
pdfm/
  parser/      raw.py (byte-level scanner), document.py (load + compare), streams.py, filters.py, actions.py
  analyzers/   streams, keywords, structure, actions, javascript, embedded, iocs, yara_scan
  js/          extract.py, deobfuscate.py, sandbox.py, shellcode.py
  report/      terminal.py, json_out.py, html_out.py, safe.py
  rules/       bundled YARA rules
  scoring.py   scanner.py   forge.py   cli.py
tests/         pytest suite (fixtures forged in memory)
tools/         benchmark.py
```

## Acknowledgements

Inspired by Didier Stevens' [pdfid and pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/),
the standard tools for manual PDF analysis.
