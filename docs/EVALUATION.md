# Evaluation

How PDFM's detection numbers were measured, so they can be checked and repeated.

## Method

- **Malicious samples** were analyzed only inside an offline REMnux VM (network disconnected
  before extraction). PDFM never opens or renders samples; it parses them statically.
- **Development vs. test:** rules were tuned only on the development sets. The test set was
  downloaded after the rules were frozen and was not inspected before measuring.
- **"Flagged"** = verdict *suspicious* or *malicious*. Exploit-free phishing lures land on
  *suspicious* by design (a bad link is a strong sign, not proof), so "flagged" is the headline
  detection metric and *malicious* is the high-confidence subset.
- Numbers come from `tools/benchmark.py DIR --label malicious|benign`.

## Datasets

All from MalwareBazaar (abuse.ch), queried on **2026-11-06**:

| Set | How it was built | Role |
|---|---|---|
| `mb` | `query=get_file_type&file_type=pdf&limit=1000` (the API returned the 100 most recent PDFs) | development |
| `mb2` | `query=get_taginfo&tag=pdf&limit=1000`, first 300 PDFs not in `mb` | development |
| `mb3` | the remaining PDFs from the same `get_taginfo` list, not in `mb` or `mb2` (394 files) | **held-out test** |

MalwareBazaar's lists change over time, so re-running the same queries later returns newer
samples. The approach is reproducible; the exact sets are not.

Academic benchmark: **CIC-Evasive-PDFMal2022** (Canadian Institute for Cybersecurity, UNB),
`Benign.zip` and `Malicious.zip` from the CIC download page, all inner archives extracted
(9,107 benign and 21,864 malicious files). Never used for development.

Benign sets:

| Set | Source | Role |
|---|---|---|
| Personal | 397 PDFs from one user's documents (textbooks, slides, vendor manuals, forms) | development / sanity check |
| GovDocs1 dev | [digitalcorpora.org](https://digitalcorpora.org/corpora/file-corpora/files/) zip threads `000`-`009`, PDFs only (2,471) | development |
| GovDocs1 test | zip threads `010`-`019`, PDFs only (2,558) | **held-out false-positive test** |

GovDocs1 threads are fixed archives, so these benign sets are exactly reproducible:
`https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/0NN.zip`.

## Results

| Set | Files | Flagged | Malicious | Notes |
|---|---|---|---|---|
| `mb` (dev) | 100 | 29% → **49%** | 6% → 23% | before → after the phishing analyzer |
| `mb2` (dev) | 297 | 26% → **38%** | 9% → 10% | before → after the loader-link heuristics |
| **`mb3` (test)** | **394** | **54.3%** | **18.5%** | never seen during development (22.1% malicious before the GovDocs1 scoring fix; flagged unchanged) |
| Personal benign | 397 | 3.8% | **0%** | all 15 flagged files contain JavaScript or are malformed |
| GovDocs1 dev | 2,471 | 2.4% → 1.7% | 2 → **0** | both were legitimate; fixed by scoring overlapping findings once and judging Launch by its target |
| **GovDocs1 test** | **2,558** | **2.2%** | **0 (0.00%)** | never seen during development |

### CIC-Evasive-PDFMal2022 (held-out)

| Set | Files scanned | Flagged | Malicious |
|---|---|---|---|
| **CIC malicious** | 21,835 | **98.5%** | 54.1% |
| **CIC benign** | 9,106 | 10.9% | **0.07% (6 files)** |

Two operating points: **flag for review** (suspicious or worse) catches 98.5% of malicious files and
flags 10.9% of benign ones; **block** (malicious only) catches 54.1% at a 0.07% false-positive rate.
CIC's benign set is rich in interactive forms (XFA, embedded HTML, JavaScript), which is why far
more of it reaches *suspicious* than GovDocs1 does.

The 6 benign files rated malicious, reported unchanged (CIC was not used for tuning):

- `PDFwithjar.pdf` embeds a Java JAR and extracts it on open: arguably correctly flagged.
- `RichContentorFlash (4).pdf` combines embedded Flash with auto-running JavaScript.
- Two IRS forms with TIFF images in their XFA match the CVE-2010-0188 YARA rule, which is too broad
  (it should require a malformed TIFF, not any TIFF).
- Two IRS forms with Adobe's "update your Reader" pop-up next to a link are mistaken for a phishing
  pop-up by `JS_LURE_MESSAGE`.

30 files (0.1%) crashed the version that was measured (`45291f9`) and are excluded from the
percentages. The cause, a sandbox bug triggered by scripts that pass the global object as an
argument, was fixed in `642cae9`.

Scan speed: median 10-85 ms per file depending on the set.

## What the misses are

Inspecting development-set misses showed that most remaining undetected samples are:

- lures linking to **compromised but ordinary-looking websites** (nothing in the URL stands out),
- links to **legitimate platforms** (personal SharePoint, Dropbox) that can't be flagged without
  flagging normal documents,
- documents with **no links or scripts at all** (callback scams, images), which need page-text
  analysis or live URL reputation.

MalwareBazaar labels are also imperfect: a few "malicious" PDFs were ordinary books, so the true
detection rate is likely slightly higher than measured.
