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

Benign sets:

| Set | Source | Role |
|---|---|---|
| Personal | 397 PDFs from one user's documents (textbooks, slides, vendor manuals, forms) | development / sanity check |
| GovDocs1 | [digitalcorpora.org](https://digitalcorpora.org/corpora/file-corpora/files/) threads `000`-`009`, PDFs only | public false-positive test |

## Results

| Set | Files | Flagged | Malicious | Notes |
|---|---|---|---|---|
| `mb` (dev) | 100 | 29% → **49%** | 6% → 23% | before → after the phishing analyzer |
| `mb2` (dev) | 297 | 26% → **38%** | 9% → 10% | before → after the loader-link heuristics |
| **`mb3` (test)** | **394** | **54.3%** | **22.1%** | never seen during development |
| Personal benign | 397 | 3.8% | **0%** | all 15 flagged files contain JavaScript or are malformed |
| GovDocs1 benign | pending | | | |

Scan speed: median 58-85 ms per file, 0 crashes across all sets.

## What the misses are

Inspecting development-set misses showed that most remaining undetected samples are:

- lures linking to **compromised but ordinary-looking websites** (nothing in the URL stands out),
- links to **legitimate platforms** (personal SharePoint, Dropbox) that can't be flagged without
  flagging normal documents,
- documents with **no links or scripts at all** (callback scams, images), which need page-text
  analysis or live URL reputation.

MalwareBazaar labels are also imperfect: a few "malicious" PDFs were ordinary books, so the true
detection rate is likely slightly higher than measured.
