"""Scan every PDF under one or more directories and summarize the verdicts.

Usage:
    python tools/benchmark.py DIR [DIR ...] [--label benign|malicious] [--no-sandbox]

With --label, the directories are treated as ground truth and the script
reports the detection rate (malicious) or false-positive rate (benign).
Run against live malware only inside an isolated VM.
"""

from __future__ import annotations

import argparse
import collections
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pdfm.context import ScanOptions  # noqa: E402
from pdfm.scanner import scan  # noqa: E402


def looks_like_pdf(path: Path) -> bool:
    """By extension, or by a %PDF header for datasets that name samples by hash with no extension."""
    if path.suffix.lower() == ".pdf":
        return True
    if path.suffix:  # .zip, .json, .txt, ...: not a sample
        return False
    try:
        with path.open("rb") as f:
            return b"%PDF" in f.read(1024)
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dirs", nargs="+", type=Path)
    parser.add_argument("--label", choices=["benign", "malicious"])
    parser.add_argument("--no-sandbox", action="store_true")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary")
    parser.add_argument("--exclude", action="append", default=[], help="Skip paths containing this text")
    args = parser.parse_args()

    paths = sorted({p for d in args.dirs for p in d.rglob("*")
                    if p.is_file() and looks_like_pdf(p) and not any(x in str(p) for x in args.exclude)})
    options = ScanOptions(sandbox=not args.no_sandbox)
    verdicts: collections.Counter = collections.Counter()
    finding_counts: collections.Counter = collections.Counter()
    times, errors = [], 0

    for path in paths:
        start = time.perf_counter()
        try:
            result = scan(path, options)
        except Exception as exc:  # a crash on one sample must not stop the run; it's counted instead
            errors += 1
            print(f"ERROR      {path.name}: {type(exc).__name__}: {exc}")
            continue
        times.append(time.perf_counter() - start)
        verdicts[result.verdict.value] += 1
        finding_counts.update({f.id for f in result.findings if f.severity != "info"})
        if not args.quiet and result.verdict.value != "benign":
            ids = sorted({f.id for f in result.findings if f.severity != "info"})
            print(f"{result.verdict.value:10} {result.score:4}  {path.name[:60]:60} {', '.join(ids)}")

    scanned = sum(verdicts.values())
    print(f"\n{len(paths)} files, {scanned} scanned, {errors} errors")
    for verdict in ("benign", "suspicious", "malicious"):
        print(f"  {verdict:10} {verdicts[verdict]:6}  ({verdicts[verdict] / max(scanned, 1):.1%})")
    if times:
        print(f"  time: median {statistics.median(times) * 1000:.0f} ms, "
              f"p95 {sorted(times)[int(len(times) * 0.95)] * 1000:.0f} ms, total {sum(times):.1f} s")
    if args.label == "benign":
        print(f"  false-positive rate (malicious): {verdicts['malicious'] / max(scanned, 1):.2%}")
        print(f"  flagged rate (suspicious or malicious): "
              f"{(verdicts['malicious'] + verdicts['suspicious']) / max(scanned, 1):.2%}")
    elif args.label == "malicious":
        print(f"  detection rate (malicious): {verdicts['malicious'] / max(scanned, 1):.2%}")
        print(f"  detection rate (suspicious or malicious): "
              f"{(verdicts['malicious'] + verdicts['suspicious']) / max(scanned, 1):.2%}")
    print("  most common findings:", ", ".join(f"{k} ({v})" for k, v in finding_counts.most_common(8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
