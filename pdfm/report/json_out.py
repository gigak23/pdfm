"""Machine-readable output for pipelines (SOAR, CI, mail gateways)."""

from __future__ import annotations

import json

from pdfm.models import ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
