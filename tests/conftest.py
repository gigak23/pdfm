from pathlib import Path

import pytest

from pdfm.forge import build_all


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory) -> dict[str, Path]:
    """Freshly forged benign PDFs, keyed by file name."""
    outdir = tmp_path_factory.mktemp("fixtures")
    paths = {}
    for name, data in build_all().items():
        paths[name] = outdir / name
        paths[name].write_bytes(data)
    return paths
