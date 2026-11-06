from pathlib import Path

import pytest

from pdfm.forge import AV_SENSITIVE, build_all


@pytest.fixture(scope="session")
def forged() -> dict[str, bytes]:
    """Every forged benign PDF as bytes, including ones antivirus would quarantine on disk."""
    return build_all()


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory, forged) -> dict[str, Path]:
    """Forged PDFs written to a temp dir, keyed by file name (AV-sensitive ones excluded)."""
    outdir = tmp_path_factory.mktemp("fixtures")
    paths = {}
    for name, data in forged.items():
        if name in AV_SENSITIVE:
            continue
        paths[name] = outdir / name
        paths[name].write_bytes(data)
    return paths
