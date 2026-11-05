"""Person 1: core checks.

STEP 1: check_package() is a stub that returns fake data in the shared format.
STEP 2: replace the body with real PyPI/npm, name-similarity and OSV checks.
"""
from __future__ import annotations

import re

from result_format import PackageResult


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Turn requirements.txt text into (name, version) pairs. Skips blank lines and comments."""
    packages = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"[=<>~!]=", line, maxsplit=1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else "latest"
        packages.append((name, version))
    return packages


def check_package(name: str, version: str = "latest") -> PackageResult:
    """STUB: returns a fake result in the agreed format."""
    return PackageResult(
        name=name,
        version=version,
        verdict="Caution",
        confidence="Low",
        reasons=["Stub result: real checks are not written yet"],
        evidence={"source": "stub"},
        fix=None,
    )
