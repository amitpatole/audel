"""Drift guard: the version lives in pyproject, __init__ and CITATION.cff — they must agree."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import audel

ROOT = Path(__file__).resolve().parents[2]


def _pyproject_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def _citation_version() -> str:
    m = re.search(r"^version:\s*(\S+)\s*$", (ROOT / "CITATION.cff").read_text(), re.MULTILINE)
    assert m, "CITATION.cff has no version line"
    return m.group(1).strip("\"'")


def test_init_matches_pyproject():
    assert audel.__version__ == _pyproject_version()


def test_citation_matches_pyproject():
    assert _citation_version() == _pyproject_version()


def test_changelog_mentions_current_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert f"[{_pyproject_version()}]" in text
