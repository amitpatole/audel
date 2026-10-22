"""Docs move in lockstep with the code: the configuration page must match the Settings model."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_configuration_page_matches_settings():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "gen_config_docs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert (ROOT / "docs" / "configuration.md").read_text() == gen.render(), (
        "docs/configuration.md is stale: run python scripts/gen_config_docs.py")


def test_every_cli_command_is_documented():
    from typer.main import get_command

    from audel.adapters.cli import app

    cli_doc = (ROOT / "docs" / "cli.md").read_text()
    for name in get_command(app).commands:
        assert f"audel {name}" in cli_doc, f"`audel {name}` missing from docs/cli.md"
