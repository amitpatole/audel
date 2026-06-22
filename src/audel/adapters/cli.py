"""Audel CLI (Typer). The graded commands are wired phase by phase; ``doctor``/``version`` work now."""

from __future__ import annotations

import typer

from .. import __version__
from ..config import load_settings
from .doctor import format_checks, run_checks

app = typer.Typer(add_completion=False, help="Audel — Ears for AI Agents 👂")

_SOON = "This command lands in a later build (see TASKS.md); the package scaffold is in place."


@app.command()
def version() -> None:
    """Print the Audel version."""
    typer.echo(f"audel {__version__}")


@app.command()
def doctor() -> None:
    """Check ffmpeg, ASR, CLAP, Chromium, and which backends have credentials."""
    checks = run_checks(load_settings())
    typer.echo("audel doctor:")
    typer.echo(format_checks(checks))
    typer.echo("ok" if all(c.ok for c in checks if c.name in {"ffmpeg"}) else
               "note: install ffmpeg for the deterministic check path")


@app.command()
def check(source: str) -> None:
    """Deterministic grade (no LLM, no egress) — Phase 1."""
    typer.secho(f"check {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def analyze(source: str) -> None:
    """Full grade with backend critique — Phase 3."""
    typer.secho(f"analyze {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def watch(source: str) -> None:
    """Temporal/playback liveness — Phase 4."""
    typer.secho(f"watch {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def render(source: str) -> None:
    """Decode to waveform + signals — Phase 1."""
    typer.secho(f"render {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def diff(baseline: str, candidate: str) -> None:
    """Waveform/transcript/loudness diff — Phase 1."""
    typer.secho(f"diff {baseline} {candidate}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def demo() -> None:
    """Play a deliberately broken clip → FAIL with time-grounded issues → fixed → PASS — Phase 1."""
    typer.secho(f"demo: {_SOON}", fg=typer.colors.YELLOW)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
