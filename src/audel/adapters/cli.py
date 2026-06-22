"""Audel CLI (Typer). The graded commands are wired phase by phase; ``doctor``/``version`` work now."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import typer

from .. import __version__
from ..config import load_settings
from ..models import Report
from .doctor import format_checks, run_checks

app = typer.Typer(add_completion=False, help="Audel — Ears for AI Agents 👂")

_SOON = "This command lands in a later build (see TASKS.md); the package scaffold is in place."

_SEV_COLOR = {"pass": typer.colors.GREEN, "warn": typer.colors.YELLOW, "fail": typer.colors.RED}


def _print_report(report: Report) -> None:
    color = _SEV_COLOR.get(report.verdict.value, typer.colors.WHITE)
    typer.secho(f"{report.verdict.value.upper()}  {report.summary}", fg=color, bold=True)
    for i in report.issues:
        span = f"[{i.span.start_ms}–{i.span.end_ms}ms]" if i.span else ""
        typer.echo(f"  • [{i.kind.value}/{i.severity.value}] {span} {i.message}")


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
    """Deterministic grade (no LLM, no egress)."""
    from ..core import check as _check

    report = asyncio.run(_check(source))
    _print_report(report)
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


@app.command()
def render(source: str) -> None:
    """Decode to trustworthy signals (loudness, true-peak, RMS, silent spans)."""
    from ..core import render as _render

    rr = asyncio.run(_render(source))
    typer.echo(f"{rr.duration_ms or 0}ms  {rr.channels or 0}ch  {rr.sample_rate or 0}Hz  "
               f"{rr.codec}\n  LUFS={rr.integrated_lufs}  true_peak={rr.true_peak_dbtp}dBTP  "
               f"RMS={rr.rms_dbfs}dBFS  silences={len(rr.silences)}")


@app.command()
def analyze(source: str) -> None:
    """Full grade with backend critique — Phase 3."""
    typer.secho(f"analyze {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def watch(source: str) -> None:
    """Temporal/playback liveness — Phase 4."""
    typer.secho(f"watch {source}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def diff(baseline: str, candidate: str) -> None:
    """Waveform/transcript/loudness diff — Phase 1."""
    typer.secho(f"diff {baseline} {candidate}: {_SOON}", fg=typer.colors.YELLOW)


@app.command()
def demo() -> None:
    """Grade a deliberately-broken clip → time-grounded FAIL, then a fixed clip → PASS (no API key)."""
    from ..core import check as _check
    from ._demo_assets import make_broken, make_good

    with tempfile.TemporaryDirectory(prefix="audel-demo-") as td:
        d = Path(td)
        typer.secho("\n1) broken clip (clipping):", bold=True)
        _print_report(asyncio.run(_check(str(make_broken(d)))))
        typer.secho("\n2) fixed clip:", bold=True)
        _print_report(asyncio.run(_check(str(make_good(d)))))
        typer.echo("\nNo API key used — this is the deterministic check path.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
