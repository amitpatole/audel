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
def analyze(
    source: str,
    brief: str = typer.Option(None, help="Free-text description of the intended audio."),
    expect: list[str] = typer.Option(None, "--expect", help="Repeatable claim, e.g. 'must: language is en'."),
    backend: str = typer.Option(None, help="ollama|anthropic|gemini-audio|local (default: ollama)."),
) -> None:
    """Full grade: deterministic signals + ASR + backend LLM/CLAP critique (egress on this path)."""
    from ..core import analyze as _analyze
    from ..models import Brief

    b = Brief.from_inputs(text=brief, expect=expect) if (brief or expect) else None
    report = asyncio.run(_analyze(source, brief=b, backend=backend))
    _print_report(report)
    if report.conformance:
        for c in report.conformance.claims:
            typer.echo(f"    [{c.importance.value}] {c.status.value}: {c.text}")
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


@app.command()
def watch(
    source: str,
    click: str = typer.Option(None, help="CSS selector to click (URL mode) — check its sound fires."),
) -> None:
    """Temporal grade: plays-through / dropouts / A/V desync (file) or sound-fires (http(s) URL)."""
    from ..core import watch as _watch

    report = asyncio.run(_watch(source, click_selector=click))
    _print_report(report)
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


@app.command()
def diff(baseline: str, candidate: str) -> None:
    """Grade two clips and report what a fix changed (resolved / introduced / persisted issues)."""
    from ..core import check as _check
    from ..core import compute_diff as _compute_diff

    before = asyncio.run(_check(baseline))
    after = asyncio.run(_check(candidate))
    d = _compute_diff(before, after)
    verdict = "improved" if d.improved else ("regressed" if d.regressed else "no change")
    color = typer.colors.GREEN if d.improved else (typer.colors.RED if d.regressed else typer.colors.WHITE)
    typer.secho(f"{verdict}: {before.verdict.value.upper()} → {after.verdict.value.upper()}",
                fg=color, bold=True)
    for label, items in (("resolved", d.resolved), ("introduced", d.introduced),
                         ("persisted", d.persisted)):
        for it in items:
            typer.echo(f"  [{label}] {it}")


@app.command()
def stream(source: str,
           chunk_ms: int = typer.Option(500, help="Chunk size fed per step (simulated live cadence).")) -> None:
    """Grade a source as a LIVE stream: decode, then feed it in chunks to a bounded StreamMonitor.

    Demonstrates the realtime path (live voice-agent / call QA). Prints periodic status, then the
    final time-grounded report.
    """
    import wave

    from ..core.stream import StreamMonitor
    from ..mediaguard import decode_to_wav, validate_source

    settings = load_settings()
    path = validate_source(source, settings)
    wav = decode_to_wav(path, settings)
    try:
        with wave.open(str(wav), "rb") as w:
            sr, ch = w.getframerate(), w.getnchannels()
            mon = StreamMonitor(sample_rate=sr, channels=ch, settings=settings)
            n = max(1, int(sr * chunk_ms / 1000))
            while True:
                frames = w.readframes(n)
                if not frames:
                    break
                u = mon.feed(frames)
                typer.echo(f"  t={u.t_ms:>6}ms  rms={u.rms_dbfs:6.1f}dBFS  "
                           f"{'CLIP ' if u.clipping else ''}{'SILENT ' if u.silent else ''}"
                           f"→ {u.verdict.value}")
    finally:
        wav.unlink(missing_ok=True)
    typer.secho("\nfinal:", bold=True)
    _print_report(mon.finalize())


@app.command()
def serve(host: str = typer.Option("127.0.0.1", help="Bind host. Non-loopback requires AUDEL_API_TOKEN."),
          port: int = typer.Option(8000, help="Bind port.")) -> None:
    """Start the REST service (needs audel[serve]). Loopback is zero-config; a routable bind
    refuses to start without AUDEL_API_TOKEN (fail closed)."""
    from .rest import serve as _serve

    _serve(host=host, port=port)


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
