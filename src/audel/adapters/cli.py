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


_SPEC_HELP = "Delivery spec: a built-in name (see `audel specs`) or a path to a JSON spec."
_CONTENT_HELP = "Content type: speech | music | mixed (enables content-aware checks)."


def _settings_for(content: str | None):
    return load_settings(content_type=content) if content else load_settings()


@app.command()
def check(source: str,
          spec: str = typer.Option(None, "--spec", help=_SPEC_HELP),
          content: str = typer.Option(None, "--content", help=_CONTENT_HELP),
          json_out: bool = typer.Option(False, "--json", help="Print the JSON report.")) -> None:
    """Deterministic grade (no LLM, no egress)."""
    from ..core import check as _check

    report = asyncio.run(_check(source, settings=_settings_for(content), spec=spec))
    if json_out:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


def _parse_languages(items: list[str] | None) -> dict[int, str]:
    out: dict[int, str] = {}
    for it in items or []:
        idx, sep, code = it.partition("=")
        if not sep or not idx.strip().isdigit():
            raise typer.BadParameter(f"--language expects TRACK=CODE, e.g. 1=es (got {it!r})")
        out[int(idx)] = code.strip()
    return out


@app.command()
def listen(
    source: str,
    script: Path = typer.Option(None, "--script", help="Approved script (text file) to check the read against."),
    captions: Path = typer.Option(None, "--captions", help="SRT or WebVTT file to check against the audio."),
    require: list[str] = typer.Option(None, "--require", help="Wording that must be said (repeatable)."),
    forbid: list[str] = typer.Option(None, "--forbid", help="Wording that must not be said (repeatable)."),
    language: list[str] = typer.Option(None, "--language", help="Expected language per track, TRACK=CODE (repeatable)."),
    key_message: list[str] = typer.Option(None, "--key-message", help="What a listener should take away (repeatable; 'must:' prefix makes a miss an error)."),
    tone: str = typer.Option(None, "--tone", help="Expected delivery: calm|warm|neutral|urgent|angry|monotone|rushed."),
    understand: bool = typer.Option(False, "--understand", help="Use a model for key messages, takeaway and delivery (may egress; ollama-local stays on your network)."),
    backend: str = typer.Option(None, help="Backend for --understand (default: ollama-local if AUDEL_LOCAL_LLM_URL is set)."),
    spec: str = typer.Option(None, "--spec", help=_SPEC_HELP),
    content: str = typer.Option(None, "--content", help=_CONTENT_HELP),
    json_out: bool = typer.Option(False, "--json", help="Print the JSON report."),
    html: Path = typer.Option(None, "--html", help="Write a self-contained HTML QC report here."),
) -> None:
    """Hear AND listen: signal QC, then what was said (script, wording, pace, captions, message)."""
    from ..core import listen as _listen

    report = asyncio.run(_listen(
        source, settings=_settings_for(content), spec=spec,
        script=script.read_text(encoding="utf-8") if script else None,
        captions=captions.read_text(encoding="utf-8") if captions else None,
        required=require or None, forbidden=forbid or None,
        languages=_parse_languages(language), key_messages=key_message or None, tone=tone,
        understand=understand, backend=backend))
    if json_out:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)
        ls = report.listening
        if ls is not None:
            if ls.takeaway:
                typer.echo(f"  takeaway: {ls.takeaway}")
            for d in ls.delivery:
                typer.echo(f"  heard [{d.start_ms}–{d.end_ms}ms]: {d.delivery or '?'}, pace "
                           f"{d.pace or '?'}, {d.intelligibility or '?'}")
        if report.conformance:
            for c in report.conformance.claims:
                typer.echo(f"    [{c.importance.value}] {c.status.value}: {c.text}")
    if html:
        from ..qc_report import render_html

        html.write_text(render_html(report, source_name=Path(source).name), encoding="utf-8")
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


token_app = typer.Typer(help="Manage per-tenant API tokens.")
app.add_typer(token_app, name="token")


@token_app.command("new")
def token_new(tenant: str = typer.Option(None, help="Tenant name ([A-Za-z0-9._-], 1-64 chars). "
                                         "Omit to mint a shared AUDEL_API_TOKEN."),
              rate_per_min: int = typer.Option(None, help="Optional per-tenant rate limit.")) -> None:
    """Mint a token. Prints the token ONCE (plus the tokens-file hash entry for a tenant)."""
    import json as _json

    from ..auth import new_token, token_hash, valid_tenant

    if tenant is None:
        typer.echo(new_token())
        return
    if not valid_tenant(tenant) or tenant.lower() in ("default", "anonymous", "admin"):
        raise typer.BadParameter("tenant must be 1-64 chars of [A-Za-z0-9._-] and not reserved")
    if rate_per_min is not None and rate_per_min < 1:
        raise typer.BadParameter("--rate-per-min must be at least 1")
    tok = new_token()
    entry: dict = {"sha256": token_hash(tok)}
    if rate_per_min is not None:
        entry["rate_per_min"] = rate_per_min
    typer.echo(f"token (give this to the tenant; it is not stored anywhere): {tok}")
    typer.echo("add to the tenants object in AUDEL_API_TOKENS_FILE:")
    typer.echo(_json.dumps({tenant: entry}))


@app.command()
def purge(hours: float = typer.Option(24.0, help="Remove temp files older than this many hours."),
          sessions: bool = typer.Option(True, help="Also reap expired loop sessions.")) -> None:
    """Delete stale workspace temp files and expired sessions (crash leftovers, retention)."""
    from ..workspace import Workspace

    ws = Workspace(load_settings())
    n = ws.purge_tmp(hours * 3600)
    m = ws.gc() if sessions else 0
    typer.echo(f"removed {n} temp file(s) and {m} session(s) from {ws.root}")


@app.command()
def specs() -> None:
    """List the built-in delivery specs."""
    from ..specs import BUILTIN_SPECS

    for s in BUILTIN_SPECS.values():
        extra = []
        if s.max_short_term_lufs is not None:
            extra.append(f"S≤{s.max_short_term_lufs:g}")
        if s.gating.value == "dialogue":
            extra.append("speech-gated")
        typer.echo(f"  {s.name:<15} {s.integrated_lufs:>6.1f} LUFS ±{s.tolerance_lu:<4g} "
                   f"TP≤{s.max_true_peak_dbtp:<5g} {s.strictness.value:<7} "
                   f"{' '.join(extra):<20} {s.description}")


@app.command()
def qc(source: str,
       spec: str = typer.Option(None, "--spec", help=_SPEC_HELP),
       content: str = typer.Option(None, "--content", help=_CONTENT_HELP),
       html: Path = typer.Option(None, "--html", help="Write a self-contained HTML QC report here."),
       json_path: Path = typer.Option(None, "--json", help="Write the JSON report here.")) -> None:
    """Grade against a delivery spec and write operator-facing QC reports (HTML and/or JSON)."""
    from ..core import check as _check
    from ..qc_report import render_html

    report = asyncio.run(_check(source, settings=_settings_for(content), spec=spec))
    _print_report(report)
    if html:
        html.write_text(render_html(report, source_name=Path(source).name), encoding="utf-8")
        typer.echo(f"html report: {html}")
    if json_path:
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"json report: {json_path}")
    raise typer.Exit(0 if report.verdict.value != "fail" else 1)


@app.command()
def bench(corpus: Path = typer.Option(None, "--corpus",
                                      help="Directory with labels.json (default: synthetic corpus)."),
          json_out: bool = typer.Option(False, "--json", help="Print the JSON result.")) -> None:
    """Measure detector precision/recall on a labelled corpus (synthetic by default)."""
    import json as _json

    from ..bench import load_corpus, run_bench, synthetic_bench

    if corpus:
        res = asyncio.run(run_bench(load_corpus(corpus)))
    else:
        with tempfile.TemporaryDirectory(prefix="audel-bench-") as td:
            res = synthetic_bench(Path(td))
    if json_out:
        typer.echo(_json.dumps(res.to_dict(), indent=2))
    else:
        typer.echo(f"{res.exact}/{res.cases} cases graded exactly")
        typer.echo(f"  {'check':<22}{'tp':>4}{'fn':>4}{'fp':>4}  precision  recall")
        for k, v in sorted(res.per_check.items()):
            pr = "-" if v.precision is None else f"{v.precision:.2f}"
            rc = "-" if v.recall is None else f"{v.recall:.2f}"
            typer.echo(f"  {k:<22}{v.tp:>4}{v.fn:>4}{v.fp:>4}  {pr:>9}  {rc:>6}")
        for m in res.misses:
            typer.echo(f"  miss: {m['case']}: expected {m['expected']}, raised {m['raised']}")
    raise typer.Exit(0 if res.exact == res.cases else 1)


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
    """Start the REST service (needs the serve extra). Loopback is zero-config; a routable bind
    refuses to start without auth (AUDEL_API_TOKEN, AUDEL_API_TOKENS_FILE or a JWKS)."""
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
