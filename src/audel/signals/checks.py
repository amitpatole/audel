"""Turn :class:`Measurements` into time-grounded :class:`audel.models.Issue` objects.

Deterministic only — no LLM, no network. Each issue carries a ``span`` (ms) so an agent or an
operator can jump to the exact moment, and ``detail["check"]`` names the precise rule (the
``kind`` stays within the shared audio vocabulary so every consumer of the contract, Verel
included, understands it). Thresholds come from the :class:`~audel.specs.DeliverySpec` and
Settings — never from code.
"""

from __future__ import annotations

import math

import numpy as np

from ..config import Settings
from ..models import Confidence, Issue, IssueKind, IssueSource, Severity, Span
from ..specs import ContentType, DeliverySpec, Gating, Strictness, legacy_spec, resolve_spec
from .measure import SERIES_HZ, Measurements, TrackMeasurements

_TRUNCATION_TAIL_DBFS = -25.0   # tail RMS louder than this with no trailing silence => maybe cut
_TRUNCATION_REL_DB = 3.0        # ... and within this of the track's overall RMS
_FULL_SILENCE_FRACTION = 0.98   # a single silence covering ~all of the file = dead audio
_DEAD_CHANNEL_MARGIN_DB = 10.0  # a channel this far below the floor while the track is live = dead
_DC_OFFSET_LIMIT = 0.01         # |DC| above 1 % of full scale
_PHASE_SIDE_OVER_MID_DB = 3.0   # side this much louder than mid = anti-correlated pair
_HUM_MIN_DBFS = -70.0           # hum band median must be at least this loud to matter
_HUM_MAX_SPREAD_DB = 6.0        # ... and steady (p90 - p10 of the band series)
_HUM_FLOOR_DOMINANCE_DB = -6.0  # ... and carry the quiet passages (band ≥ total - 6 dB there)
_MAX_SPANS = 20                 # cap per-rule spans (report size bound on pathological media)


def effective_spec(settings: Settings, spec: DeliverySpec | str | None = None) -> DeliverySpec:
    resolved = resolve_spec(spec) if spec is not None else resolve_spec(settings.delivery_spec)
    return resolved or legacy_spec(settings.loudness_target, settings.clipping_dbtp)


def effective_content(settings: Settings, spec: DeliverySpec) -> ContentType:
    if settings.content_type:
        try:
            return ContentType(settings.content_type.strip().lower())
        except ValueError:
            pass
    return spec.content or ContentType.MIXED


def _ms(s: float) -> int:
    return int(max(0.0, s) * 1000)


def _full_span(dur_s: float) -> Span:
    return Span(start_ms=0, end_ms=_ms(dur_s))


def _span(start_s: float, end_s: float, dur_s: float) -> Span:
    if end_s < 0:
        end_s = dur_s
    return Span(start_ms=_ms(start_s), end_ms=_ms(max(start_s, end_s)))


def _frame_spans(frames, pick, limit: float, window_s: float) -> list[tuple[float, float, float]]:
    """Merge consecutive frames whose value exceeds ``limit`` into (start_s, end_s, worst) spans."""
    spans: list[list[float]] = []
    for t, *vals in frames:
        v = pick(vals)
        if v is None or v == -math.inf or v <= limit:
            continue
        start = max(0.0, t - window_s)
        if spans and start <= spans[-1][1] + 0.11:
            spans[-1][1] = t
            spans[-1][2] = max(spans[-1][2], v)
        else:
            spans.append([start, t, v])
    return [(a, b, c) for a, b, c in spans]


def _track_label(tm: TrackMeasurements, multi: bool) -> str:
    if not multi:
        return ""
    lang = f" [{tm.stream.language}]" if tm.stream.language else ""
    return f"track {tm.stream.index}{lang}: "


def _issue(kind, sev, msg, span, check, tm, *, conf=Confidence.HIGH, **detail) -> Issue:
    return Issue.make(kind, sev, msg, span=span, source=IssueSource.DSP, confidence=conf,
                      detail={"check": check, "stream": tm.stream.index, **detail})


def _silence(tm, dur, settings, label) -> tuple[list[Issue], bool]:
    silent_total = sum((e if e >= 0 else dur) - s for s, e in tm.silences)
    rms_silent = tm.rms_dbfs is not None and (tm.rms_dbfs == -math.inf or tm.rms_dbfs <= settings.silence_dbfs)
    if (dur > 0 and silent_total >= _FULL_SILENCE_FRACTION * dur) or rms_silent:
        return [_issue(IssueKind.SILENCE, Severity.CRITICAL, f"{label}audio is silent throughout",
                       _full_span(dur), "silent_track", tm, rms_dbfs=tm.rms_dbfs)], True
    out = []
    for s, e in tm.silences:
        gap = (e if e >= 0 else dur) - s
        if gap >= 1.5:
            out.append(_issue(IssueKind.SILENCE, Severity.WARNING, f"{label}{gap:.1f}s of silence",
                              _span(s, e, dur), "silence_gap", tm, conf=Confidence.MEDIUM,
                              gap_s=round(gap, 2)))
    return out, False


def _peaks(tm, dur, spec, label) -> list[Issue]:
    tp = tm.true_peak_dbtp
    if tp is None or tp == -math.inf or tp <= spec.max_true_peak_dbtp:
        return []
    spans = _frame_spans(tm.frames, lambda v: v[2], spec.max_true_peak_dbtp, 0.1)[:_MAX_SPANS]
    clipped = tp >= 0.0
    what = "clipping (true peak at or above full scale)" if clipped else "over the true-peak ceiling"
    msg = (f"{label}true peak {tp:.1f} dBTP exceeds {spec.max_true_peak_dbtp:.1f} dBTP "
           f"({spec.name}): {what}")
    first = _span(spans[0][0], spans[0][1], dur) if spans else _full_span(dur)
    return [_issue(IssueKind.CLIPPING, Severity.ERROR, msg, first,
                   "clipping" if clipped else "true_peak_ceiling", tm, true_peak_dbtp=tp,
                   ceiling_dbtp=spec.max_true_peak_dbtp, spec=spec.name,
                   occurrences=len(spans),
                   spans_ms=[[_ms(a), _ms(b)] for a, b, _ in spans])]


def _loudness(tm, dur, spec, label) -> list[Issue]:
    out: list[Issue] = []
    sev = Severity.ERROR if spec.strictness is Strictness.REJECT else Severity.WARNING
    measured, basis, conf = tm.integrated_lufs, "programme", Confidence.HIGH
    if spec.gating is Gating.DIALOGUE:
        if tm.dialogue_lufs is not None:
            measured, basis, conf = tm.dialogue_lufs, "speech-gated", Confidence.MEDIUM
        else:
            conf = Confidence.LOW  # gating unavailable: graded on programme loudness, flagged
    if measured is not None and measured != -math.inf:
        delta = measured - spec.integrated_lufs
        if abs(delta) > spec.tolerance_lu:
            direction = "louder" if delta > 0 else "quieter"
            out.append(_issue(
                IssueKind.LOUDNESS, sev,
                f"{label}integrated loudness ({basis}) {measured:.1f} LUFS is {abs(delta):.1f} LU "
                f"{direction} than the {spec.name} target ({spec.integrated_lufs:.0f} ±"
                f"{spec.tolerance_lu:g} LU)",
                _full_span(dur), "integrated_loudness", tm, conf=conf, lufs=measured,
                target_lufs=spec.integrated_lufs, tolerance_lu=spec.tolerance_lu, basis=basis,
                spec=spec.name, dialogue_coverage=tm.dialogue_coverage))
    for limit, idx, window, name, check in (
        (spec.max_short_term_lufs, 1, 3.0, "short-term", "max_short_term"),
        (spec.max_momentary_lufs, 0, 0.4, "momentary", "max_momentary"),
    ):
        if limit is None:
            continue
        spans = _frame_spans(tm.frames, lambda v, i=idx: v[i], limit, window)[:_MAX_SPANS]
        if spans:
            worst = max(s[2] for s in spans)
            out.append(_issue(
                IssueKind.LOUDNESS, sev,
                f"{label}{name} loudness peaks at {worst:.1f} LUFS, over the {spec.name} maximum "
                f"of {limit:.0f} LUFS ({len(spans)} passage(s))",
                _span(spans[0][0], spans[0][1], dur), check, tm, max_lufs=worst, limit_lufs=limit,
                spec=spec.name, occurrences=len(spans),
                spans_ms=[[_ms(a), _ms(b)] for a, b, _ in spans]))
    if spec.max_lra_lu is not None and tm.lra is not None and tm.lra > spec.max_lra_lu:
        out.append(_issue(IssueKind.LOUDNESS, Severity.WARNING,
                          f"{label}loudness range {tm.lra:.1f} LU exceeds {spec.max_lra_lu:g} LU "
                          f"({spec.name})", _full_span(dur), "loudness_range", tm,
                          lra=tm.lra, limit_lu=spec.max_lra_lu, spec=spec.name))
    return out


def _truncation(tm, dur, label) -> list[Issue]:
    ends_silent = any((e < 0 or abs((e if e >= 0 else dur) - dur) < 0.2) for _, e in tm.silences)
    tail = tm.tail_rms_dbfs
    # A cut ends at PROGRAMME level (the tail is about as loud as the track overall), not merely
    # above an absolute floor — a steady noise bed or hum tail is not a truncation.
    level = tm.rms_dbfs if tm.rms_dbfs is not None and math.isfinite(tm.rms_dbfs) else None
    at_programme_level = level is None or (tail is not None and tail >= level - _TRUNCATION_REL_DB)
    if (tail is not None and tail != -math.inf and tail > _TRUNCATION_TAIL_DBFS
            and at_programme_level and not ends_silent and dur > 0.5):
        end_ms = _ms(dur)
        return [_issue(IssueKind.TRUNCATION, Severity.WARNING,
                       f"{label}audio ends at high energy with no trailing silence — possibly cut off",
                       Span(start_ms=max(0, end_ms - 250), end_ms=end_ms), "truncation", tm,
                       conf=Confidence.LOW, tail_rms_dbfs=tail)]
    return []


def _channels(tm, dur, settings, label) -> list[Issue]:
    out: list[Issue] = []
    live = tm.rms_dbfs is not None and tm.rms_dbfs != -math.inf and tm.rms_dbfs > settings.silence_dbfs
    if live and len(tm.channels) >= 2:
        for ch in tm.channels:
            if ch.label == "LFE":
                continue  # an empty LFE is normal for dialogue-led mixes
            dead = ch.rms_dbfs is None or ch.rms_dbfs == -math.inf or \
                ch.rms_dbfs <= settings.silence_dbfs - _DEAD_CHANNEL_MARGIN_DB
            if dead:
                out.append(_issue(IssueKind.CHANNEL_ISSUE, Severity.ERROR,
                                  f"{label}channel {ch.label} is silent while the track is live",
                                  _full_span(dur), "dead_channel", tm, channel=ch.label,
                                  rms_dbfs=ch.rms_dbfs))
    for ch in tm.channels:
        if ch.dc_offset is not None and math.isfinite(ch.dc_offset) and abs(ch.dc_offset) > _DC_OFFSET_LIMIT:
            out.append(_issue(IssueKind.CHANNEL_ISSUE, Severity.WARNING,
                              f"{label}channel {ch.label} has a DC offset of {ch.dc_offset:+.3f}",
                              _full_span(dur), "dc_offset", tm, channel=ch.label,
                              dc_offset=ch.dc_offset))
    mid, side = tm.mid_rms_dbfs, tm.side_rms_dbfs
    if live and mid is not None and side is not None and side != -math.inf:
        mid_v = -150.0 if mid == -math.inf else mid
        if mid_v <= settings.silence_dbfs and side > settings.silence_dbfs + _DEAD_CHANNEL_MARGIN_DB:
            out.append(_issue(IssueKind.CHANNEL_ISSUE, Severity.ERROR,
                              f"{label}left/right are polarity-inverted copies: the programme "
                              "cancels to silence when folded down to mono", _full_span(dur),
                              "polarity_inversion", tm, mid_rms_dbfs=mid, side_rms_dbfs=side))
        elif side - mid_v > _PHASE_SIDE_OVER_MID_DB:
            out.append(_issue(IssueKind.CHANNEL_ISSUE, Severity.WARNING,
                              f"{label}left/right are largely out of phase (side {side - mid_v:.1f} "
                              "dB above mid); content will thin out in mono", _full_span(dur),
                              "phase", tm, conf=Confidence.MEDIUM, mid_rms_dbfs=mid,
                              side_rms_dbfs=side))
    return out


def _hum(tm, dur, settings, content, label) -> list[Issue]:
    if not settings.hum_detection or content is ContentType.MUSIC:
        return []
    total = np.asarray(tm.series_total, dtype=float)
    if total.size < 2 * SERIES_HZ:
        return []
    out: list[Issue] = []
    for freq, series in ((50, tm.series_50), (60, tm.series_60)):
        band = np.asarray(series, dtype=float)
        n = min(band.size, total.size)
        if n < 2 * SERIES_HZ:
            continue
        b, t = band[:n], total[:n]
        # Hum is a steady FLOOR: judge level and steadiness on the quiet half of the band series
        # (programme content only ever adds energy above it), and require that the band carries
        # the quietest passages of the full-band signal.
        med = float(np.percentile(b, 25))
        spread = float(np.percentile(b, 50) - np.percentile(b, 10))
        quiet = t <= np.percentile(t, 20)
        dominance = float(np.median(b[quiet] - t[quiet])) if quiet.any() else -150.0
        if med > _HUM_MIN_DBFS and spread < _HUM_MAX_SPREAD_DB and dominance >= _HUM_FLOOR_DOMINANCE_DB:
            out.append(_issue(IssueKind.NOISE, Severity.WARNING,
                              f"{label}{freq} Hz mains hum at {med:.0f} dBFS, steady across the "
                              "programme and dominant in the quiet passages", _full_span(dur),
                              "hum", tm, conf=Confidence.MEDIUM, frequency_hz=freq,
                              level_dbfs=round(med, 1), spread_db=round(spread, 1)))
    return out


def _noise_floor(tm, dur, settings, content, label, hum_found: bool = False) -> list[Issue]:
    if content is not ContentType.SPEECH:
        return []
    total = np.asarray(tm.series_total, dtype=float)
    if total.size < 2 * SERIES_HZ:
        return []
    floor = float(np.percentile(total, 5))
    if floor > settings.noise_floor_dbfs:
        snr = float(np.percentile(total, 95)) - floor
        return [_issue(IssueKind.NOISE, Severity.WARNING,
                       f"{label}noise floor {floor:.0f} dBFS in the quietest passages (estimated "
                       f"SNR {snr:.0f} dB); "
                       + ("the mains hum above is the likely cause" if hum_found
                          else "background noise or hiss is likely audible"),
                       _full_span(dur), "noise_floor", tm, conf=Confidence.MEDIUM,
                       noise_floor_dbfs=round(floor, 1), snr_db=round(snr, 1))]
    return []


def evaluate(m: Measurements, settings: Settings, spec: DeliverySpec | str | None = None) -> list[Issue]:
    issues: list[Issue] = []
    dur = m.info.duration_s

    if not m.info.has_audio:
        issues.append(Issue.make(IssueKind.MISSING_AUDIO, Severity.CRITICAL,
                                 "no audio stream in the media", span=_full_span(dur),
                                 source=IssueSource.DSP, detail={"check": "missing_audio"}))
        return issues

    sp = effective_spec(settings, spec)
    content = effective_content(settings, sp)
    multi = len(m.tracks) > 1
    for tm in m.tracks:
        label = _track_label(tm, multi)
        found, dead = _silence(tm, dur, settings, label)
        issues.extend(found)
        if dead:
            continue  # nothing else is meaningful on a dead track
        issues.extend(_peaks(tm, dur, sp, label))
        issues.extend(_loudness(tm, dur, sp, label))
        issues.extend(_truncation(tm, dur, label))
        issues.extend(_channels(tm, dur, settings, label))
        hum = _hum(tm, dur, settings, content, label)
        issues.extend(hum)
        issues.extend(_noise_floor(tm, dur, settings, content, label, hum_found=bool(hum)))
    return issues
