"""Golden-corpus benchmark — measure how often Audel's deterministic checks are right.

Two modes:

* **Synthetic** (default): generates a labelled corpus of short clips with known defects
  (loudness misses, true-peak overs, clipping, dead / inverted / out-of-phase channels, DC offset,
  mains hum, hiss, silence gaps, truncation, multi-track faults) and grades each one. Fully
  deterministic (seeded), no network, no keys. This proves the detectors fire on what they claim
  and stay quiet on clean material; it does not prove field accuracy.
* **Your corpus**: ``audel bench --corpus DIR`` reads ``DIR/labels.json``::

      [{"file": "promo_017.wav", "spec": "ebu_r128_s1", "content": "mixed",
        "expect": ["max_short_term"]}]

  ``expect`` lists the ``detail.check`` names a correct grade must raise; anything else raised is
  counted as a false positive. This is how a team measures Audel on its own deliverables before
  trusting it as a gate.

Results are per check: true positives, false negatives, false positives, precision and recall.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import wave
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .config import Settings, load_settings
from .errors import ConfigError
from .mediaguard import _tool

SR = 48000
_MAX_LABELS = 10_000


@dataclass
class Case:
    name: str
    file: Path
    expect: set[str]
    spec: str | None = "ebu_r128"
    content: str | None = None


@dataclass
class CheckScore:
    tp: int = 0
    fn: int = 0
    fp: int = 0

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return None if d == 0 else self.tp / d

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return None if d == 0 else self.tp / d


@dataclass
class BenchResult:
    cases: int = 0
    exact: int = 0                       # cases whose raised set == expected set
    per_check: dict[str, CheckScore] = field(default_factory=dict)
    misses: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cases": self.cases, "exact": self.exact,
            "per_check": {k: {"tp": v.tp, "fn": v.fn, "fp": v.fp, "precision": v.precision,
                              "recall": v.recall} for k, v in sorted(self.per_check.items())},
            "misses": self.misses,
        }


# --- synthetic signal generation --------------------------------------------------------------

def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def _speechlike(seconds: float, seed: int, tail_silence_s: float = 0.5) -> np.ndarray:
    """Band-limited noise (~100 Hz - 4 kHz, where voice energy lives) in syllable-rate bursts with
    phrase pauses, ending in a short silence like a real read."""
    rng = _rng(seed)
    n = int(SR * seconds)
    t = np.arange(n) / SR
    spec = np.fft.rfft(rng.normal(0.0, 1.0, n))
    f = np.fft.rfftfreq(n, 1 / SR)
    spec[(f < 100) | (f > 4000)] = 0.0
    y = np.fft.irfft(spec, n)
    env = (np.sin(2 * np.pi * 4.0 * t) ** 2) * ((t % 1.3) < 1.0)   # syllables + phrase pauses
    y = y * env
    if tail_silence_s > 0:
        y[-int(SR * tail_silence_s):] = 0.0
    return y


def _write(path: Path, x: np.ndarray) -> Path:
    x = np.atleast_2d(x.T).T if x.ndim == 1 else x  # (n,) -> (n,1)
    data = (np.clip(x, -1.0, 1.0) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(data.shape[1])
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(data.tobytes())
    return path


def _lufs(path: Path, ffmpeg: str) -> float:
    err = subprocess.run([ffmpeg, "-nostdin", "-hide_banner", "-i", str(path), "-af",
                          "ebur128=framelog=quiet", "-f", "null", "-"],
                         capture_output=True, text=True, check=False, timeout=60).stderr
    from .signals._parse import parse_ebur128

    v = parse_ebur128(err).get("I")
    if v is None or not np.isfinite(v):
        raise RuntimeError(f"could not measure {path}")
    return float(v)


def _normalized(path: Path, x: np.ndarray, target: float, ffmpeg: str,
                ceiling: float = 0.7) -> Path:
    """Write ``x`` scaled to exactly ``target`` LUFS integrated, soft-limited (like a real master)
    so sample peaks stay under ``ceiling`` and true peak stays under typical spec ceilings."""
    peak = float(np.max(np.abs(x))) or 1.0
    x = x * (0.25 / peak)
    for _ in range(6):
        _write(path, x)
        x = x * 10 ** ((target - _lufs(path, ffmpeg)) / 20)
        if float(np.max(np.abs(x))) > ceiling:
            x = ceiling * np.tanh(x / ceiling)  # soft knee: loud peaks squeezed, body untouched
        else:
            break
    _write(path, x)
    _write(path, x * 10 ** ((target - _lufs(path, ffmpeg)) / 20))
    return path


def build_synthetic_corpus(out: Path) -> list[Case]:
    ffmpeg = _tool("ffmpeg")
    out.mkdir(parents=True, exist_ok=True)
    cases: list[Case] = []
    d = 6.0
    sp = _speechlike(d, 1)
    n = sp.size
    t = np.arange(n) / SR

    def add(name, x, target, expect, spec="ebu_r128", content=None):
        p = out / f"{name}.wav"
        if target is None:
            _write(p, x)
        else:
            _normalized(p, x, target, ffmpeg)
        cases.append(Case(name, p, set(expect), spec, content))

    stereo = lambda left, right: np.stack([left, right], axis=1)  # noqa: E731
    add("clean_r128", stereo(sp, _speechlike(d, 2)), -23.0, [])
    add("loud_r128", stereo(sp, _speechlike(d, 2)), -18.0, ["integrated_loudness"])
    add("quiet_r128", stereo(sp, _speechlike(d, 2)), -28.0, ["integrated_loudness"])
    add("clean_atsc", stereo(sp, _speechlike(d, 2)), -24.0, [], spec="atsc_a85")

    p = out / "tp_over.wav"
    _normalized(p, stereo(sp, _speechlike(d, 2)), -23.0, ffmpeg)
    with wave.open(str(p), "rb") as w:
        raw = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").reshape(-1, 2).astype(float) / 32767
    # A smooth 2 ms transient to ~-0.45 dBFS: over the -1 dBTP ceiling, under full scale.
    bump = 0.95 * np.hanning(96)
    i0 = int(SR * 3.0)
    raw[i0:i0 + 96, 0] = bump
    _write(p, raw)
    cases.append(Case("tp_over", p, {"true_peak_ceiling"}))

    hot = np.clip(stereo(sp, _speechlike(d, 2)) * 40, -1, 1)
    add("clipped", hot, None, ["clipping", "integrated_loudness"])

    add("dead_right", stereo(sp, np.zeros(n)), -23.0, ["dead_channel"])
    add("polarity_inverted", stereo(sp, -sp), -23.0, ["polarity_inversion"])
    add("phase_partial", stereo(sp, -0.8 * sp + 0.25 * _speechlike(d, 3)), -23.0, ["phase"])
    add("dc_offset", stereo(sp + 0.0, _speechlike(d, 2)) + 0.0, -23.0, [])
    # DC is added after normalisation so the loudness target still holds
    p = out / "dc_offset.wav"
    with wave.open(str(p), "rb") as w:
        raw = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").reshape(-1, 2).astype(float) / 32767
    raw[:, 0] += 0.05
    _write(p, raw)
    cases[-1] = Case("dc_offset", p, {"dc_offset"})

    hum50 = sp + 0.03 * np.sin(2 * np.pi * 50 * t) + 0.01 * np.sin(2 * np.pi * 100 * t)
    add("hum_50hz", hum50, -23.0, ["hum"])
    hum60 = sp + 0.03 * np.sin(2 * np.pi * 60 * t) + 0.01 * np.sin(2 * np.pi * 120 * t)
    add("hum_60hz", hum60, -23.0, ["hum"])
    bass = 0.6 * np.sin(2 * np.pi * 55 * t) * ((t % 2.0) < 1.2) + 0.4 * sp
    add("bass_music", bass, -23.0, [])

    add("clean_podcast", sp, -16.0, [], spec="podcast")
    hiss = sp + 0.02 * _rng(9).normal(0.0, 1.0, n)
    add("hiss_podcast", hiss, -16.0, ["noise_floor"], spec="podcast")

    gap = sp.copy()
    gap[int(SR * 2.0):int(SR * 4.5)] = 0.0
    add("silence_gap", gap, -23.0, ["silence_gap"])
    add("silent", np.zeros(n), None, ["silent_track"])

    # Cut mid-word: the read stops while a syllable is at full level (no decay, no tail silence).
    trunc = _speechlike(d, 4, tail_silence_s=0)
    active = trunc[np.abs(trunc) > 0]
    word = _rng(5).normal(0, 1.0, int(SR * 0.4))
    word *= float(np.sqrt(np.mean(active ** 2))) / (float(np.sqrt(np.mean(word ** 2))) or 1.0)
    trunc[-word.size:] = word
    add("truncated", trunc, -23.0, ["truncation"])

    # Short-form: integrated on target, but a 4 s passage far above the s1 short-term ceiling.
    # 9 dB burst over 3.5 s of a 24 s spot: I ≈ base + 3 LU, so at I = -23 the burst reads ≈ -17
    # LUFS short-term, over the -18 ceiling.
    adv = np.concatenate([_speechlike(10.0, 6, 0), 2.82 * _speechlike(3.5, 7, 0),
                          _speechlike(10.5, 8)])
    add("ad_short_term", adv, -23.0, ["max_short_term"], spec="ebu_r128_s1")

    # Multi-track: track 0 clean, track 1 (e.g. an M&E or second language) silent.
    t0 = _normalized(out / "_mt0.wav", stereo(sp, _speechlike(d, 2)), -23.0, ffmpeg)
    t1 = _write(out / "_mt1.wav", np.zeros((n, 2)))
    mt = out / "multitrack_silent_track.mkv"
    subprocess.run([ffmpeg, "-nostdin", "-v", "error", "-y", "-i", str(t0), "-i", str(t1),
                    "-map", "0:a", "-map", "1:a", "-c:a", "pcm_s16le",
                    "-metadata:s:a:0", "language=eng", "-metadata:s:a:1", "language=spa",
                    str(mt)], check=True, timeout=60)
    cases.append(Case("multitrack_silent_track", mt, {"silent_track"}))
    return cases


def load_corpus(root: Path) -> list[Case]:
    """Read ``root/labels.json``. Every file must resolve INSIDE ``root`` (no traversal)."""
    root = root.expanduser().resolve()
    labels = root / "labels.json"
    if not labels.is_file():
        raise ConfigError(f"no labels.json in {root}")
    try:
        data = json.loads(labels.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ConfigError(f"unreadable labels.json: {type(e).__name__}") from e
    if not isinstance(data, list) or len(data) > _MAX_LABELS:
        raise ConfigError(f"labels.json must be a list of at most {_MAX_LABELS} entries")
    cases = []
    for i, row in enumerate(data):
        if not isinstance(row, dict) or not isinstance(row.get("file"), str):
            raise ConfigError(f"labels.json entry {i} needs a 'file' string")
        try:
            f = (root / row["file"]).resolve()
        except (ValueError, OSError) as e:
            raise ConfigError(f"labels.json entry {i}: invalid file name") from e
        spec = row.get("spec")
        if spec is not None:
            from .specs import BUILTIN_SPECS

            if not isinstance(spec, str) or spec.strip().lower() not in BUILTIN_SPECS:
                raise ConfigError(f"labels.json entry {i}: spec must be a built-in name")
        if root not in f.parents:
            raise ConfigError(f"labels.json entry {i} points outside the corpus directory")
        expect = row.get("expect", [])
        if not isinstance(expect, list) or not all(isinstance(e, str) for e in expect):
            raise ConfigError(f"labels.json entry {i}: 'expect' must be a list of check names")
        cases.append(Case(name=row.get("name") or f.name, file=f, expect=set(expect),
                          spec=spec, content=row.get("content")))
    return cases


async def run_bench(cases: list[Case], settings: Settings | None = None) -> BenchResult:
    from .core import check

    base = settings or load_settings()
    res = BenchResult()
    for c in cases:
        s = base.model_copy(update={"content_type": c.content}) if c.content else base
        report = await check(str(c.file), settings=s, spec=c.spec)
        raised: set[str] = {str(i.detail["check"]) for i in report.issues if i.detail.get("check")}
        res.cases += 1
        res.exact += int(raised == c.expect)
        for chk in c.expect | raised:
            sc = res.per_check.setdefault(chk, CheckScore())
            if chk in c.expect and chk in raised:
                sc.tp += 1
            elif chk in c.expect:
                sc.fn += 1
            else:
                sc.fp += 1
        if raised != c.expect:
            res.misses.append({"case": c.name, "expected": sorted(c.expect), "raised": sorted(raised)})
    return res


def synthetic_bench(workdir: Path, settings: Settings | None = None) -> BenchResult:
    return asyncio.run(run_bench(build_synthetic_corpus(workdir), settings))
