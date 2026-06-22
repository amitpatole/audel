# Audel — KICKOFF / Build Plan

> **Audel — Ears for AI Agents 👂**
> A machine-graded **audio** feedback loop coding agents consume to self-correct before claiming *done*.
>
> Sibling to **[AgentVision](https://amitpatole.github.io/agent-vision/)** (eyes) and **[Verel](https://amitpatole.github.io/verel/)** (brain).
> AgentVision: *render → see → report → fix.*  Audel: **play → hear → report → fix.**
> The eyes confirm a video *renders*; **Audel confirms it actually has sound and the narration is right.**

> ✅ **Name locked: `audel`** — *audits audio* (Verel verifies reasoning; Audel audits audio). `audel`
> appears free on PyPI, so import name = distribution name = CLI = `audel`. Claim it before Phase 0.
> *(Swap to `sonel` is trivial if you prefer the sound over the pun.)*

---

## 1. Thesis (why this exists)

AI coding agents are **deaf**: they generate TTS, music, video soundtracks, web-app sound effects, IVR/voice-bot prompts, audiobooks, and transcode outputs — and never *hear* the result, shipping silent tracks, truncated speech, wrong-language narration, clipping, and dead audio channels they can't perceive. Audel gives them ears: **play → hear → report → fix**, so the agent self-corrects before it claims done. The output is a machine **verdict** (`pass`/`warn`/`fail`) with **time-grounded** issues — the audio analog of AgentVision's coordinate-grounded issues.

It is **not** an ambient room mic. It's a grader for audio artifacts, built to drop into the Verel verdict bus exactly where the eyes already plug in.

---

## 2. One contract with the eyes (this is what makes the trio click)

Audel must emit the **same `Report` / `Handoff` shape AgentVision emits**, so Verel ingests the ears identically to the eyes. AgentVision defines these in `agentvision.models.*` (`Report`, `Issue`, `Conformance`, `ClaimResult`, `Brief`, `IntentClaim`, `Handoff`, verdict `pass|warn|fail`). Audel reuses that contract.

**Decision — extract a shared contract package `agentsense`** holding the verdict/report/intent/handoff models + the `Sense` protocol, depended on by `agentvision`, `audel`, and `verel`:

```
        ┌──────────── agentsense (shared contract) ────────────┐
        │ Verdict · Report · Issue · Conformance · ClaimResult │
        │ Brief · IntentClaim · Importance · Handoff · Sense   │
        └──────────────────────────────────────────────────────┘
              ▲                  ▲                  ▲
        agentvision           audel              verel
          (eyes)             (ears)             (brain)
```

- Refactor is small: move `agentvision.models.*` into `agentsense`, re-export from `agentvision.models` for back-compat.
- **Fallback (zero coordination):** Audel re-declares structurally-identical pydantic models and ships a CI conformance test asserting its `Handoff` is schema-compatible with AgentVision's. Works, but invites drift — prefer the shared package.

The only audio-specific divergence: **`Issue` is time-grounded** (`span: {start_ms, end_ms}`) where the eyes are bbox-grounded. Keep that as an optional grounding union in the shared `Issue` (`bbox | span | None`).

---

## 3. Public API — mirrors AgentVision one-to-one

High-level entry points are **async**, return a `Report`. Same names, same call shape; `source` is audio / video / a URL / raw waveform.

```python
import asyncio
from audel import analyze, load_settings

async def main():
    report = await analyze("dist/intro.mp4", settings=load_settings(audio_backend="local"))
    print(report.verdict, [i.message for i in report.issues])

asyncio.run(main())
```

| AgentVision | Audel | Audio meaning |
|---|---|---|
| `analyze(source, *, brief, backend, expected, …) -> Report` | `analyze(...) -> Report` | decode/play → DSP + ASR grounding **+** backend (audio-LLM/transcript) critique; with `brief`, gate verdict on conformance |
| `check(source, *, brief, …) -> Report` | `check(...) -> Report` | **deterministic, no LLM, no egress** — silence/clipping/LUFS/truncation/decode/duration + ASR transcript vs `must:` text claims |
| `watch(source, *, frames, interval_ms, …) -> Report` | `watch(...) -> Report` | temporal: does it **play through**, sound fires on event, no dropouts, A/V sync (liveness over time) |
| `render(source, …) -> RenderResult` | `render(...) -> RenderResult` | decode/play to **waveform + trustworthy signals** (peaks, LUFS, VAD segments, spectrogram, transcript) — the DOM/CV analog |
| `compute_diff(baseline, candidate) -> DiffResult` | `compute_diff(...) -> DiffResult` | waveform + transcript + loudness diff between two renders |

Same session + intent + handoff surface:

```python
from audel import LoopSession, GenerativeLoopSession
from audel import Brief, IntentClaim                 # from agentsense
from audel import Report, Issue, Conformance, Handoff

brief = Brief.from_inputs(
    text="30s product intro, warm female VO, ends on a chime",
    expect=[
        'must: narration says "welcome to Audel"',
        'must: language is en',
        'must: duration < 32s',
        'should: no clipping',
        'must: contains a chime sound at the end',   # non-speech → CLAP
    ],
)
report  = await analyze("intro.mp4", brief=brief, backend="gemini-audio")
handoff = report.to_handoff()        # {verdict, next_action, todo, open_questions} for the brain
report.issue_signature()             # stuck/progress detection across fix iterations
```

`Conformance.score` (fraction of claims satisfied) and `Conformance.matches_intent()` (no `must` violated/uncertain) behave exactly as in AgentVision.

---

## 4. What Audel actually grades

**Source types (`source_type='auto'`):** audio files (wav/mp3/flac/ogg/m4a), video (extract audio track), a URL / local web app (play headless, capture audio), raw `numpy` waveform, a TTS endpoint's bytes.

**Deterministic signals (the `check` path — no LLM, the "trustworthy grounding"):**
- decode validity (corrupt / empty / wrong codec) · missing audio track · dead/mono channel
- **silence** detection (all-silent, or gaps where speech is expected)
- **clipping** / true-peak (dBTP) · **integrated loudness** (LUFS) + LRA vs target (broadcast −16/−14, etc.)
- **truncation** (cut off mid-word) · **dropouts**/glitches · **A/V desync**
- duration / sample-rate / channel sanity · SNR / noise floor
- **ASR transcript** → match against `must:` text claims; **language** detection

**Backend (the `analyze` path — optional LLM):** audio-native models (Gemini audio, GPT-4o-audio) or transcript-fed text LLMs critique naturalness/tone and grade non-deterministic `must`/`should` claims. **CLAP** does zero-shot non-speech conformance ("contains a chime / doorbell / alarm").

**Issue kinds (each time-grounded):** `silence` · `clipping` · `loudness` · `truncation` · `dropout` · `decode_error` · `missing_audio` · `desync` · `transcript_mismatch` · `wrong_language` · `noise` · `channel_issue` · `duration`.

```jsonc
// Issue (audio)
{ "kind": "transcript_mismatch", "severity": "error",
  "span": { "start_ms": 30120, "end_ms": 31040 },
  "message": "expected 'welcome to Audel', heard 'welcome to oral'",
  "evidence": { "expected": "...", "heard": "...", "confidence": 0.82 } }
```

---

## 5. Backends (pluggable, mirror `VisionBackend`)

```python
# agentsense / audel.backends.base
class AudioBackend(Protocol):
    async def transcribe(self, audio: Waveform, *, language: str | None = None) -> Transcript: ...
    async def complete_text(self, system: str, user: str) -> str: ...   # claim extraction / critique
    async def critique_audio(self, audio: Waveform, prompt: str) -> str: ...  # audio-native LLMs; else ""
```

Offline **`local`** backend: faster-whisper for `transcribe`, returns `""` for the LLM methods (exactly as AgentVision's local backend returns `""` from `complete_text`). Backends register via entry points (`audel.backends`), so third parties ship `audel-backend-foo` and `analyze(backend="foo")` resolves it.

---

## 6. PyPI packaging (mirror AgentVision conventions)

`src/` layout · PEP 621 · hatchling · pydantic (`BaseModel`/`BaseSettings`) · `py.typed` · async entry points · env prefix **`AUDEL_`** (provider keys keep their conventional names).

| Install | Pulls in |
|---|---|
| `pip install audel` | core: decode (ffmpeg), DSP checks, schema, CLI, MCP, **no torch** |
| `audel[render]` | ffmpeg + Playwright/Chromium (play web apps, capture audio) |
| `audel[asr]` | faster-whisper (local deterministic ASR) |
| `audel[cloud]` | Deepgram / Groq / AssemblyAI / Gemini-audio backends |
| `audel[clap]` | CLAP zero-shot non-speech conformance |
| `audel[all]` | everything |

Heavy deps **lazy-imported** inside backends. `import audel` stays fast.

**CLI / adapters (parallel to AgentVision):**
```bash
audel demo        # plays a deliberately broken clip (silent gap + truncated VO + wrong-language +
                  # clipping), prints FAIL with time-grounded issues, then the fixed clip → PASS. No API key.
audel doctor      # check ffmpeg, audio backends, Chromium
audel check  intro.mp4
audel analyze intro.mp4 --brief "30s intro" --expect 'must: language is en'
audel watch  http://localhost:3000 --frames 20 --interval-ms 500   # sound-fires / playback liveness
audel diff   old.wav new.wav
audel mcp         # MCP server: hear_check / hear_analyze / hear_watch / hear_diff / hear_status
```
Adapters: **CLI / MCP / REST / Skill** — same four as AgentVision.

---

## 7. Repo layout

```
audel/
├── pyproject.toml                 # extras, entry points, AUDEL_ settings
├── src/audel/
│   ├── __init__.py                # analyze, check, watch, render, compute_diff, models (lazy heavy deps)
│   ├── core/ {analyze, check, watch, render, diff, loop, generate}.py
│   ├── signals/ {decode, silence, clipping, loudness, truncation, vad, snr, desync}.py
│   ├── speech/ {asr, language, conformance}.py
│   ├── acoustic/ {clap}.py
│   ├── backends/ {base, local, deepgram, gemini_audio, registry}.py
│   ├── adapters/ {cli, mcp, rest, skill}.py
│   ├── models/                    # re-export from agentsense (+ audio Issue.span)
│   └── config.py                  # Settings(BaseSettings), load_settings
├── tests/fixtures/                # silent.wav, truncated.wav, clipping.wav, wrong_lang.mp3, good.mp4
└── .github/workflows/publish.yml  # Trusted Publishing (OIDC) → TestPyPI → PyPI
```

---

## 8. Phased tasks → TASKS.md

### Phase 0 — Contract + scaffold
- [ ] Claim PyPI dist name. Extract/establish **`agentsense`** (Verdict, Report, Issue w/ `span`, Conformance, ClaimResult, Brief, IntentClaim, Importance, Handoff, `Sense`); agentvision re-exports for back-compat.
- [ ] `audel` `src/` scaffold, `pyproject` (extras + entry points), depend on `agentsense`; lazy-import guard test (no torch on `import audel`).
- **Accept:** `import audel` is fast; `audel doctor` runs; Audel's `Handoff` passes a schema-compat test against AgentVision's.

### Phase 1 — render() + deterministic check()
- [ ] `signals/decode.py` (ffmpeg) → `Waveform` + base metrics; `render()` returns RenderResult (waveform + signals).
- [ ] silence / clipping / loudness(LUFS) / truncation / duration / channel checks → `Issue`s with `span`.
- [ ] `check()` assembles a `Report` (verdict from issues), `audel check` + `audel demo` (FAIL→PASS).
- **Accept:** `audel demo` prints time-grounded FAIL then PASS, no API key; fixtures grade correctly in CI.

### Phase 2 — Speech grading + conformance
- [ ] `speech/asr.py` (faster-whisper) + language detect; `AudioBackend` Protocol + `local` backend + registry.
- [ ] `speech/conformance.py`: grade `Brief`/`IntentClaim` text claims against transcript; populate `Conformance`.
- **Accept:** `check(source, brief=...)` fails on wrong-language / missing phrase / over-duration; `matches_intent()` correct.

### Phase 3 — analyze() with backends + CLAP
- [ ] Cloud/audio-LLM backends (`[cloud]`) behind registry; `analyze()` adds critique + non-deterministic claim grading.
- [ ] `acoustic/clap.py` (`[clap]`) for non-speech conformance ("contains a chime").
- **Accept:** `analyze(brief=...)` grades a tone/naturalness `should:` claim and a CLAP `must: contains <sound>` claim.

### Phase 4 — watch() temporal + web capture
- [ ] `core/watch.py`: playback liveness, dropout/desync over time; `[render]` Playwright path to play a URL and capture audio (ffmpeg file path first; headless web-audio capture is the hard part — document it).
- **Accept:** `watch` flags a video whose audio is silent though it "plays," and a button whose click sound never fires.

### Phase 5 — Loop + handoff + Verel
- [ ] `LoopSession`/`IterationResult`/`GenerativeLoopSession`; `Report.to_handoff()`, `issue_signature()` for stuck detection.
- [ ] Register Audel as a `verel.senses` sense feeding `verel.verdict`; one cross-modal demo (AgentVision: "video renders" + Audel: "audio plays & VO correct" → combined verdict).
- **Accept:** Verel gates "done" on Audel's verdict; eyes+ears co-grade one media artifact end-to-end.

### Phase 6 — Adapters + publish
- [ ] MCP / REST / Skill adapters; `audel mcp`. Finalize extras; verify light base wheel; document an external backend plugin.
- [ ] `publish.yml` → TestPyPI → PyPI (Trusted Publishing). README quickstart mirroring AgentVision's.
- **Accept:** clean-venv `pip install audel[render,asr,clap]` runs the quickstart; installs from TestPyPI.

### Phase 7 — Realtime polish (optional)
- [ ] Streaming verification (live voice-agent / call QA), metrics via `hear_status`, Docker, benchmarks.

---

## 9. Open decisions

1. **Dist name:** `audel` (import stays `audel`) vs `agentaural`.
2. **Shared contract:** extract `agentsense` (recommended) vs Audel-local mirror + conformance test.
3. **Default audio-LLM backend** for `analyze` (Gemini-audio / GPT-4o-audio / transcript+text-LLM).
4. **Loudness targets** preset list (broadcast −23/−16, podcast −16, streaming −14).
5. Confirm AgentVision's `Issue` can take an optional `span` grounding (vs a separate `AudioIssue`).

---

## 10. First message to paste into Claude Code

> Build **Audel — Ears for AI Agents**: a pip-installable Python package that grades audio/voice/media
> artifacts (`pass`/`warn`/`fail` with **time-grounded** issues) so coding agents self-correct before
> claiming done. It is the audio sibling of **AgentVision** (eyes) and plugs into **Verel** (brain) the
> same way the eyes do. Mirror AgentVision's public API exactly — async `analyze/check/watch/render/
> compute_diff`, `LoopSession`/`GenerativeLoopSession`, `Brief`/`IntentClaim`, `Report`/`Issue`/
> `Conformance`/`Handoff` (`to_handoff`, `issue_signature`), `AudioBackend` Protocol, `Settings`
> (`AUDEL_` prefix). Reuse the shared `agentsense` contract; `Issue` is time-grounded via `span`.
> Follow `KICKOFF.md`; start at Phase 0 then Phase 1. Python 3.10–3.12, `src/` layout, hatchling,
> pydantic, `py.typed`, async. Light base install (ffmpeg + DSP, no torch); ML behind extras
> (`[render]`,`[asr]`,`[cloud]`,`[clap]`), lazy-imported. Defaults: ffmpeg decode, faster-whisper
> local ASR, CLAP for non-speech conformance. Ship `audel demo` (broken clip → FAIL with time-grounded
> issues → fixed → PASS, no API key) and `audel doctor`. Write fixture tests per phase and stop at each
> phase's acceptance check for my review.
