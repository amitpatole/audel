# Audel — TASKS

> Execution checklist derived from `Audel_kickoff_plan.md`, **grounded against the real
> AgentVision v0.7.3 source** at `/home/amitpatole/Eyes_For_AI_Agents/src/agentvision`.
> Decisions resolved 2026-06-22. Build at `/home/amitpatole/WORKSPACE/Audel`.

## Locked decisions

1. **Dist/import/CLI name:** `audel`. ✅ **Reserved** — skeleton `0.0.1` published to PyPI
   2026-06-22 (https://pypi.org/project/audel/). Git repo: github.com/amitpatole/audel (private).
2. **Shared contract:** extract **`agentsense`**; `agentvision.models` re-exports for back-compat.
3. **Default `analyze` backend:** transcript + text-LLM. **Primary text critique = Ollama Cloud**
   (user has a Max plan = flat-rate, no per-token cost) via OpenAI-compatible `https://ollama.com/v1`,
   key at `~/.config/ollama/key`. Good models verified 2026-06-22: `gemma4:31b` (clean JSON, ~1.8s),
   `qwen3.5:397b`, `glm-5`, `deepseek-v3.2`; `gpt-oss:*` need reasoning-channel parsing (empty
   `content` field). Anthropic-Haiku stays as a fallback `complete_text` backend.
   - **AUDIO-NATIVE critique:** Ollama Cloud **cannot** do it — empirically, its API rejects audio
     input even for `gemini-3-flash-preview` (`"expected image mime type, got audio/wave"`); it only
     accepts `images`. So raw-waveform tone/naturalness critique still needs a true audio model
     (Gemini-audio / GPT-4o-audio) as an opt-in `[cloud]` backend. Most `must:`/`should:` claims are
     transcript-graded (Ollama, free) — reserve the paid audio model for prosody/naturalness claims.
   - ASR stays local faster-whisper (Ollama serves no ASR model).
4. **Loudness presets:** `LoudnessTarget` = streaming −14 / **podcast −16 (default)** /
   broadcast_ebu −23 / broadcast_us −24. Env: `AUDEL_LOUDNESS_TARGET`.
5. **Issue grounding:** add strict-schema-safe `Span{start_ms:int, end_ms:int}`;
   `agentsense.Issue.kind` is `str`; agentsense owns only cross-domain kinds
   (`INTENT_MISMATCH`, `OTHER`); each sense ships its own `IssueKind` str-enum.
6. **Python:** ≥3.11 (match AgentVision, not the doc's 3.10). `src/` + hatchling + pydantic v2
   + pydantic-settings + `py.typed`. Env prefix `AUDEL_`.

## Reality notes from AgentVision source (read these before coding)

- `agentvision/models/`: `geometry.py` (Size/Viewport/BBox), `report.py` (Severity, IssueKind,
  Importance, ClaimStatus, Confidence, IssueSource, Verdict, **Issue**, ClaimResult,
  Conformance, **Report**, `verdict_from_issues`), `intent.py` (IntentClaim w/ `must:`/`should:`
  prefix parser, Brief.from_inputs), `handoff.py` (NextAction, **Handoff.from_report**).
- `Issue` is **strict-schema-safe**: closed enums, `detail_json` is a JSON **string** (property
  `detail` decodes it). Preserve this — it's what lets the model serialize to LLM structured
  output. `Span` must be a flat int submodel, no free dicts.
- `IssueKind` is a **closed enum** used by `verdict_from_issues()` and `Handoff.from_report()`
  (special-cases `INTENT_MISMATCH`). This is why kind must become `str` in agentsense (decision 5).
- `Handoff.from_report()` splits issues into defects vs intent by `kind == INTENT_MISMATCH`.
  Audio analog: `transcript_mismatch` / `wrong_language` are intent-ish — map them so they land
  in `todo` as `[intent/...]`, not as raw defects.
- Backend protocol (`backends/base.py`): `VisionBackend` = `name`, `available()`,
  `async analyze(req)->Report`, `async complete_text(system,user)->str`. Local backend returns
  `""` from `complete_text`. Mirror this shape for `AudioBackend` (+ `transcribe`,
  `critique_audio`).
- `config.py`: `env_prefix="AGENTVISION_"`, provider keys via `validation_alias` (conventional
  names), key-file fallback under `~/.config/<Provider>/key`, `platformdirs` cache. Mirror for
  `AUDEL_`. Credentials read here only, never logged/persisted.
- `pyproject`: hatchling, `[project.scripts]`, extras lazy-imported, default Anthropic model
  `claude-haiku-4-5`.

---

## Phase 0 — Contract + scaffold

### 0a. Extract `agentsense` (touches published agentvision — verify carefully)
- [ ] Create `agentsense` package (`src/agentsense/`, hatchling, py.typed, pydantic only — zero
      heavy deps). Move the **structural** models: Verdict, Severity, Confidence, Importance,
      ClaimStatus, IssueSource, `Span` (new), `Issue` (with `kind: str` + optional `span`),
      ClaimResult, Conformance, Report (`verdict_from_issues`, `issue_signature`, `to_handoff`),
      Brief/IntentClaim, Handoff/NextAction, and a `Sense` protocol.
- [ ] agentsense owns cross-domain kinds only: `INTENT_MISMATCH`, `OTHER` (string constants).
- [ ] Refactor `agentvision.models.*` to re-export from agentsense; keep `agentvision`'s
      vision `IssueKind` str-enum local. Run AgentVision's existing test suite green — **no
      behavior change** (this is the acceptance gate for 0a).
- [ ] Decide agentsense versioning/publish (own dist, pin `agentsense>=x` in both).

### 0b. Audel scaffold
- [ ] `src/audel/` skeleton per repo layout (§7 of kickoff). `pyproject` with extras
      (`render`,`asr`,`cloud`,`clap`,`all`,`dev`) + entry points (`audel`, `audel-mcp`,
      `audel-serve`) + `audel.backends` plugin entry-point group. Depend on `agentsense`.
- [ ] `audel/models/`: re-export agentsense + define audio `IssueKind` str-enum (silence,
      clipping, loudness, truncation, dropout, decode_error, missing_audio, desync,
      transcript_mismatch, wrong_language, noise, channel_issue, duration).
- [ ] `config.py`: `Settings(BaseSettings)` env prefix `AUDEL_`, `LoudnessTarget` preset enum,
      provider keys via conventional aliases, key-file fallback. `load_settings()`.
- [ ] `audel doctor` (check ffmpeg / Chromium / asr / backends). Lazy `__getattr__` for heavy
      entry points so `import audel` stays torch-free.
- **Accept:** `import audel` is fast (assert no torch/numpy-heavy import); `audel doctor` runs;
  a schema-compat test asserts `audel`'s `Handoff` is schema-identical to AgentVision's;
  AgentVision's own tests still pass after the 0a refactor.

## Phase 1 — render() + deterministic check()
- [ ] `signals/decode.py` (ffmpeg subprocess, **argv form**, bounded: max-duration / max-bytes
      cap before decode, timeout) → `Waveform` (numpy) + base metrics.
- [ ] `signals/`: silence, clipping/true-peak (dBTP), loudness (LUFS+LRA vs target), truncation,
      duration, channel/mono-dead checks → `Issue`s with `span`.
- [ ] `core/render.py` → `RenderResult` (waveform + peaks + LUFS + VAD segments + spectrogram).
- [ ] `core/check.py` → assembles `Report` via `verdict_from_issues`. **No LLM, no egress.**
- [ ] `adapters/cli.py`: `audel check`, `audel render`; `audel demo` (broken clip:
      silent gap + truncated VO + wrong-lang + clipping → FAIL with time-grounded issues →
      fixed clip → PASS, **no API key**).
- [ ] `tests/fixtures/`: silent.wav, truncated.wav, clipping.wav, wrong_lang.mp3, good.mp4.
- **Accept:** `audel demo` prints time-grounded FAIL then PASS, no key; fixtures grade correctly
  in CI; decode is resource-bounded (regression test on an oversized/garbage input).

## Phase 2 — Speech grading + conformance
- [ ] `speech/asr.py` (faster-whisper, `[asr]`, lazy) + language detect.
- [ ] `backends/base.py` `AudioBackend` Protocol (`name`, `available()`, `transcribe`,
      `complete_text`, `critique_audio`) + `backends/local.py` (whisper transcribe; `""` for LLM
      methods) + `backends/registry.py` (entry-point resolution).
- [ ] `speech/conformance.py`: grade `Brief`/`IntentClaim` text claims vs transcript →
      `Conformance`; populate `must`/`should`. Map `transcript_mismatch`/`wrong_language` so
      `to_handoff()` files them as intent items.
- **Accept:** `check(source, brief=...)` fails on wrong-language / missing phrase / over-duration;
  `matches_intent()` correct; handoff todo lists intent misses as `[intent/must]`.

## Phase 3 — analyze() with backends + CLAP
- [ ] Cloud/audio-LLM backends (`[cloud]`): default = transcript→Anthropic-Haiku text critique;
      opt-in Gemini-audio `critique_audio`. Behind registry.
- [ ] `core/analyze.py`: deterministic signals + ASR grounding + backend critique +
      non-deterministic claim grading; gate verdict on conformance when `brief` given.
- [ ] `acoustic/clap.py` (`[clap]`, lazy): zero-shot non-speech conformance ("contains a chime").
- **Accept:** `analyze(brief=...)` grades a tone/naturalness `should:` and a CLAP
  `must: contains <sound>` claim.

## Phase 4 — watch() temporal + web capture
- [ ] `core/watch.py`: playback liveness, dropout/desync over time.
- [ ] `[render]` Playwright path: play a URL headless + capture audio (do ffmpeg file path
      first; headless web-audio capture is the hard part — document the approach + sandbox the
      browser process).
- **Accept:** `watch` flags a video that's silent though it "plays," and a button whose click
  sound never fires.

## Phase 5 — Loop + handoff + Verel
- [ ] `core/loop.py` `LoopSession`/`IterationResult`; `core/generate.py`
      `GenerativeLoopSession`; reuse `Report.to_handoff()` + `issue_signature()` for stuck detect.
- [ ] Register Audel as a `verel.senses` sense feeding `verel.verdict`
      (Verel src: `/home/amitpatole/WORKSPACE/Nirvana/src/verel`). One cross-modal demo:
      AgentVision "video renders" + Audel "audio plays & VO correct" → combined verdict.
- **Accept:** Verel gates "done" on Audel's verdict; eyes+ears co-grade one artifact end-to-end.

## Phase 6 — Adapters + publish
- [ ] MCP / REST / Skill adapters; `audel mcp` (hear_check/analyze/watch/diff/status). Finalize
      extras; verify light base wheel; document an external `audel-backend-foo` plugin.
- [ ] `.github/workflows/publish.yml` → TestPyPI → PyPI (Trusted Publishing / OIDC). README
      quickstart mirroring AgentVision.
- **Accept:** clean-venv `pip install audel[render,asr,clap]` runs the quickstart; installs from
  TestPyPI.

## Phase 7 — Realtime polish (optional)
- [ ] Streaming verification (live voice-agent / call QA), `hear_status` metrics, Docker, benchmarks.

---

## Security cadence (apply per phase — Audel handles untrusted media + optional egress)
- **Phase 1 decode** is the top attack surface: ffmpeg in **argv form** (no shell), input-size
  + duration caps **before** allocating/decoding, subprocess timeout + `RLIMIT_*`, reject
  unknown codecs. Regression-test garbage/oversized/zip-bomb-style inputs.
- **`check` path = zero egress** — assert no network in tests (reuse AgentVision's `netguard`
  pattern if present).
- **Web capture (Phase 4):** sandbox the headless browser; SSRF guard on user-supplied URLs.
- **Secrets:** provider keys resolved in `config.py` only, never logged/persisted; fail closed
  when a requested cloud backend has no key (don't silently downgrade to a weaker grade).
- Run the audit→triage→fix→verify→commit→red-team loop before any publish (Phase 6).
