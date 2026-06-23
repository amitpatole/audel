# Audel — Ears for AI Agents

> **Problem:** AI coding agents are *deaf* — they generate TTS, soundtracks, web-app sound
> effects, voice-bot prompts, and audiobooks, and never *hear* the result.
> **Result:** Audel gives them ears — **play → hear → report → fix** — so the agent
> **self-corrects before it claims done.**

```bash
pip install audel
audel demo                       # no API key required
```

`audel demo` grades a deliberately silent render, prints a **FAIL** report (missing audio —
DSP-grounded, no LLM key), then loops against the fixed version and prints
*"what changed: issues resolved → PASS."*

## What it does

| Capability | What you get |
|---|---|
| **Hear & report** | A machine verdict (`pass`/`warn`/`fail`) + **time-grounded** issues — loudness (EBU R128), clipping, silence/dropouts, A/V desync — DSP-grounded, no key needed. |
| **[Match intent](quickstart.md)** | Grade audio against a brief — language, phrase coverage, duration — via local faster-whisper ASR. PASS means *"it says what I meant,"* not just *"it has sound."* |
| **Listen & critique** | `analyze` adds acoustic + LLM judgment (Ollama Cloud text critique, or key-gated Anthropic / Gemini-audio / CLAP) for subjective claims — egress only here; `check` stays offline. |
| **Streaming / temporal** | `watch` grades behavior over time; `StreamMonitor` grades live PCM chunks — playthrough, dropouts, liveness — bounded by construction. |
| **Ears → brain handoff** | A distilled `{verdict, next_action, todo}` signal any agent/brain acts on. |

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quickstart](quickstart.md)** — install, system deps, first run.
- :material-console: **CLI** — `demo` · `check` · `analyze` · `watch` · `render` · `diff` · `stream` · `serve` · `doctor`.
- :material-cog: **Adapters** — REST (FastAPI) and MCP (9 tools) service surfaces.

</div>

## Offline by construction

`check` never touches the network — loudness, clipping, silence, dropout and A/V-desync grading
run entirely on local DSP (ffmpeg filters) and local ASR (faster-whisper). Egress happens **only**
on `analyze`, and only to a backend you name; transcripts are treated as untrusted input. The base
install is light (ffmpeg + DSP, no torch) — ML lives behind extras: `[asr]`, `[render]`, `[cloud]`,
`[clap]`.

## Eyes, ears & brain

Audel is the **ears**. It pairs with **[AgentVision](https://github.com/amitpatole/agent-vision)**,
the **eyes** — which confirms a video *renders* — and **[Verel](https://github.com/amitpatole/verel)**,
the **brain** — an agent framework where *nothing is "done" until a grader returns a verdict.*
AgentVision confirms it renders; **Audel confirms it actually has sound and the narration is right;**
Verel decides and **compounds only verified work** into memory. All three share one contract,
[`agentsensory`](https://pypi.org/project/agentsensory/).

```text
  AgentVision  ·  Audel  ·  Verel
     eyes          ears       brain
   it renders   it sounds   it's done
```

Install: `pip install "verel[hearing]"` pulls the whole stack ·
Source: [GitHub](https://github.com/amitpatole/audel) ·
Package: [PyPI](https://pypi.org/project/audel/) · License: MIT.
