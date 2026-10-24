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

| Layer | What you get |
|---|---|
| **[Hear](checks.md)** | `check` grades every track against a [delivery spec](specs.md): loudness (integrated, short-term, momentary, LRA), true peak, clipping, silence, truncation, dead, inverted or out-of-phase channels, DC offset, mains hum and noise floor. It is deterministic, time-grounded and never uses the network. |
| **[Listen](listening.md)** | `listen` grades what was said: script adherence, required and forbidden wording, pace, dead air, intelligibility, captions and language per track. It runs offline on local ASR. |
| **[Understand](listening.md#understanding-opt-in)** | Opt-in model judgment: did the key messages land, what is the takeaway, and does the delivery match the brief. It can run fully [on-prem](on-prem.md). |
| **[Operate](deployment.md)** | REST and MCP, async jobs, signed-URL ingestion, metrics, an audit log, tenants, JWT and mTLS, an egress policy, plus a hardened container and Helm chart. |
| **Ears to brain** | A distilled `{verdict, next_action, todo}` handoff any agent or brain acts on. |

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quickstart](quickstart.md)** — install, system deps, first run.
- :material-console: **[CLI](cli.md)** — `check` · `listen` · `qc` · `specs` · `bench` · `serve` · `demo` and more.
- :material-cog: **[Running as a service](deployment.md)** — REST, async jobs, metrics, container and Helm.
- :material-shield: **[Security](security.md)** — threat model and hardening checklist.

</div>

## Offline by construction

`check` and offline `listen` never touch the network. They run on local DSP (ffmpeg's BS.1770
meters) and local ASR (faster-whisper). Model-assisted steps reach only the backend you name, and
`ollama-local` keeps them on your own network. `AUDEL_EGRESS=deny` makes Audel fully offline.
Transcripts are treated as untrusted input. The base
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
Package: [PyPI](https://pypi.org/project/audel/) · License: MIT ·
Cite: [doi:10.5281/zenodo.23609200](https://doi.org/10.5281/zenodo.23609200) ([how to cite](writeup.md#how-to-cite)).
