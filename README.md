# Audel — Ears for AI Agents 👂

> A machine-graded **audio** feedback loop that coding agents consume to self-correct
> before claiming *done*: **play → hear → report → fix.**

Sibling to **[AgentVision](https://github.com/amitpatole/agent-vision)** (eyes) and
**Verel** (brain). AgentVision confirms a video *renders*; **Audel confirms it actually
has sound and the narration is right.**

AI coding agents are **deaf** — they generate TTS, soundtracks, web-app sound effects,
voice-bot prompts, and audiobooks, and never *hear* the result. Audel gives them ears:
it grades audio/voice/media artifacts and returns a machine **verdict**
(`pass`/`warn`/`fail`) with **time-grounded** issues, so the agent self-corrects before
it claims done.

## Status

**`0.1.0` — live on [PyPI](https://pypi.org/project/audel/).** Grade an audio/media artifact and
get a machine verdict back:

```python
import asyncio
from audel import check, load_settings

async def main():
    report = await check("dist/intro.mp4", settings=load_settings())
    print(report.verdict, [i.message for i in report.issues])   # pass|warn|fail + time-grounded

asyncio.run(main())
```

The surface mirrors AgentVision one-to-one: async `analyze` / `check` / `watch` / `render` /
`compute_diff`, `Brief` / `IntentClaim`, `Report` / `Issue` (time-grounded via `span`) /
`Conformance` / `Handoff`, an `AudioBackend` protocol, live `StreamMonitor`, and CLI / MCP / REST
adapters. `check` is **offline by construction** (local DSP + faster-whisper ASR); egress happens
only on `analyze`. Light base install (ffmpeg + DSP, no torch); ML behind extras
(`[render]`, `[asr]`, `[cloud]`, `[clap]`).

📖 **Docs:** [amitpatole.github.io/audel](https://amitpatole.github.io/audel/)

## Install

```bash
pip install audel
```

## License

MIT © Amit Patole
