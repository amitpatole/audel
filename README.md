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

🚧 **Early development.** This `0.0.1` release reserves the name on PyPI. The graded API is
landing incrementally:

```python
import asyncio
from audel import analyze, load_settings   # coming soon

async def main():
    report = await analyze("dist/intro.mp4", settings=load_settings(audio_backend="local"))
    print(report.verdict, [i.message for i in report.issues])

asyncio.run(main())
```

Planned surface mirrors AgentVision one-to-one: async `analyze` / `check` / `watch` /
`render` / `compute_diff`, `Brief` / `IntentClaim`, `Report` / `Issue` (time-grounded via
`span`) / `Conformance` / `Handoff`, an `AudioBackend` protocol, and CLI / MCP / REST
adapters. Light base install (ffmpeg + DSP, no torch); ML behind extras
(`[render]`, `[asr]`, `[cloud]`, `[clap]`).

## Install

```bash
pip install audel
```

## License

MIT © Amit Patole
