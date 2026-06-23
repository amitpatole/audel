# Quickstart

## Install

```bash
pip install audel            # light base: ffmpeg + DSP, no torch
audel doctor                 # check ffmpeg + optional extras
audel demo                   # FAIL → PASS, no API key required
```

Optional capabilities live behind extras:

```bash
pip install "audel[asr]"     # local faster-whisper transcription (intent grading)
pip install "audel[cloud]"   # Anthropic / Gemini / Ollama critique backends
pip install "audel[render]"  # headless browser capture for web audio
pip install "audel[clap]"    # CLAP acoustic embedding backend
```

## Grade a file offline

`check` runs entirely locally — no network, no key. It grades loudness (EBU R128), clipping,
silence, dropouts and A/V desync.

```python
import asyncio
from audel import check, load_settings

async def main():
    report = await check("dist/intro.mp4", settings=load_settings())
    print(report.verdict)                         # pass | warn | fail
    for issue in report.issues:
        print(issue.span, issue.message)          # time-grounded

asyncio.run(main())
```

## Match intent (local ASR)

Grade what the audio *says* against a brief — language, required phrases, duration —
using local faster-whisper.

```python
from audel import check, load_settings, Brief

brief = Brief(language="en", must_say=["welcome to Audel"], max_duration_s=30)
report = await check("dist/intro.mp4", brief=brief,
                     settings=load_settings(audio_backend="local"))
```

## Listen & critique (egress)

`analyze` is the only path that leaves the machine, and only to a backend you name. It adds
acoustic and LLM judgment for subjective claims; transcripts are treated as untrusted input.

```python
from audel import analyze, load_settings

report = await analyze("dist/narration.wav",
                       settings=load_settings(audio_backend="local"))
print(report.verdict, [i.message for i in report.issues])
```

## CLI

```bash
audel check  dist/intro.mp4            # offline verdict
audel analyze dist/narration.wav       # + critique (egress)
audel watch  dist/clip.mp4             # temporal: playthrough / dropouts / desync
audel stream --format f32              # grade live PCM chunks from stdin
audel diff   before.json after.json    # what changed between two reports
audel serve                            # REST (FastAPI) service
```

## Ears → brain

Hand a graded report to Verel (the brain) so verified-only work compounds:

```bash
pip install "verel[hearing]"           # pulls verel → audel → agentsensory
```

```python
from verel.senses.audio import from_audel
sense = from_audel(report)             # Audel verdict becomes a Verel grader signal
```
