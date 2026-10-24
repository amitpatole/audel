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

`check` runs entirely locally, with no network and no key. It grades every audio track against a
[delivery spec](specs.md): loudness, true peak, clipping, silence, truncation, channels, phase,
hum and noise. See the [checks reference](checks.md).

```python
import asyncio
from audel import check, load_settings

async def main():
    report = await check("dist/intro.mp4", spec="ebu_r128", settings=load_settings())
    print(report.verdict)                         # pass | warn | fail
    for issue in report.issues:
        print(issue.span, issue.message)          # time-grounded

asyncio.run(main())
```

## Match intent (local ASR)

Grade what the audio says against a brief, such as language, required phrases and duration,
using local faster-whisper. Claims carry an importance prefix: `must:`, `should:` or `nice:`.

```python
from audel import Brief, check

brief = Brief.from_inputs(expect=['must: language is en',
                                  'must: narration says "welcome to Audel"',
                                  'should: duration < 30s'])
report = await check("dist/intro.mp4", brief=brief)
for claim in report.conformance.claims:
    print(claim.importance.value, claim.status.value, claim.text)
```

## Hear and listen

`listen` runs the full signal check, then grades what was said. That covers script adherence,
required and forbidden wording, pace, pauses, captions and per-track language. It stays offline
unless you add `understand=True`. See [Hearing and listening](listening.md).

```python
from audel import listen

report = await listen("read.wav", script=open("script.txt").read(),
                      captions=open("read.srt").read(), required=["terms and conditions apply"])
print(report.verdict, report.listening.script_adherence, report.listening.wpm)
```

## Critique with a model (may egress)

`analyze` adds acoustic and model judgment for subjective claims in a brief. It leaves the
machine only to the backend you name, and the `ollama-local` backend keeps it on your network (see
[On-prem inference](on-prem.md)). Transcripts are treated as untrusted input. Set
`AUDEL_EGRESS=deny` to make Audel fully offline.

```python
from audel import analyze, load_settings

report = await analyze("dist/narration.wav",
                       settings=load_settings(audio_backend="local"))
print(report.verdict, [i.message for i in report.issues])
```

## CLI

```bash
audel check   dist/intro.mp4 --spec ebu_r128     # hearing: offline verdict
audel listen  dist/read.wav --script script.txt  # hearing + listening
audel qc      dist/master.wav --spec atsc_a85 --html qc.html
audel watch   dist/clip.mp4                      # temporal: playthrough / dropouts / desync
audel stream  dist/call.wav                      # grade a file fed as a live stream
audel diff    before.wav after.wav               # what a fix changed between two clips
audel serve                                      # REST service
```

The full command list is on the [CLI](cli.md) page.

## Ears → brain

Hand a graded report to Verel (the brain) so verified-only work compounds:

```bash
pip install "verel[hearing]"           # pulls verel → audel → agentsensory
```

```python
from verel.senses.audio import from_audel
sense = from_audel(report)             # Audel verdict becomes a Verel grader signal
```
