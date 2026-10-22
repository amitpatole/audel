# Audel — ears for AI agents and media pipelines

Audel **hears** audio and then **listens** to it. It returns a machine verdict (`pass`, `warn` or
`fail`) with findings grounded to the millisecond, so an agent or a pipeline can fix the problem
before it ships.

- **Hearing** asks whether the signal is healthy and on spec. It grades every track against a
  delivery spec (EBU R128, R128 s1, ATSC A/85, OP-59, ARIB TR-B32, Netflix-style speech-gated,
  Spotify, YouTube, Apple), covering integrated, short-term and momentary loudness, true peak,
  clipping, silence, truncation, dead or inverted or out-of-phase channels, DC offset, mains hum
  and noise floor.
- **Listening** asks whether the right thing was said and whether a person could follow it. It
  checks script adherence with time-grounded omissions and substitutions, required and forbidden
  wording, pace, dead air, intelligibility, captions (SRT and WebVTT text, offset, reading rate)
  and language per track. With an opt-in model it also checks whether key messages landed and how
  they were delivered.

Hearing and offline listening never touch the network. Model-assisted understanding can run
entirely on your own hardware through an on-prem Ollama server.

## Install

```bash
pip install --pre audel           # light base: ffmpeg + DSP (--pre: 1.0.0rc1)
pip install "audel[asr]"          # local faster-whisper: listening
pip install "audel[serve,oidc]"   # REST service with JWT auth
audel doctor
audel demo                        # broken clip -> FAIL, fixed clip -> PASS, no key
```

Audel needs `ffmpeg` on the PATH.

## Use it

```bash
audel check  promo.wav --spec ebu_r128_s1
audel listen read.wav --script script.txt --captions read.srt --require "terms and conditions apply"
audel qc     master.wav --spec atsc_a85 --html qc.html --json qc.json
```

```python
from audel import check, listen

heard = await check("promo.wav", spec="ebu_r128_s1")
listened = await listen("read.wav", script=open("script.txt").read())
print(listened.verdict, listened.listening.script_adherence)
```

## Run it as a service

`audel serve` provides sync grading and async jobs. It can ingest from signed object-store URLs,
and it exposes Prometheus metrics and a JSON audit log. Auth is per-tenant tokens or OIDC JWT,
with optional mutual TLS, per-tenant rate limits, and an egress policy (`allow`, `local-only` or
`deny`). A hardened container and Helm chart ship in the repository. See
[Running as a service](https://amitpatole.github.io/audel/deployment/) and the
[threat model](https://amitpatole.github.io/audel/security/).

## How accurate is it

`audel bench` reports precision and recall per check. It runs on a seeded synthetic corpus out
of the box, and on your own labelled deliverables with `--corpus`. Measure it on your material
before you make it a gate. See [Checks reference](https://amitpatole.github.io/audel/checks/).

## Part of a family

Audel is the ears. [AgentVision](https://github.com/amitpatole/agent-vision) is the eyes and
[Verel](https://github.com/amitpatole/verel) is the brain. All three speak one contract,
[`agentsensory`](https://pypi.org/project/agentsensory/), and `pip install "verel[hearing]"`
pulls in the whole stack.

📖 **Docs:** [amitpatole.github.io/audel](https://amitpatole.github.io/audel/) ·
**Changelog:** [CHANGELOG.md](CHANGELOG.md) · **Security:** [SECURITY.md](SECURITY.md)

## License

MIT © Amit Patole
