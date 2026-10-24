# Design and citation

## What Audel is

Audel is a machine-graded audio feedback loop. An AI agent, or a stage in a media pipeline, hands
it a file, a URL or a stream, and gets back a verdict (`pass`, `warn` or `fail`) with issues that
are grounded in time: each one says what is wrong, where in the programme, on which track and
channel, and how sure Audel is. The agent fixes the work and asks again, and the work is only
called done once Audel passes it.

It does two jobs. **Hearing** is signal measurement: loudness against a delivery spec, true peak,
clipping, silence and dropouts, phase and polarity, hum, noise floor, dead channels, timeline gaps,
truncation and media the demuxer never read. **Listening** is meaning: what was said, in which
language, whether captions match the speech, whether required phrases are present and forbidden
ones absent, and, through an optional model backend, whether the programme does what its brief
asked.

## Why it exists

Agents now generate speech, music, sound design and whole programmes, and they cannot hear any of
it. They report a task as finished when a file exists, not when the file is right. Broadcast QC
tools solve the measurement half for human operators, but they are heavy, closed and not built to
sit inside an agent's loop. Audel is pre-flight QC for that loop: light enough to run on every
attempt, deterministic where it can be, and explicit about where it is not.

## Architecture

```text
input (file / URL / stream)
  -> guard      allowlisted demuxers, local-file protocol only, SSRF-safe fetch, size and
                duration caps, one deadline per file
  -> probe      streams, layouts, declared durations
  -> timeline   packet scan per track: gaps, overlaps, jumps, unread media regions
  -> passes     one streamed decode per pass, analysed in a second process:
                loudness / true peak / per-channel stats, spectral series (hum, noise, mid/side),
                tail, speech regions (VAD) for dialogue-gated loudness
  -> checks     measurements -> issues, against a delivery spec (EBU R128, ATSC A/85, Netflix...)
  -> listening  transcript (faster-whisper), captions, phrases, language, model critique
  -> Report     verdict + grounded issues + Handoff (the shared agentsensory contract)
```

The same core runs behind four adapters: a Python API, a CLI, an MCP server for agents, and a
REST service with async jobs, URL ingest, metrics and an audit log. The service is multi-tenant:
tenant tokens, JWT or mutual TLS identify the caller, and every resource a caller can drive is
bounded per tenant and overall (grading slots, queued jobs, disk held by uploads and fetches,
request rate). Egress is off by default, so audio and transcripts leave the host only when an
operator turns a remote backend on.

Audel is one organ of a larger system. It emits the same `Report` and `Handoff` types as its
sibling graders (vision, vitals, knowledge), defined in the shared
[`agentsensory`](https://pypi.org/project/agentsensory/) contract, so an orchestrator such as
[`verel`](https://pypi.org/project/verel/) can treat hearing like any other sense.

## How it was verified

- **The gate.** Lint, type checks and the test suite (878 tests at release) run on every change,
  together with a no-key demo and a strict documentation build. CI repeats them on Python 3.11
  and 3.12 against the distribution's own ffmpeg.
- **A decode battery.** 473 files across codecs, containers and channel layouts (stereo to 22.2
  and higher-order ambisonics), graded under two delivery specs and compared before and after
  every decode change. A release ships only with no unexplained differences.
- **Adversarial review.** Twenty rounds of independent red-team review against three surfaces:
  network and input handling, decode and sandboxing, and secrets and authentication. Every
  finding was fixed, proved blocked by re-running its reproduction, and pinned by a regression
  test. No round after the sixth found a way past authentication.
- **Throughput.** On a shared 4-core host under heavy load, a 10-minute stereo programme grades in
  about 16 s against EBU R128, and the service sustains about 1,700 two-minute files an hour with
  four workers.

## Limits

Audel measures what a file contains and what was said in it. It does not judge taste, and its
model-assisted critique is advisory. Grading depends on ffmpeg's decoders and demuxers, so their
behaviour bounds Audel's. Security review closes the vectors it finds; it cannot remove risk from
dependencies, the operating system and container runtime, or problems no one has found yet.

## How to cite

If you use Audel in your work, please cite it. The concept DOI always resolves to the latest
version:

> Patole, A. *Audel: Ears for AI Agents.* Zenodo.
> [doi:10.5281/zenodo.23609200](https://doi.org/10.5281/zenodo.23609200)

```bibtex
@software{patole_audel,
  author    = {Patole, Amit},
  title     = {Audel: Ears for AI Agents},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.23609200},
  url       = {https://doi.org/10.5281/zenodo.23609200}
}
```

The repository's `CITATION.cff` carries the same details for GitHub's "Cite this repository".
