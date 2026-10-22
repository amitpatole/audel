# CLI

Every command exits `0` on `pass` or `warn` and `1` on `fail`, so it can gate a pipeline step
directly.

| Command | What it does |
|---|---|
| `audel check SOURCE [--spec S] [--content C] [--json]` | Hearing: the deterministic signal grade. No model, no network. |
| `audel listen SOURCE [options]` | Hearing plus listening. See below. |
| `audel qc SOURCE [--spec S] [--html F] [--json F]` | Grade and write operator QC reports. |
| `audel specs` | List built-in delivery specs. |
| `audel bench [--corpus DIR] [--json]` | Precision and recall per check, on the synthetic corpus or your labelled one. |
| `audel render SOURCE` | Raw signals: loudness, true peak, RMS, silent spans. |
| `audel analyze SOURCE [--brief T] [--expect C]... [--backend B]` | Signals, ASR and backend critique of brief claims. |
| `audel watch SOURCE [--click SELECTOR]` | Temporal grade of a file, or of a web page's sound. |
| `audel diff BASELINE CANDIDATE` | What a fix changed: resolved, introduced and persisted issues. |
| `audel stream SOURCE [--chunk-ms N]` | Grade a file fed as a live stream through the bounded monitor. |
| `audel serve [--host H] [--port P]` | REST service. A routable bind requires auth. |
| `audel token new [--tenant NAME] [--rate-per-min N]` | Mint a token, the only kind Audel accepts. With `--tenant` it also prints the tokens-file hash entry. |
| `audel purge [--hours N]` | Remove stale temp files and expired sessions. |
| `audel doctor` | Environment and backend diagnostics. |
| `audel demo` | Broken clip to FAIL, fixed clip to PASS. No key needed. |
| `audel version` | Print the version. |

## `audel listen`

```text
--script PATH          approved script to check the read against
--captions PATH        SRT or WebVTT file to check against the audio
--require TEXT         wording that must be said (repeatable)
--forbid TEXT          wording that must not be said (repeatable)
--language TRACK=CODE  expected language per audio track (repeatable)
--key-message TEXT     what a listener should take away (repeatable; "must:" makes a miss an error)
--tone LABEL           calm | warm | neutral | urgent | angry | monotone | rushed
--understand           use a model for key messages, takeaway and delivery
--backend NAME         backend for --understand (default ollama-local when configured)
--spec S --content C   as for check
--json                 print the JSON report
--html PATH            write the HTML QC report
```

## In a pipeline

```bash
audel qc "$MASTER" --spec atsc_a85 --html "$OUT/qc.html" --json "$OUT/qc.json" \
  || { echo "audio QC failed, see $OUT/qc.html"; exit 1; }
```
