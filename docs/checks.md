# Checks reference

`check` is deterministic. It uses ffmpeg's ITU-R BS.1770 meters and signal statistics, makes no
model calls and sends nothing over the network. Every audio track in the file is graded, not only
the first.

Each finding has a `kind` from the shared audio vocabulary, which is what Verel and other
consumers of the contract key on. It also has a precise rule name in `detail.check`.

| `detail.check` | `kind` | Fires when | Severity |
|---|---|---|---|
| `missing_audio` | `missing_audio` | the file has no audio stream | critical |
| `silent_track` | `silence` | a track is silent end to end | critical |
| `silence_gap` | `silence` | 1.5 s or more of silence inside a live track | warning |
| `integrated_loudness` | `loudness` | integrated loudness is outside the spec target ± tolerance | error (rejected) or warning (advisory) |
| `max_short_term` | `loudness` | short-term loudness (3 s) passes the spec maximum | as above |
| `max_momentary` | `loudness` | momentary loudness (400 ms) passes the spec maximum | as above |
| `loudness_range` | `loudness` | LRA is above the spec ceiling | warning |
| `true_peak_ceiling` | `clipping` | true peak is above the spec ceiling but below full scale | error |
| `clipping` | `clipping` | true peak is at or above 0 dBTP | error |
| `truncation` | `truncation` | the track ends at programme level with no decay | warning (low confidence) |
| `short_track` | `truncation` | one audio track starts late or ends early on the programme timeline | error |
| `decode_errors` | `dropout` | the decoder reported corrupt data or CRC failures in this stream | warning, error at 10 or more |
| `duration_mismatch` | `duration` | the container's declared length differs from the decoded audio | warning |
| `empty_stream` | `silence` | an audio stream contains no samples | critical |
| `packet_gap` | `dropout` | audio packets are missing from the stream's timeline, including a hole stored as one long sample | warning, error above 10% of the track |
| `timeline_shortfall` | `dropout` | the packet timeline runs longer than the audio that decodes plus the reported gaps (missing audio spread through the track) | warning, error above 10% |
| `dialogue_unmeasured` | `loudness` | a dialogue-gated spec, but no dialogue was detected or the speech-gated measurement failed; graded on programme loudness | warning (low confidence) |
| `spectral_unavailable` | `other` | the hum, noise-floor and phase checks could not run on a track | warning (low confidence) |
| `timeline_excess` | `duration` | more audio decodes than the packet timeline holds (duplicated or mis-timed packets) | warning |
| `timestamp_jump` | `other` | packet timestamps jump by more than any file may run (a corrupt timeline) | error |
| `packet_gap_total` | `dropout` | more missing-packet gaps than are listed; reports the total | warning |
| `gap_scan_incomplete` | `other` | the packet timeline couldn't be read in full, so missing-packet detection is incomplete | warning (low confidence) |
| `container_truncated` | `truncation` | the file header declares more audio than the file contains (WAV, RF64, BW64, W64, AIFF, CAF) | error |
| `track_decode_error` | `decode_error` | one audio track can't be decoded (the others are still graded) | critical |
| `dead_channel` | `channel_issue` | one channel is silent while the track is live (LFE excluded) | error |
| `polarity_inversion` | `channel_issue` | left and right cancel to silence in a mono fold-down | error |
| `phase` | `channel_issue` | left and right are largely anti-correlated | warning |
| `dc_offset` | `channel_issue` | a channel carries more than 1 % DC offset | warning |
| `hum` | `noise` | steady 50 or 60 Hz energy dominates the quiet passages | warning |
| `noise_floor` | `noise` | speech content has a noise floor above -50 dBFS | warning |

Every finding carries a `span` in milliseconds. Loudness and true-peak findings that cover several
passages also list each passage in `detail.spans_ms`.

## Per-track results

`report.tracks` holds one summary per audio stream. Each summary has codec, layout, language tag,
integrated loudness, speech-gated loudness, true peak, maximum momentary and short-term loudness,
LRA and RMS. Container metadata is attacker-controlled, so tags are truncated and charset-filtered
before they reach a report.

```json
{
  "index": 0, "codec": "pcm_s16le", "channels": 2, "sample_rate": 48000,
  "integrated_lufs": -24.3, "lra": 5.1, "true_peak_dbtp": -0.1,
  "max_momentary_lufs": -22.5, "max_short_term_lufs": -24.0, "rms_dbfs": -31.11
}
```

## Example

This is real output for a 10-second stereo promo. The right channel is dead, there is 50 Hz hum,
and a transient overshoots the ceiling:

```text
$ audel check promo.wav --spec ebu_r128 --content speech
FAIL  5 issue(s): channel_issue, clipping, loudness, noise
  • [clipping/error] [6999–7099ms] true peak -0.1 dBTP exceeds -1.0 dBTP (ebu_r128): over the true-peak ceiling
  • [loudness/error] [0–10000ms] integrated loudness (programme) -24.3 LUFS is 1.3 LU quieter than the ebu_r128 target (-23 ±0.5 LU)
  • [channel_issue/error] [0–10000ms] channel FR is silent while the track is live
  • [noise/warning] [0–10000ms] 50 Hz mains hum at -49 dBFS, steady across the programme and dominant in the quiet passages
  • [noise/warning] [0–10000ms] noise floor -49 dBFS in the quietest passages (estimated SNR 10 dB); the mains hum above is the likely cause
```

## QC report for operators

`audel qc` writes a self-contained HTML page for the person who signs off the deliverable. It has
the verdict, the spec, a per-track table, a timeline of findings and the findings table. The page
loads nothing external and runs no script. Every value is HTML-escaped and a Content-Security-Policy
forbids scripts.

```bash
audel qc promo.wav --spec ebu_r128 --html promo.qc.html --json promo.qc.json
```

## How accurate is it

`audel bench` grades a labelled corpus and reports precision and recall per check. With no
arguments it generates a deterministic synthetic corpus of 20 clips. Each clip has a known defect,
and the corpus includes clean controls and look-alikes such as a bass line next to mains hum.

```text
$ audel bench
20/20 cases graded exactly
  check                   tp  fn  fp  precision  recall
  clipping                 1   0   0       1.00    1.00
  dc_offset                1   0   0       1.00    1.00
  dead_channel             1   0   0       1.00    1.00
  hum                      2   0   0       1.00    1.00
  integrated_loudness      3   0   0       1.00    1.00
  max_short_term           1   0   0       1.00    1.00
  noise_floor              1   0   0       1.00    1.00
  phase                    1   0   0       1.00    1.00
  polarity_inversion       1   0   0       1.00    1.00
  silence_gap              1   0   0       1.00    1.00
  silent_track             2   0   0       1.00    1.00
  true_peak_ceiling        1   0   0       1.00    1.00
  truncation               1   0   0       1.00    1.00
```

The synthetic corpus shows that each detector fires on its defect and stays quiet on clean
material. It does not show field accuracy. To measure Audel on your own deliverables, label a
folder of real files and run the same benchmark over it:

```json
[
  {"file": "promo_017.wav", "spec": "ebu_r128_s1", "expect": ["max_short_term"]},
  {"file": "ep101_mix.wav", "spec": "atsc_a85", "content": "mixed", "expect": []}
]
```

```bash
audel bench --corpus ./qc-corpus      # exits non-zero unless every file grades exactly
```

## Throughput

These figures come from one 4-core laptop. Each track is graded single-threaded, so run several
jobs in parallel to use more cores.

| Workload | Wall time | Peak memory |
|---|---|---|
| 10 min stereo, `ebu_r128` | 16.1 s (about 37x realtime) | 59 MB |
| 10 min stereo, `netflix` (speech-gated) | 17.1 s | 380 MB |
