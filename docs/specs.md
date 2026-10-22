# Delivery specs

A delivery spec is the rule set a deliverable has to meet: an integrated loudness target and
tolerance, a true-peak ceiling, and optionally short-term and momentary maxima, a loudness-range
ceiling, and dialogue gating. Audel treats specs as **data**. Grading reads only the spec object,
so moving a deliverable from one platform to another never needs a code change.

## Built-in specs

```bash
audel specs
```

| Name | Integrated | Tolerance | True peak | Extra | Miss is |
|---|---|---|---|---|---|
| `ebu_r128` | -23 LUFS | ±0.5 LU | -1 dBTP | | rejected |
| `ebu_r128_s1` | -23 LUFS | ±0.5 LU | -1 dBTP | short-term ≤ -18 LUFS | rejected |
| `atsc_a85` | -24 LKFS | ±2 LU | -2 dBTP | | rejected |
| `op59` | -24 LKFS | ±1 LU | -2 dBTP | | rejected |
| `arib_tr_b32` | -24 LKFS | ±1 LU | -1 dBTP | | rejected |
| `netflix` | -27 LKFS | ±2 LU | -2 dBTP | speech-gated | rejected |
| `spotify` | -14 LUFS | ±2 LU | -1 dBTP | music | advisory |
| `youtube` | -14 LUFS | ±2 LU | -1 dBTP | | advisory |
| `apple_music` | -16 LUFS | ±2 LU | -1 dBTP | music | advisory |
| `apple_podcasts` | -16 LUFS | ±1 LU | -1 dBTP | speech | advisory |
| `podcast` | -16 LUFS | ±2 LU | -1 dBTP | speech | advisory |

A **rejected** miss is graded `error`, so the verdict is `fail`. Broadcasters reject deliveries
that miss their loudness spec. An **advisory** miss is graded `warning`, because streaming
platforms normalize playback loudness themselves.

The values follow the published recommendations. Contracts often tighten them. When yours does,
write a custom spec rather than relying on a built-in.

## Use a spec

=== "CLI"

    ```bash
    audel check promo.wav --spec ebu_r128_s1
    audel qc master.mxf --spec atsc_a85 --html qc.html --json qc.json
    ```

=== "Python"

    ```python
    from audel import check

    report = await check("promo.wav", spec="ebu_r128_s1")
    print(report.spec, report.verdict, [t.integrated_lufs for t in report.tracks])
    ```

=== "Environment"

    ```bash
    export AUDEL_DELIVERY_SPEC=ebu_r128        # default for every check
    export AUDEL_CONTENT_TYPE=speech           # enables the speech noise-floor check
    ```

=== "REST"

    ```bash
    curl -F file=@promo.wav -F spec=ebu_r128_s1 http://127.0.0.1:8000/check
    curl http://127.0.0.1:8000/specs
    ```

With no spec set, Audel grades exactly as 0.1 did. It uses the `AUDEL_LOUDNESS_TARGET` preset
with a ±2 LU advisory tolerance, and the report shows `spec: "preset.podcast"`.

## Custom specs

An operator spec is a JSON file. Unknown keys are rejected and every value is range-checked.

```json
{
  "name": "acme_tv",
  "description": "ACME network delivery, 2026 contract",
  "integrated_lufs": -24,
  "tolerance_lu": 1,
  "max_true_peak_dbtp": -2,
  "max_short_term_lufs": -20,
  "max_lra_lu": 15,
  "gating": "program",
  "strictness": "reject",
  "content": "mixed"
}
```

```bash
audel check ep101_mix.wav --spec /etc/audel/acme_tv.json
```

!!! note "Spec files are operator configuration"
    The CLI, the Python API and `AUDEL_DELIVERY_SPEC` accept a spec file path. The REST service and
    the MCP server accept **built-in names only**, so a remote caller or an agent can never point
    Audel at a file on the host.

## Dialogue gating

Some specs measure loudness over speech only. Audel approximates dialogue gating in three steps.
It finds speech with the Silero voice-activity detector bundled in faster-whisper, listening to
every channel except LFE on its own, from one streamed decode high-passed at 100 Hz. A downmix
would miss dialogue in some immersive channels, or in channels mixed in antiphase. A detected
passage counts only where its channel is audible in the mix, within 20 dB of the loudest
channel at that moment, so a voice buried under music elsewhere isn't taken for dialogue. It then
computes BS.1770 integrated loudness from the main pass's own 400 ms loudness blocks, counting
only blocks that lie entirely inside speech, with the standard absolute and relative gates. Then
it grades that value against the target.

The finding records `basis: "speech-gated"` and `dialogue_coverage`, the fraction of the
programme that is speech. Confidence is `medium`. If no dialogue is detected (less than 0.4 s), or
the measurement fails, the grade says so (`dialogue_unmeasured`) and uses programme loudness.
Without the `[asr]` extra, Audel falls back to programme loudness and marks the finding `low`
confidence.

!!! warning "This is an approximation"
    Speech-gated loudness is not Dolby Dialogue Intelligence. When a contract requires a licensed
    dialogue-intelligence meter, use Audel as the pre-flight check and the licensed meter for
    sign-off.
