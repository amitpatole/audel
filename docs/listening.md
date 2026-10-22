# Hearing and listening

Hearing and listening are different things. **Hearing** perceives the signal: is there sound, is it
loud enough, is it clipped, are both channels alive. **Listening** attends to meaning: were the
right words said, could someone follow them, and did the message land.

Audel does both:

| | Hearing | Listening |
|---|---|---|
| Entry point | `check` | `listen` (runs `check` first) |
| Question | Is the signal healthy and on spec? | Was the right thing said, and can a listener follow it? |
| Grounding | ffmpeg BS.1770 meters, signal statistics | word-timed transcript (local faster-whisper) |
| Network | never | never, unless you add `understand` |

## What `listen` checks

Everything in this table is deterministic and offline. It needs the `[asr]` extra.

| `detail.check` | Finds | Severity |
|---|---|---|
| `script_omission` | script words that were never read, time-grounded to the gap | error for 3 or more words, else warning |
| `script_substitution` | words read differently from the script | error for 5 or more words, else warning |
| `script_insertion` | unscripted runs of 3 or more words (ad-libs) | warning |
| `script_adherence` | overall word error rate above 25 % | error |
| `required_term` | wording that must be said and was not, such as a legal line or sponsor read | error |
| `forbidden_term` | wording that must not be said, with a span for each occurrence | error |
| `speech_rate` | overall pace outside 110 to 190 words per minute | warning |
| `rushed_passage` | 10-second stretches well above the pace ceiling | warning |
| `long_pause` | 3 s or more of dead air inside the read | warning |
| `low_intelligibility` | a second or more the recogniser itself could barely make out | warning, low confidence |
| `track_language` | an audio track in the wrong language | error |
| `caption_text` | a cue that says something different from the audio | error or warning |
| `caption_offset` | captions consistently early or late | error |
| `caption_timing` | a single cue off the speech | warning |
| `caption_reading_rate` | a cue faster than 20 characters per second | warning |
| `caption_missing` | 3 s or more of speech with no caption | warning |
| `caption_format` | zero-length or overlapping cues | warning |

Recognition is not ground truth. Audel treats a run of missing script words as the strong
signal and a single changed word as a weak one. Use a larger whisper model (`AUDEL_ASR_MODEL=small`
or `large-v3`, with `AUDEL_ASR_DEVICE=cuda` on a GPU host) when you need fewer recognition errors.

## Understanding (opt-in)

With `understand=True`, a model also answers what a deterministic pass cannot:

- **Key messages.** Did each intended message come across? Each one becomes a `Conformance`
  claim. A miss is a warning, or an error if the message has a `must:` prefix.
- **Takeaway.** The one sentence an ordinary listener would leave with.
- **Delivery.** An audio-capable model hears excerpts from the beginning, middle and end, and labels
  delivery, pace and intelligibility. When the brief names a `tone`, a mismatch is reported.

Every model finding is advisory, marked `source: audio_llm` with medium or low confidence. The
transcript is passed as untrusted, delimited data, and the model is told never to follow
instructions inside it.

## Example

This is real output for a short news read. The run used the approved script, an SRT file, one
required line, two key messages and an expected calm tone. Understanding ran on an on-prem model
(see [On-prem inference](on-prem.md)).

```bash
audel listen read.wav --script script.txt --captions caps.srt \
  --require "terms and conditions apply" \
  --understand --key-message "must: heavy rain is coming tonight" \
  --key-message "the bridge on the A1 is closed" --tone calm
```

```text
FAIL  10 issue(s) — 28 words at 197 wpm, script adherence 74%, 3 caption cues
  • [loudness/warning] [0–10337ms] integrated loudness (programme) -20.2 LUFS is 4.2 LU quieter than the preset.podcast target (-16 ±2 LU)
  • [other/warning] [0–9860ms] speech rate 197 words/min is rushed (comfortable range 110-190)
  • [transcript_mismatch/warning] [1600–2180ms] script says "news at six", heard "new matrix"
  • [transcript_mismatch/error] [5200–5480ms] script line not heard: "with flooding possible near the river"
  • [transcript_mismatch/error] [0–10337ms] read departs from the script: 74% adherence (word error rate 26%)
  • [other/warning] [2600–3200ms] cue 2 reads at 132 characters/s (limit 20): too fast to read
  • [transcript_mismatch/error] [2600–3200ms] cue 2 says "Heavy rain will spread across the north tonight and into tomorrow morning across all regions." but the audio there says "heavy rain will"
  • [transcript_mismatch/error] [6000–9000ms] cue 3 says "Sport is next." but the audio there says "drivers are urged to take care on the roads terms and conditions"
  • [intent_mismatch/warning] [0–10337ms] key message not conveyed: the bridge on the A1 is closed (The transcript does not mention the A1 bridge.)
  • [intent_mismatch/warning] [0–9860ms] delivery heard as urgent; the brief asks for calm
  takeaway: Heavy rain is expected across the North tonight, and drivers are advised to be cautious.
  heard [0–9860ms]: urgent, pace normal, clear
    [must] satisfied: heavy rain is coming tonight
    [should] violated: the bridge on the A1 is closed
```

The "new matrix" substitution is a recognition error on robotic synthesized speech. Audel graded it
as a warning, not an error, for exactly that reason.

## Python

```python
from audel import listen

report = await listen(
    "promo.wav",
    spec="ebu_r128_s1",
    script=open("promo_script.txt").read(),
    required=["terms and conditions apply"],
    forbidden=["acme"],
    captions=open("promo.srt").read(),
    languages={1: "es"},                        # track 1 must be Spanish
    understand=True, key_messages=["the offer ends Friday"], tone="warm",
)
print(report.verdict, report.listening.wpm, report.listening.script_adherence)
```

`report.listening` holds the measurements behind the findings. It has the language, word count,
words per minute, longest pause, mean word confidence, script adherence and WER, term hits,
caption statistics, per-track languages, the takeaway and the delivery readings.

## REST and MCP

`POST /listen` takes the media file plus form fields: `script`, `captions` (SRT or WebVTT text),
repeatable `require`, `forbid`, `language` (`TRACK=CODE`) and `key_message`, and also `tone`,
`spec` and `content`. Understanding over REST is off unless the operator sets
`AUDEL_REST_ALLOW_UNDERSTAND=true`, and the backend allowlist still applies.

The MCP tool `listen_audio` takes script and caption **text**, never file paths, so an agent
cannot use it to read files on the host.
