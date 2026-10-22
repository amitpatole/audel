# On-prem inference

Unreleased programmes, embargoed news and client masters should not leave the building. Audel can
send every model-assisted step to an Ollama server you run on your own network. The deterministic
paths never use the network at all.

## Configure

```bash
export AUDEL_LOCAL_LLM_URL=http://10.0.0.100:11434
export AUDEL_TRUSTED_BACKEND_HOSTS='["10.0.0.100"]'
export AUDEL_LOCAL_LLM_MODEL=gemma4:12b-it-qat      # the default
audel doctor
```

```text
  ✓ backend:ollama-local     reachable (Ollama 0.34.2), model gemma4:12b-it-qat
```

With `AUDEL_LOCAL_LLM_URL` set, `listen --understand` uses the `ollama-local` backend by default. You
can also name it explicitly with `--backend ollama-local`, or `backend="ollama-local"` in Python.

## Why the trusted-host list exists

Audel's SSRF guard refuses any backend URL that resolves to a private, loopback or link-local
address. That stops a misconfigured or malicious URL from reaching internal services. A LAN
inference server is private by design, so the operator has to name it explicitly in
`AUDEL_TRUSTED_BACKEND_HOSTS`, with an exact host match. Without that, doctor shows:

```text
  ✗ backend:ollama-local     refused: refusing to reach '10.0.0.100': resolves to a non-public address (SSRF protection) (add it to trusted_backend_hosts)
```

Some addresses are refused even when trusted: cloud metadata endpoints, link-local, multicast,
unspecified and reserved ranges. Backend requests refuse HTTP redirects, and responses are size
capped. A trusted server can't bounce Audel to an internal address or flood its memory.

## What the local model does

| Step | Endpoint | What is sent |
|---|---|---|
| Key messages and takeaway | `/api/chat`, text | the transcript, as delimited untrusted data |
| Delivery and tone | `/api/chat`, audio | up to three 16 kHz mono excerpts of 30 s each |
| Verbatim transcript | none | faster-whisper runs locally; Ollama serves no verbatim ASR |

`gemma4:12b-it-qat` hears audio on Ollama 0.34, where the clip goes in the message's `images` list.
We verified this with a spoken number that only the audio carried. Set `AUDEL_LOCAL_LLM_AUDIO=false`
to use the model for text only.

## Measured

These figures come from an RTX 3500 Ada laptop GPU with 12 GB, on a 10-second news read:

| Step | Time |
|---|---|
| Full `listen --understand` (hearing, ASR, key messages, one delivery excerpt) | 20.8 s |
| One warm audio-delivery call | 18 to 31 s |

Model findings are advisory. They never override a deterministic finding, and they carry medium or
low confidence in the report.
