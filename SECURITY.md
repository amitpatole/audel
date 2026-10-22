# Security policy

Audel grades untrusted media. It decodes files with ffmpeg, can fetch URLs, can drive a headless
browser, and can send audio or transcripts to a configured model provider. We treat that surface
seriously and welcome reports.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (including release candidates) | yes |
| 0.1.x | security fixes until 1.0.0 final ships |
| older | no |

## Reporting a vulnerability

Please report privately. Do not open a public issue for an unfixed vulnerability.

- Use GitHub's private advisory form: <https://github.com/amitpatole/audel/security/advisories/new>
- Or email amit.patole@gmail.com with the subject `audel security`.

Include the Audel version, how you ran it (library, CLI, REST, MCP), and a minimal reproduction.
We aim to acknowledge within 3 working days and to ship a fix or mitigation for confirmed
high-severity issues within 30 days. We credit reporters in the CHANGELOG unless you ask us not to.

## How Audel is hardened

The threat model and every control are documented at
<https://amitpatole.github.io/audel/security/>. In short:

- **Decode is bounded.** Byte, duration, sample-rate and channel caps are enforced before decode.
  ffmpeg runs in argv form with no shell, under a wall-clock timeout and `RLIMIT_*` limits.
- **`check` and `listen` (offline mode) never touch the network.** Egress only happens on the paths
  that are documented to use a provider, and `AUDEL_EGRESS=deny` refuses them outright.
- **Every outbound URL is SSRF-vetted** and connections are pinned to the vetted IP, which closes
  DNS rebinding.
- **The REST service fails closed.** It refuses a routable bind without authentication, compares
  credentials in constant time, authenticates before reading request bodies, and caps body size,
  concurrency and request rate.
- **No default secrets.** Provider keys come from the environment or `~/.config/<Provider>/key`
  and are scrubbed from logs.

No audit removes all risk. ffmpeg, the Python runtime, model providers and the host OS remain in
your trust boundary. Run the service in a container with a read-only root filesystem and no
ambient credentials.
