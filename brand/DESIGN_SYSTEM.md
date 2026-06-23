# Trio Design System — "Warm Paper"

One visual family across **AgentVision** (eyes 👁), **Audel** (ears 👂), **Verel** (brain 🧠).
Elegant, subtle, professional. Light-first, printed-document calm. **No gradients, no glows, no
neon.** Accent appears sparingly — a margin rule, an eyebrow, a single word — never as the loud
element.

Authorship signature: a quiet `— amitpatole` line, set in the accent ink, in every footer and the
corner of every social card. (Maker's-mark *form* TBD — this spec reserves the slot.)

**Restraint on ornament.** No decorative emoji in headings, eyebrows, nav, or wordmarks. The accent
dot and hairline carry identity. Emoji, if ever used, is confined to prose where it clarifies meaning
— never as a brand device.

## Palette

| Token            | Hex       | Use                                            |
| ---------------- | --------- | ---------------------------------------------- |
| `--bg`           | `#f7f5f1` | warm off-white page base                       |
| `--surface`      | `#fffdf9` | cards / raised panels                          |
| `--panel`        | `#efece4` | code blocks, quiet fills                       |
| `--ink`          | `#1b1a17` | primary text                                   |
| `--ink-muted`    | `#6b6862` | secondary text                                 |
| `--ink-faint`    | `#918d84` | captions, metadata                             |
| `--rule`         | `#e3ded4` | hairlines (1px), borders                       |

Per-sense accent. Two tiers: **`accent`** (mid-tone, for rules/marks/decoration) and **`accent-ink`**
(darker, AA ≥4.5:1 on `--bg`, for accent-colored *text*).

| Sense                | accent    | accent-ink | emoji |
| -------------------- | --------- | ---------- | ----- |
| Eyes — AgentVision   | `#3a8a99` | `#256b78`  | 👁     |
| Ears — **Audel**     | `#c4943f` | `#90641a`  | 👂     |
| Brain — Verel        | `#7a72b5` | `#564f8c`  | 🧠     |

## Type

- **Display / headings:** Source Serif 4 (editorial serif; screen-optimized; pairs with Inter).
- **Body / UI:** Inter (already in use across both existing sites).
- **Code / mono:** ui-monospace, JetBrains Mono.

Headings set tight (`letter-spacing:-.01em`), regular-to-semibold weight — never heavy. Body at
comfortable measure (~66ch max). Generous line-height (1.6 body).

## Principles

1. **Whitespace is the design.** Air around everything; let the page breathe.
2. **One accent per view.** A single hairline or eyebrow carries the sense color. Resist coloring more.
3. **Hairlines, not boxes.** Separate with 1px `--rule`; avoid heavy borders and fills.
4. **No motion gimmicks, no gradients, no shadows beyond a whisper.** Flat, printed sensibility.
5. **Mono for the literal.** Commands, code, version strings only.

## Where it applies

- MkDocs Material: `palette.scheme: default` (light) + an `extra.css` mapping these tokens onto
  Material's `--md-*` variables; `font.text: Inter`, headings overridden to Source Serif 4.
- Social cards (1280×640): warm-paper template, accent-dot eyebrow ("Ears · The audio sense"),
  serif wordmark, one accent margin rule, mono `pip install` chip, `— amitpatole` corner signature.
- Favicon / corner mark: a reserved monogram in accent ink (no emoji).

Retrofit order: prove on **Audel** (no site yet), then bring **AgentVision** and **Verel** to match.
