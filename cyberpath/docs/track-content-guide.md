# CyberPath Track Content Guide

> Authoring guide for learning tracks. Targets content authors —
> internal staff, community contributors, instructors with subject-
> matter expertise. Read this before opening a PR that adds or
> modifies a track.
>
> Status: design intent for v1.0.0 / v1.0.0. Concrete linter rules
> and CLI flags will firm up as `cyberpath-cli` lands. The schema in
> this document is the contract — implementations conform to the
> schema, not the other way around.

A CyberPath track is a versioned, bilingual unit of curriculum that
produces audit-grade completion evidence. Authoring a track is *not*
the same as authoring a Moodle course: every change you make ends up
hashed, sealed into the CITADEL WORM ledger, and referenced by every
learner certificate that was issued against that revision. Treat
content like code.

## File layout

Track content lives under `content/<track-id>/` in the deployment's
content repository (separate repo from the platform code, pulled
under Apache 2.0). The convention:

```
content/
  phishing-recognition/
    track.yaml                           # track metadata + module list
    lessons/
      01-what-is-phishing.sq.md
      01-what-is-phishing.en.md
      02-spotting-spear-phishing.sq.md
      02-spotting-spear-phishing.en.md
    quizzes/
      knowledge-check.yaml
    labs/
      recognise-spear-phishing/
        lab.yaml
        assets/
          sample-1.eml
          sample-2.eml
    glossary/
      sq.yaml
      en.yaml
    CHANGELOG.md
```

`<track-id>` is the slug. Lowercase, hyphenated, ASCII only. Match
the value of `track.yaml.id`.

## Track YAML schema

```yaml
# content/phishing-recognition/track.yaml
id:      phishing-recognition         # slug; matches directory name
version: 1.4.0                        # semver per track (see Versioning)
title:
  sq:  "Njohja e phishing-ut"
  en:  "Phishing recognition"
description:
  sq:  "Njohja e emaileve, vishing dhe smishing phishing."
  en:  "Recognising phishing emails, vishing, and smishing."

audience:
  - all-staff
  - non-technical

# NIS2 Article 21 measure mappings. Use the art21.{a..i,j} pattern
# from docs/nis2-integration.md. Do NOT invent measure ids.
nis2_mappings:
  primary:    art21.g                 # cyber hygiene + training
  secondary:
    - art21.i                         # human resources & access control awareness

prerequisites:
  - nis2-article-21-awareness         # other track ids

duration_minutes: 120                 # estimated learner time, validated by linter
language_source:  sq                  # canonical authoring language

modules:
  - id:    intro
    order: 1
    title:
      sq: "Hyrje në phishing"
      en: "Introduction to phishing"
    lessons:
      - 01-what-is-phishing
    quiz: ~                           # no quiz at this module
    lab:  ~

  - id:    spotting
    order: 2
    title:
      sq: "Si ta dallosh phishing-un"
      en: "How to spot phishing"
    lessons:
      - 02-spotting-spear-phishing
    quiz: knowledge-check             # references quizzes/knowledge-check.yaml
    lab:  recognise-spear-phishing    # references labs/recognise-spear-phishing/

certification:
  offered:               true
  level:                 baseline     # baseline | practitioner | expert
  expires_after_months:  12           # null for non-expiring

# Computed by `cyberpath-cli content lint`; do not edit by hand.
content_hash: "blake3:b6c1...e3"

changelog:
  - version: 1.4.0
    date:    2027-04-10
    changes:
      - "Added vishing module (non-breaking)."
  - version: 1.3.0
    date:    2027-02-01
    breaking: true                    # invalidates in-flight enrolments
    changes:
      - "Removed deprecated 2018 phishing samples."
```

### Module YAML (nested)

Modules are inline under `track.yaml` as shown above. Each module
references lesson slugs (resolved to `lessons/<slug>.{sq,en}.md`),
optionally one quiz, and optionally one lab. A module with neither
quiz nor lab is permitted but flagged by the linter as
`module-thin`; reading-only modules are allowed for awareness tracks
where hands-on practice is genuinely not applicable.

### Lesson schema (markdown body)

Lessons are paired markdown files: one per language. The two files
must have matching front-matter:

```yaml
---
id:                 02-spotting-spear-phishing
order:              2
duration_minutes:   25                # used to validate track duration
video:              "https://cdn.example/cyberpath/spear-phishing.mp4"
video_caption:      "https://cdn.example/cyberpath/spear-phishing.sq.vtt"
checkpoints:
  - at_seconds:     90
    type:           reflection
    prompt:
      sq: "Sa nga këto sinjale ke parë në email-et e tua këtë javë?"
      en: "How many of these signals have you seen in your email this week?"
---

# Si ta dallosh phishing-un e drejtuar (spear phishing)

Spear phishing-u përdor informacion të veçantë për ty ose
organizatën tënde...

```python
# Optional code block, syntax-highlighted in the learner UI.
# The language hint is required and validated by the linter.
def is_suspicious(sender: str) -> bool:
    return sender.endswith("@suspicious.example")
```
```

Rules for the markdown body:

- One H1 only, matches the lesson title.
- All images use relative paths inside the track directory.
- All images carry alt text in the lesson's language.
- Code blocks must declare a language (`bash`, `python`, `go`, `js`,
  `yaml`, `text`). The linter rejects unlabeled fences.
- Interactive checkpoints must reference timestamps that exist in
  the video; the linter cross-checks against the WebVTT track.

### Quiz schema

```yaml
# content/phishing-recognition/quizzes/knowledge-check.yaml
id:               knowledge-check
randomise:        true                # shuffle question order
randomise_choices: true
pass_threshold:   0.80                # 80% to pass
questions:
  - id:    q1
    type:  multiple-choice
    prompt:
      sq: "Cili nga të mëposhtmit është një sinjal i phishing-ut?"
      en: "Which of the following is a phishing signal?"
    choices:
      - id: a
        text:
          sq: "Adresa e dërguesit nuk përputhet me domain-in zyrtar"
          en: "Sender address doesn't match the official domain"
      - id: b
        text:
          sq: "Email-i është nënshkruar me PGP"
          en: "The email is PGP-signed"
    correct: [a]
    explanation:
      sq:  "Mospërputhja e domain-it është një sinjal klasik."
      en:  "Domain mismatch is a classic signal."

  - id:    q2
    type:  true-false
    prompt:
      sq: "Smishing është phishing nëpërmjet SMS."
      en: "Smishing is phishing via SMS."
    correct: true
    explanation:
      sq: "Po — 'SMS phishing' = smishing."
      en: "Yes — 'SMS phishing' = smishing."

  - id:    q3
    type:  code-fill
    prompt:
      sq: "Plotëso shprehjen që kontrollon nëse domain-i nuk përputhet:"
      en: "Complete the expression that checks for a domain mismatch:"
    template: |
      def domain_matches(sender: str, expected: str) -> bool:
          return sender.split("@")[1] ___ expected
    correct: ["==", "is"]             # accepted answers
    explanation:
      sq:  "'==' krahason vlerat."
      en:  "'==' compares values."

  - id:    q4
    type:  scenario
    prompt:
      sq: "Marrë një email që pretendon se vjen nga CEO-ja..."
      en: "You receive an email claiming to be from the CEO..."
    choices:
      - id: a
        text:
          sq: "Përgjigju menjëherë siç kërkohet"
          en: "Reply immediately as requested"
      - id: b
        text:
          sq: "Verifiko nëpërmjet një kanali tjetër (telefon, Slack)"
          en: "Verify via a separate channel (phone, Slack)"
    correct: [b]
    explanation:
      sq: "Verifiko jashtë-bandë para se të veprosh."
      en: "Verify out-of-band before acting."
```

Question types:

| Type | Use for |
|---|---|
| `multiple-choice` | Single or multi-select; `correct` is a list of choice ids |
| `true-false`      | Boolean fact-check; `correct` is `true` or `false` |
| `code-fill`       | Short code snippet completion; `correct` is a list of accepted strings (exact match, trimmed) |
| `scenario`        | Decision-based; structurally a multiple-choice but rendered with extra context framing |

Every question must carry an `explanation` shown after submission —
this is non-negotiable. Quizzes without explanations are rejected by
the linter.

## Versioning

Each track follows semver:

- **Patch** (`1.4.0` → `1.4.1`): typo fixes, clarifications, alt-text
  additions. Does not invalidate in-flight enrolments.
- **Minor** (`1.4.0` → `1.5.0`): new optional module, additional
  questions in a quiz bank, new lab variant. In-flight enrolments
  continue against the version they started on.
- **Major** (`1.x` → `2.0.0`): breaking changes — removed lesson,
  reordered modules, raised pass threshold, changed NIS2 mapping.
  Sets `changelog[].breaking: true`. In-flight enrolments are paused
  and learners are prompted to either complete on the old version
  (within a deployment-configured grace window) or restart on the
  new version.

Completed tracks are immutable. Once a learner produces a completion
against `phishing-recognition@1.4.0`, that version is frozen for them
forever — the certificate, the WORM evidence, and the audit trail all
resolve to the exact `content_hash` at completion time.

## Localisation

CyberPath is bilingual day one (shqip + anglisht). The authoring
language is shqip — the `language_source` field declares this, and
the linter expects shqip prose to read naturally rather than as a
back-translation.

Workflow:

1. Author lesson in shqip first (`02-spotting-spear-phishing.sq.md`).
2. Translate into English (`02-spotting-spear-phishing.en.md`),
   maintaining the same headings and section order.
3. Run `cyberpath-cli content lint --check-parity` to confirm both
   files have matching front-matter, matching headings, and matching
   checkpoint timestamps.
4. Glossary references (terms like *phishing*, *spear phishing*,
   *vishing*) resolve through `glossary/sq.yaml` and `glossary/en.yaml`
   — link with `[[term:phishing]]` rather than redefining inline.

Fallback policy: if a learner's UI language is `sq` and a lesson is
missing the `.sq.md` file, the runner serves the `.en.md` file with
a banner stating the translation is pending. This is permitted only
in pre-v1.0 development; v1.0.0+ tracks must ship both languages
complete or the linter blocks publication.

## Accessibility

- **Alt text** required for every image. Decorative images use
  `alt=""` explicitly.
- **Screen-reader markup**: do not use tables for layout. Code
  blocks must have a language hint so screen readers can announce
  them properly.
- **Color-blind safe palettes** for screenshots and diagrams: prefer
  ColorBrewer "Set2" or the ecosystem-standard palette in the design
  system. Never rely on red/green alone to convey pass/fail —
  reinforce with text or icons.
- **Captions** required for any video. WebVTT files in both `sq` and
  `en`.

## Quality gates

Run before opening a PR:

```bash
# Lint everything in the track directory
cyberpath-cli content lint content/phishing-recognition/

# Validate duration estimate (sum of lesson durations vs track total)
cyberpath-cli content validate-duration content/phishing-recognition/

# Check parity between sq and en versions
cyberpath-cli content lint --check-parity content/phishing-recognition/

# Compute (or refresh) content_hash
cyberpath-cli content hash content/phishing-recognition/
```

The CI pipeline runs all of the above plus a glossary-coverage check
(every term used in lessons must resolve to the glossary).

## Review workflow

Two-eyes review is mandatory for any track change. The CODEOWNERS
file pins each track to a primary author + a security-team reviewer.
PR checklist:

- [ ] Linter clean
- [ ] Both `sq` and `en` updated (or breaking change is patch-only
      cosmetic to a single language)
- [ ] CHANGELOG entry added with correct semver bump
- [ ] If breaking, `changelog[].breaking: true` set
- [ ] NIS2 measure mappings unchanged, or PR description justifies
      the change with a link to the audit-impact assessment

After merge, the content snapshot becomes immutable: the
`content_hash` is what gets sealed into completions and certificates
issued against this version.

## Minimal example

Below is a complete minimal "Phishing recognition" track that the
linter accepts:

```yaml
# content/phishing-recognition/track.yaml
id:      phishing-recognition
version: 1.0.0
title:
  sq: "Njohja e phishing-ut"
  en: "Phishing recognition"
description:
  sq: "Si ta njohësh një email phishing."
  en: "How to recognise a phishing email."
audience:        [all-staff]
nis2_mappings:
  primary:       art21.g
  secondary:     [art21.i]
prerequisites:   []
duration_minutes: 30
language_source:  sq
modules:
  - id:     intro
    order:  1
    title:
      sq: "Hyrje"
      en: "Intro"
    lessons:  [01-what-is-phishing]
    quiz:     knowledge-check
    lab:      ~
certification:
  offered:                true
  level:                  baseline
  expires_after_months:   12
content_hash: "blake3:PLACEHOLDER"
changelog:
  - version: 1.0.0
    date:    2026-04-26
    changes: ["Initial draft."]
```

## See also

- [./module-list.md](./module-list.md) — the 8 v1.0.0 tracks
- [./lab-content-guide.md](./lab-content-guide.md) — authoring labs
- [./instructor-handbook.md](./instructor-handbook.md) — running tracks for cohorts
- [./architecture.md](./architecture.md) — content_versions table
- [./nis2-integration.md](./nis2-integration.md) — measure id taxonomy
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — community PR process
