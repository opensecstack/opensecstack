# Mentorship Programme

opensecstack runs a structured mentorship programme for contributors who want to grow from occasional contributor to platform maintainer. All mentorship is voluntary and unpaid on both sides.

---

## Who this is for

- Students and early-career engineers who want to build open-source security experience
- Practitioners who know security but are new to Rust, Go, or large-scale Python projects
- Experienced engineers who want to contribute to an EU-native security stack
- Anyone preparing a conference talk or thesis around NIS2, cryptographic governance, or API security

There is no minimum experience requirement. If you have a pull request merged or have been active in Discussions for at least 30 days, you are eligible.

---

## What mentors provide

- A 1:1 call (30–60 min) to understand your goals and suggest a contribution path
- Code review priority — your PRs get reviewed within 72 hours instead of 7 days
- Architecture guidance — explaining design decisions so your contributions fit the bigger picture
- Conference prep support — if you want to present opensecstack, we help you build the talk
- A reference letter or LinkedIn recommendation after 3+ accepted contributions

Mentors do **not** write code for you. They guide, review, and unblock.

---

## What mentees commit to

- One contribution per month (code, docs, triage, or translation) while in the programme
- Show up to monthly community calls or watch the recording
- Give honest feedback about the mentorship after 3 months

---

## Duration

3 months, renewable by mutual agreement. There is no obligation to renew.

---

## How to apply

1. Open a GitHub Discussion in the **Mentorship** category
2. Use the title: `[MENTORSHIP] Your name — area of interest`
3. In the body, write:
   - What you have done in opensecstack so far (or what you want to start with)
   - What you want to learn or build
   - How many hours per week you can commit
   - Whether you prefer async (GitHub/Discord) or sync (video calls) communication

A Core Maintainer will match you with a mentor within 2 weeks.

---

## Available mentors

| Name | Platforms | Languages | Availability |
|------|-----------|-----------|-------------|
| **Erjon Bylykbashi** ([@erjonb](https://github.com/erjonb)) | CITADEL, APIGuard | Go, Python | 2 mentees max — async preferred (GitHub/Discord) |
| **Marta Kowalczyk** ([@mkowalczyk-sec](https://github.com/mkowalczyk-sec)) | NIS2 Compass, CITADEL | Python, SQL | 1 mentee — biweekly video call |
| **Sophie Vandenberghe** ([@svandenberghe](https://github.com/svandenberghe)) | vantage-hash, SDK | Rust, Go | 1 mentee — async only; strong preference for Track C (cryptography) |

If you are a maintainer who wants to mentor, add yourself via PR.

### Mentor Profiles

#### Driton Berisha
- **Expertise**: Go, distributed systems, cryptographic audit trails
- **Platforms**: GitHub, Discord
- **Languages**: Albanian, English
- **Availability**: 2 hours/week, Tuesdays 18:00–20:00 CET

#### Fjolla Gashi
- **Expertise**: Python, Flask, compliance frameworks (NIS2, ISO 27001)
- **Platforms**: GitHub, Slack
- **Languages**: Albanian, English, German
- **Availability**: 3 hours/week, flexible schedule

#### Luan Morina
- **Expertise**: Go SDK design, API client patterns, testing strategies
- **Platforms**: GitHub, Discord
- **Languages**: Albanian, English
- **Availability**: 2 hours/week, Thursdays 17:00–19:00 CET

---

## Focus tracks

### Track A — Security engineering
Contribute to APIGuard scanner modules or CITADEL governance engine. Expected output: at least one new OWASP module or one MARSHAL feature merged (VIGIL is design-stage — see `citadel/docs/vigil.md` — so VIGIL contributions are design/RFC work rather than mergeable code for now).

### Track B — Compliance and regulatory
Contribute to NIS2 Compass measure evaluators, evidence artifacts, or regulatory report templates. Prior knowledge of NIS2 Article 21 helpful but not required.

### Track C — Cryptography and low-level
Contribute to `vantage-hash`, the WORM chain, or the Ed25519 anchor rotation system. Rust experience required.

### Track D — DevOps and platform engineering
Contribute CI/CD workflows, Kubernetes manifests, Helm charts, or Docker Compose improvements. Focus on making the local dev experience and production deployment smoother.

### Track E — Documentation and advocacy
Write documentation, tutorials, or blog posts. Translate existing docs into Albanian, German, French, or Dutch. Prepare conference presentations or university lectures about opensecstack.

---

## Academic partnerships

opensecstack welcomes thesis, capstone, and research collaborations. If you are a student or lecturer looking to use opensecstack as a research platform, contact us via GitHub Discussions with the tag `[ACADEMIC]`.

Past and planned academic topics:
- NIS2 compliance automation and evidence chain integrity
- Cryptographic governance for critical infrastructure
- Time Dimension Segmentation as a hashing strategy
- Separation of Duties enforcement in open-source platforms
- MVNO governance under European telecommunications regulation
