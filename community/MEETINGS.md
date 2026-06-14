# Community Meetings

All opensecstack meetings are open to everyone unless marked **maintainers only**.

---

## Monthly community call

**When:** First Thursday of every month, 17:00 CET (16:00 UTC in winter, 15:00 UTC in summer)
**Where:** Video link posted in GitHub Discussions one week before each call
**Duration:** 60 minutes
**Language:** English (Albanian translation available on request)

### Agenda template

Each call follows this structure:

| Time | Segment | Owner |
|------|---------|-------|
| 0:00 – 0:05 | Welcome and code of conduct reminder | Host |
| 0:05 – 0:20 | Platform status updates (2–3 min per active platform) | Platform maintainers |
| 0:20 – 0:35 | RFC / ADR in progress — open discussion | RFC author |
| 0:35 – 0:50 | Community demos — show what you built | Community (sign up in Discussions) |
| 0:50 – 0:58 | Open floor — questions, blockers, shoutouts | All |
| 0:58 – 1:00 | Next call date, action items | Host |

To add a demo slot: open a comment in the Discussions thread for that month's call.

---

## Biweekly maintainer sync

**When:** Every other Monday, 10:00 CET
**Who:** Platform and Core Maintainers
**Where:** Discord `#maintainer-sync` voice channel
**Duration:** 30 minutes
**Notes:** Summary posted to GitHub Discussions after each session

### Standing agenda

1. PR queue review — anything stuck, anything needing expedited review?
2. Blocking issues — report anything that stops contributors merging
3. Security items — no detail in public; refer to private channel
4. Release planning — what goes into the next tag?
5. Action items from last sync

---

## Quarterly security review

**When:** Last week of each quarter (March, June, September, December)
**Who:** Security Team (Core Maintainers with security designation)
**Format:** Closed session; outcome summary published within 7 days

Scope:
- Review all security advisories opened in the quarter
- Re-assess threat model for any new platforms or integrations
- Audit CITADEL connector keys — rotate any that are > 90 days old
- Review WORM chain integrity report (VIGIL_DEEP output)
- Update [SECURITY.md](../SECURITY.md) if scope has changed

---

## Meeting notes archive

Notes are published as Discussions posts within 48 hours of each call.

| Date | Type | Topics | Notes |
|------|------|--------|-------|
| 2026-01-09 | Community call | v0.1.0 launch, CITADEL roadmap, SDK walkthrough | [Discussion #12](https://github.com/opensecstack/opensecstack/discussions) |
| 2026-02-06 | Community call | APIGuard v0.6.0 CITADEL integration, TripleHash design | [Discussion #18](https://github.com/opensecstack/opensecstack/discussions) |
| 2026-03-06 | Community call | vantage-hash crate, IRFlow design preview, EU conference recap | [Discussion #24](https://github.com/opensecstack/opensecstack/discussions) |

---

## Host rotation — April to June 2026

Community calls rotate between Core Maintainers and Ambassadors. If you want to host or co-host, open a PR adding your name to the rotation below.

| Date | Host | Topic |
|------|------|-------|
| April 7, 2026 | Marek Kowalski (Poland) | NIS2 transposition progress in Central Europe |
| April 21, 2026 | Giulia Rossi (Italy) | API fuzzing strategies for OWASP Top 10 |
| May 5, 2026 | Sophie Dubois (Belgium) | DORA compliance tooling roadmap |
| May 19, 2026 | Elira Hoxha (Albania) | Adoption challenges in EU candidate countries |
| June 2, 2026 | Arben Krasniqi | APIGuard v0.2.0 scan engine improvements |
| June 16, 2026 | Community | v0.2.0 release retrospective & v0.3.0 planning |

---

## Proposing a topic

To get a topic on the agenda:

1. Open or find a GitHub Discussion in the **Community Calls** category
2. Add a comment with: `[TOPIC] Your topic — 5-min or 15-min slot`
3. The host will confirm inclusion one week before the call

Topics added within 48 hours of the call may be deferred to the open floor.
