"""
NIS2 Article 23 incident-reporting deadline computation.

This module encodes the three statutory deadlines for a "significant
incident" under EU NIS2 Directive (2022/2555) Article 23, all measured
from the moment the affected entity *became aware* of the incident:

    1. Early warning        — within 24 hours  (Article 23(4)(a))
    2. Incident notification — within 72 hours  (Article 23(4)(b)), which
       updates/confirms the early warning and gives an initial assessment
       (severity, impact, indicators of compromise where available).
    3. Final report          — within 1 month of the incident notification
       (Article 23(4)(d)), with a detailed description, root cause,
       mitigation taken, and cross-border impact where relevant.

All functions here are pure (no DB, no Flask) so the deadline arithmetic
can be unit-tested precisely against fixed points in time. The Incident
and IncidentReport models (app/models.py) call into this module rather
than duplicating the arithmetic or storing the deadlines as independent
mutable columns, which is the source-of-truth-drift risk this module
exists to avoid: the three deadlines are always a deterministic function
of Incident.detected_at (and, for the final report, Incident.resolved_at
— see final_report_due_at below), so persisting them as separately
editable columns would let them silently diverge from detected_at if
detected_at were ever corrected without a matching due-date fix-up.

KNOWN LIMITATION — the ongoing-incident extension (Article 23(4)):
if a significant incident is still ongoing at the time the final report
is due, Article 23 requires the entity to submit an *interim progress
report* at that point instead, with the true final report then due one
month after the entity actually resolves the incident. This module
implements the primary 3-deadline path in full. Of the extension case,
it implements only the resolved_at-based re-basing of the final report's
due date (see final_report_due_at) because that needs no additional
state beyond a timestamp this system already needs for other reasons.
It does NOT implement a distinct "interim progress report" obligation or
report_type — see nis2compass/docs/incident-reporting.md ("Known
limitations") for the full explanation and the manual process an
operator must currently follow for an incident that is still open when
the primary final-report deadline arrives.
"""

from datetime import datetime, timedelta

# --------------------------------------------------------------------- #
# Deadline windows (Article 23(4))
# --------------------------------------------------------------------- #

EARLY_WARNING_WINDOW = timedelta(hours=24)
NOTIFICATION_WINDOW = timedelta(hours=72)

# Article 23(4)(d) specifies "one month" without defining calendar-month
# arithmetic, and calendar months vary between 28 and 31 days. Rather than
# pull in a new dependency (e.g. python-dateutil, not currently a project
# requirement — see requirements.txt) purely for relativedelta's calendar
# semantics, this uses a fixed 30-day window. That approximation is
# deliberately conservative: for every calendar month with more than 30
# days (i.e. every 31-day month), a fixed 30-day window computes a due
# date that is EARLIER than a strict calendar-month reading would give,
# so the system never tells an organisation it has more time than the
# law actually allows. For 28/29-day months (February), the computed
# deadline is later by 1-2 days than a strict calendar-month reading —
# organisations operating in that edge case should confirm the exact
# date with their compliance/legal function; this is called out again in
# nis2compass/docs/incident-reporting.md.
FINAL_REPORT_WINDOW = timedelta(days=30)

REPORT_TYPES: tuple[str, ...] = ("early_warning", "notification", "final_report")

# The order in which Article 23 obligations logically build on one
# another: the notification "updates and, where necessary, confirms" the
# early warning (Art. 23(4)(b)), and the final report follows the
# notification (Art. 23(4)(d)). This ordering is used to reject
# out-of-sequence submissions — see app/api/incidents.py.
REPORT_TYPE_ORDER: dict[str, int] = {rt: i for i, rt in enumerate(REPORT_TYPES)}

# How far ahead of a deadline it is surfaced as "due_soon" rather than
# "on_track", so the at-risk endpoint (and any external monitoring that
# polls it) has a warning window before a legally binding deadline is
# actually missed, rather than only flagging it after the fact.
DUE_SOON_WINDOW = timedelta(hours=6)


def early_warning_due_at(detected_at: datetime) -> datetime:
    """Article 23(4)(a): within 24 hours of becoming aware of the incident."""
    return detected_at + EARLY_WARNING_WINDOW


def notification_due_at(detected_at: datetime) -> datetime:
    """Article 23(4)(b): within 72 hours of becoming aware of the incident."""
    return detected_at + NOTIFICATION_WINDOW


def final_report_due_at(detected_at: datetime, resolved_at: datetime | None = None) -> datetime:
    """Article 23(4)(d): within one month of the incident notification.

    Primary path: one month after the notification deadline (not after
    whenever the notification was actually filed — the statutory clock
    runs from the deadline for the prior obligation to keep this a pure
    function of detected_at, matching how the other two deadlines work).

    Ongoing-incident extension (partial — see module docstring): if the
    incident is still open past the primary due date and later resolves,
    `resolved_at` re-bases the due date to one month after the actual
    resolution, since Article 23(4) ties the true final-report deadline
    to resolution, not to the original notification, once an interim
    report has superseded the primary deadline. We only apply this
    re-basing when resolution happens *after* the primary due date —
    resolving earlier than that does not change anything about the
    primary path.
    """
    primary_due = notification_due_at(detected_at) + FINAL_REPORT_WINDOW
    if resolved_at is not None and resolved_at > primary_due:
        return resolved_at + FINAL_REPORT_WINDOW
    return primary_due


def due_at_for(report_type: str, detected_at: datetime, resolved_at: datetime | None = None) -> datetime:
    """Dispatch to the right *_due_at() function for a given report_type."""
    if report_type == "early_warning":
        return early_warning_due_at(detected_at)
    if report_type == "notification":
        return notification_due_at(detected_at)
    if report_type == "final_report":
        return final_report_due_at(detected_at, resolved_at)
    raise ValueError(f"unknown report_type: {report_type!r}")


def deadline_status(
    due_at: datetime,
    submitted_at: datetime | None,
    now: datetime,
    due_soon_window: timedelta = DUE_SOON_WINDOW,
) -> str:
    """Live status of a single deadline — never trust a stored status column
    for this because it is a function of wall-clock time, not just of state
    that changes on writes. Returns one of:

      - "met"       — submitted at or before its deadline
      - "missed"    — submitted after its deadline
      - "overdue"   — not yet submitted, deadline has passed
      - "due_soon"  — not yet submitted, deadline within `due_soon_window`
      - "on_track"  — not yet submitted, deadline comfortably in the future
    """
    if submitted_at is not None:
        return "met" if submitted_at <= due_at else "missed"
    if now > due_at:
        return "overdue"
    if due_at - now <= due_soon_window:
        return "due_soon"
    return "on_track"
