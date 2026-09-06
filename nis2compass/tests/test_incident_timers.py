"""
Unit tests for app/incident_timers.py — pure deadline arithmetic, no DB.
"""
from datetime import datetime, timedelta, timezone

from app import incident_timers


DETECTED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class TestDeadlineComputation:
    def test_early_warning_due_at_is_24_hours_after_detection(self):
        assert incident_timers.early_warning_due_at(DETECTED) == DETECTED + timedelta(hours=24)

    def test_notification_due_at_is_72_hours_after_detection(self):
        assert incident_timers.notification_due_at(DETECTED) == DETECTED + timedelta(hours=72)

    def test_final_report_due_at_primary_path_is_one_month_after_notification(self):
        expected = DETECTED + timedelta(hours=72) + timedelta(days=30)
        assert incident_timers.final_report_due_at(DETECTED) == expected

    def test_final_report_due_at_ignores_resolution_before_primary_due_date(self):
        primary_due = incident_timers.final_report_due_at(DETECTED)
        early_resolution = primary_due - timedelta(days=10)
        assert incident_timers.final_report_due_at(DETECTED, resolved_at=early_resolution) == primary_due

    def test_final_report_due_at_rebases_after_late_resolution(self):
        primary_due = incident_timers.final_report_due_at(DETECTED)
        late_resolution = primary_due + timedelta(days=5)
        expected = late_resolution + timedelta(days=30)
        assert incident_timers.final_report_due_at(DETECTED, resolved_at=late_resolution) == expected

    def test_due_at_for_dispatches_to_the_right_function(self):
        assert incident_timers.due_at_for("early_warning", DETECTED) == incident_timers.early_warning_due_at(DETECTED)
        assert incident_timers.due_at_for("notification", DETECTED) == incident_timers.notification_due_at(DETECTED)
        assert incident_timers.due_at_for("final_report", DETECTED) == incident_timers.final_report_due_at(DETECTED)

    def test_due_at_for_rejects_unknown_report_type(self):
        try:
            incident_timers.due_at_for("bogus", DETECTED)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestDeadlineStatus:
    def test_met_when_submitted_before_due(self):
        due = DETECTED + timedelta(hours=24)
        submitted = due - timedelta(hours=1)
        now = due + timedelta(hours=10)
        assert incident_timers.deadline_status(due, submitted, now) == "met"

    def test_met_when_submitted_exactly_at_due(self):
        due = DETECTED + timedelta(hours=24)
        assert incident_timers.deadline_status(due, due, due) == "met"

    def test_missed_when_submitted_after_due(self):
        due = DETECTED + timedelta(hours=24)
        submitted = due + timedelta(minutes=1)
        now = due + timedelta(hours=1)
        assert incident_timers.deadline_status(due, submitted, now) == "missed"

    def test_overdue_when_not_submitted_and_past_due(self):
        due = DETECTED + timedelta(hours=24)
        now = due + timedelta(minutes=1)
        assert incident_timers.deadline_status(due, None, now) == "overdue"

    def test_due_soon_within_default_window(self):
        due = DETECTED + timedelta(hours=24)
        now = due - timedelta(hours=1)  # within DUE_SOON_WINDOW (6h)
        assert incident_timers.deadline_status(due, None, now) == "due_soon"

    def test_on_track_when_comfortably_before_due(self):
        due = DETECTED + timedelta(hours=24)
        now = due - timedelta(hours=12)
        assert incident_timers.deadline_status(due, None, now) == "on_track"

    def test_due_soon_boundary_is_inclusive(self):
        due = DETECTED + timedelta(hours=24)
        now = due - incident_timers.DUE_SOON_WINDOW
        assert incident_timers.deadline_status(due, None, now) == "due_soon"

    def test_custom_due_soon_window_is_respected(self):
        due = DETECTED + timedelta(hours=24)
        now = due - timedelta(hours=2)
        assert incident_timers.deadline_status(due, None, now, due_soon_window=timedelta(hours=1)) == "on_track"
        assert incident_timers.deadline_status(due, None, now, due_soon_window=timedelta(hours=3)) == "due_soon"


class TestReportTypeOrdering:
    def test_report_types_are_ordered_early_warning_first(self):
        assert incident_timers.REPORT_TYPES == ("early_warning", "notification", "final_report")

    def test_report_type_order_matches_index(self):
        for i, rt in enumerate(incident_timers.REPORT_TYPES):
            assert incident_timers.REPORT_TYPE_ORDER[rt] == i
