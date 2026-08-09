"""
Unit tests for app/notifications.py — webhook + email notification dispatch.

All functions are best-effort and never raise. No live HTTP/SMTP server is
used: urllib.request.urlopen and smtplib.SMTP are monkeypatched.
"""
import smtplib
import urllib.error
from types import SimpleNamespace

import pytest

from app import notifications


def _assessment(id_="assess-1"):
    return SimpleNamespace(id=id_)


def _control(id_="ctrl-1", measure_ref="A.5.1", remediation_due=None):
    return SimpleNamespace(id=id_, measure_ref=measure_ref, remediation_due=remediation_due)


# --------------------------------------------------------------------- #
# notify_assessment_status_change()
# --------------------------------------------------------------------- #


class TestNotifyAssessmentStatusChange:
    def test_no_op_when_webhook_url_not_configured(self, app, monkeypatch):
        calls = []
        monkeypatch.setattr(notifications, "_post_webhook", lambda *a, **kw: calls.append((a, kw)))
        with app.app_context():
            monkeypatch.setitem(app.config, "NOTIFICATION_WEBHOOK_URL", None)
            notifications.notify_assessment_status_change(_assessment(), "draft", "in_progress")
        assert calls == []

    def test_posts_correct_payload_shape(self, app, monkeypatch):
        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload

        monkeypatch.setattr(notifications, "_post_webhook", fake_post)
        with app.app_context():
            monkeypatch.setitem(app.config, "NOTIFICATION_WEBHOOK_URL", "https://hooks.example.com/x")
            notifications.notify_assessment_status_change(_assessment("a-1"), "draft", "in_progress")

        assert captured["url"] == "https://hooks.example.com/x"
        assert captured["payload"]["event"] == "assessment_status_changed"
        assert captured["payload"]["assessment_id"] == "a-1"
        assert captured["payload"]["old_status"] == "draft"
        assert captured["payload"]["new_status"] == "in_progress"
        assert "occurred_at" in captured["payload"]


# --------------------------------------------------------------------- #
# notify_control_overdue()
# --------------------------------------------------------------------- #


class TestNotifyControlOverdue:
    def test_no_op_when_webhook_url_not_configured(self, app, monkeypatch):
        calls = []
        monkeypatch.setattr(notifications, "_post_webhook", lambda *a, **kw: calls.append((a, kw)))
        with app.app_context():
            monkeypatch.setitem(app.config, "NOTIFICATION_WEBHOOK_URL", "")
            notifications.notify_control_overdue(_assessment(), _control())
        assert calls == []

    def test_posts_correct_payload_shape(self, app, monkeypatch):
        import datetime

        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload

        monkeypatch.setattr(notifications, "_post_webhook", fake_post)
        due = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        with app.app_context():
            monkeypatch.setitem(app.config, "NOTIFICATION_WEBHOOK_URL", "https://hooks.example.com/x")
            notifications.notify_control_overdue(
                _assessment("a-2"), _control("c-1", "A.5.1", remediation_due=due)
            )

        assert captured["payload"]["event"] == "control_overdue"
        assert captured["payload"]["assessment_id"] == "a-2"
        assert captured["payload"]["control_id"] == "c-1"
        assert captured["payload"]["measure_ref"] == "A.5.1"
        assert captured["payload"]["remediation_due"] == due.isoformat()

    def test_remediation_due_none_serialises_to_none(self, app, monkeypatch):
        captured = {}
        monkeypatch.setattr(notifications, "_post_webhook", lambda url, payload: captured.update(payload=payload))
        with app.app_context():
            monkeypatch.setitem(app.config, "NOTIFICATION_WEBHOOK_URL", "https://hooks.example.com/x")
            notifications.notify_control_overdue(_assessment(), _control(remediation_due=None))
        assert captured["payload"]["remediation_due"] is None


# --------------------------------------------------------------------- #
# send_email_notification()
# --------------------------------------------------------------------- #


class TestSendEmailNotification:
    def test_no_op_when_smtp_host_not_configured(self, app, monkeypatch):
        calls = []
        monkeypatch.setattr(smtplib, "SMTP", lambda *a, **kw: calls.append((a, kw)))
        with app.app_context():
            monkeypatch.setitem(app.config, "SMTP_HOST", "")
            notifications.send_email_notification("subj", "body", "to@example.com")
        assert calls == []

    def test_sends_via_smtp_with_auth(self, app, monkeypatch):
        events = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                events.append(("connect", host, port))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                events.append(("ehlo",))

            def starttls(self):
                events.append(("starttls",))

            def login(self, user, password):
                events.append(("login", user, password))

            def sendmail(self, from_addr, to_addrs, msg):
                events.append(("sendmail", from_addr, to_addrs))

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        with app.app_context():
            monkeypatch.setitem(app.config, "SMTP_HOST", "smtp.example.com")
            monkeypatch.setitem(app.config, "SMTP_PORT", "2525")
            monkeypatch.setitem(app.config, "SMTP_USER", "user1")
            monkeypatch.setitem(app.config, "SMTP_PASSWORD", "pw1")
            monkeypatch.setitem(app.config, "SMTP_FROM", "from@example.com")
            notifications.send_email_notification("Hello", "Body text", "to@example.com")

        assert ("connect", "smtp.example.com", 2525) in events
        assert ("login", "user1", "pw1") in events
        assert any(e[0] == "sendmail" and e[1] == "from@example.com" and e[2] == ["to@example.com"] for e in events)

    def test_skips_login_when_no_credentials(self, app, monkeypatch):
        events = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self):
                pass

            def login(self, user, password):
                events.append("login-called")

            def sendmail(self, *a):
                events.append("sendmail-called")

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        with app.app_context():
            monkeypatch.setitem(app.config, "SMTP_HOST", "smtp.example.com")
            monkeypatch.setitem(app.config, "SMTP_USER", "")
            monkeypatch.setitem(app.config, "SMTP_PASSWORD", "")
            notifications.send_email_notification("Hello", "Body", "to@example.com")

        assert "login-called" not in events
        assert "sendmail-called" in events

    def test_never_raises_on_smtp_failure(self, app, monkeypatch):
        def boom(*a, **kw):
            raise smtplib.SMTPConnectError(421, "down")

        monkeypatch.setattr(smtplib, "SMTP", boom)
        with app.app_context():
            monkeypatch.setitem(app.config, "SMTP_HOST", "smtp.example.com")
            # Must not raise.
            notifications.send_email_notification("Hello", "Body", "to@example.com")


# --------------------------------------------------------------------- #
# _post_webhook()
# --------------------------------------------------------------------- #


class TestPostWebhook:
    def test_posts_json_body_with_headers(self, monkeypatch):
        captured = {}

        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["data"] = req.data
            captured["content_type"] = req.get_header("Content-type")
            return FakeResp()

        monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
        notifications._post_webhook("https://hooks.example.com/x", {"event": "e", "id": 1})

        assert captured["url"] == "https://hooks.example.com/x"
        assert captured["method"] == "POST"
        assert b'"event": "e"' in captured["data"]
        assert captured["content_type"] == "application/json"

    def test_logs_warning_on_non_2xx_status_does_not_raise(self, monkeypatch):
        class FakeResp:
            status = 500

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(notifications.urllib.request, "urlopen", lambda req, timeout=None: FakeResp())
        # Must not raise.
        notifications._post_webhook("https://hooks.example.com/x", {"event": "e"})

    def test_never_raises_on_http_error(self, monkeypatch):
        def boom(req, timeout=None):
            raise urllib.error.HTTPError("https://hooks.example.com/x", 503, "unavailable", {}, None)

        monkeypatch.setattr(notifications.urllib.request, "urlopen", boom)
        # Must not raise.
        notifications._post_webhook("https://hooks.example.com/x", {"event": "e"})

    def test_never_raises_on_generic_exception(self, monkeypatch):
        def boom(req, timeout=None):
            raise ConnectionError("network unreachable")

        monkeypatch.setattr(notifications.urllib.request, "urlopen", boom)
        # Must not raise.
        notifications._post_webhook("https://hooks.example.com/x", {"event": "e"})


# --------------------------------------------------------------------- #
# _get_config()
# --------------------------------------------------------------------- #


class TestGetConfig:
    def test_returns_app_config_inside_context(self, app):
        with app.app_context():
            config = notifications._get_config()
        assert config.get("JWT_SECRET") is not None

    def test_returns_empty_dict_outside_app_context(self):
        assert notifications._get_config() == {}
