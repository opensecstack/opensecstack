from __future__ import annotations

import os

import pytest

from advisory.abuse_mail import (
    _YARA_AVAILABLE,
    AuthResults,
    _confidence_for,
    _resolve_classification,
    triage_email,
)


def _read(fixtures_dir: str, name: str) -> bytes:
    with open(os.path.join(fixtures_dir, name), "rb") as fh:
        return fh.read()


def test_phishing_email_extracts_url_and_classifies(fixtures_dir: str) -> None:
    raw = _read(fixtures_dir, "phishing_microsoft.eml")
    out = triage_email(raw)
    assert out.from_address == "noreply@phisher.example"
    assert "https://bit.ly/3xdeadbeef" in out.urls
    assert "203.0.113.42" in out.originating_ips
    assert out.auth_results.spf == "fail"
    assert out.auth_results.dkim == "fail"
    if _YARA_AVAILABLE:
        assert "phishing" in out.classification
        assert out.confidence > 0.5
    else:
        # No YARA → unknown classification, but parsing still works.
        assert out.classification == ["unknown"]


def test_legitimate_advisory_low_confidence(fixtures_dir: str) -> None:
    raw = _read(fixtures_dir, "legitimate_advisory.eml")
    out = triage_email(raw)
    assert out.from_address == "psirt@vendor.example"
    assert out.auth_results.spf == "pass"
    assert "https://vendor.example/security/advisories/CVE-2026-1234" in out.urls
    if _YARA_AVAILABLE:
        # Either the rule fires (legitimate) or no rule fires; either way
        # we should not classify a passing-DMARC PSIRT mail as malware.
        assert "malware" not in out.classification
        assert "phishing" not in out.classification


def test_scam_419_extraction(fixtures_dir: str) -> None:
    raw = _read(fixtures_dir, "scam_419.eml")
    out = triage_email(raw)
    assert out.from_address == "prince@scammer.example"
    assert "203.0.113.99" in out.originating_ips
    if _YARA_AVAILABLE:
        assert "scam" in out.classification


def test_originating_ips_filter_private() -> None:
    raw = (
        b"From: a@b\r\n"
        b"Received: from internal (internal [10.0.0.5]) by mx;\r\n"
        b"Received: from upstream (upstream [203.0.113.7]) by mx;\r\n"
        b"\r\n"
        b"hello"
    )
    out = triage_email(raw)
    assert out.originating_ips == ["203.0.113.7"]


def test_url_extraction_dedupes() -> None:
    raw = (
        b"From: a@b\r\nSubject: t\r\n\r\n"
        b"Visit https://example.com/x and again https://example.com/x and "
        b"https://example.com/y."
    )
    out = triage_email(raw)
    assert out.urls == ["https://example.com/x", "https://example.com/y"]


def test_resolve_classification_priority() -> None:
    assert _resolve_classification([]) == ["unknown"]
    assert _resolve_classification(["legitimate", "phishing"]) == ["phishing", "legitimate"]
    assert _resolve_classification(["scam"]) == ["scam"]


def test_confidence_for_scales() -> None:
    auth = AuthResults(spf="fail", dkim="fail", dmarc="fail")
    c = _confidence_for(["phishing"], auth, "a@evil.com", "b@spoofed.example")
    assert 0.6 < c <= 1.0


def test_attachment_sha256_present() -> None:
    raw = (
        b"From: a@b\r\nSubject: t\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="X"\r\n'
        b"\r\n"
        b"--X\r\n"
        b"Content-Type: text/plain\r\n\r\nhi\r\n"
        b"--X\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="x.bin"\r\n\r\n'
        b"ABCD\r\n"
        b"--X--\r\n"
    )
    out = triage_email(raw)
    assert len(out.attachments) == 1
    assert out.attachments[0].filename == "x.bin"
    assert len(out.attachments[0].sha256) == 64


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_loaded_default_rules_dir() -> None:
    from advisory.abuse_mail import load_rules

    rules = load_rules()
    assert rules is not None
