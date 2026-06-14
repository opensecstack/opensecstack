"""Abuse-mailbox triage.

Parses an RFC822 message, pulls out the artefacts an analyst cares
about (URLs, attachments, originating IPs, auth-results), runs the
bundled YARA rule-set across both headers and decoded body parts, and
returns a multi-label classification.

YARA is the heavy lifter — pure-Python text matching is reserved for
extraction (URLs, IPs) and for the auth-results parser.
"""

from __future__ import annotations

import email
import email.message
import email.policy
import hashlib
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.utils import parseaddr
from pathlib import Path
from typing import Any

try:  # yara-python is an optional runtime dep — degrade if missing.
    import yara

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — covered via _YARA_AVAILABLE branch
    yara = None  # type: ignore[assignment,unused-ignore]
    _YARA_AVAILABLE = False


_URL_EXTRACT_RE = re.compile(
    r"https?://[^\s<>\"')]+",
    re.IGNORECASE,
)
# Trailing punctuation that's almost never part of a URL but commonly
# trails one in prose ("visit https://x.com.").
_URL_TRAILING_PUNCT = ".,;:!?)]"
_IP_EXTRACT_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"
)


@dataclass
class Attachment:
    """One MIME attachment surfaced from the message."""

    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class AuthResults:
    """Best-effort parse of Authentication-Results header(s)."""

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


@dataclass
class TriageResult:
    """Output of :func:`triage_email`."""

    subject: str
    from_address: str
    return_path: str | None
    received_chain: list[str]
    originating_ips: list[str]
    auth_results: AuthResults
    urls: list[str]
    attachments: list[Attachment]
    yara_matches: list[str]
    classification: list[str]
    confidence: float
    iocs: list[str] = field(default_factory=list)


# ── YARA loader ───────────────────────────────────────────────────────────────


_compiled_yara: Any | None = None


def _default_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def load_rules(rules_dir: Path | None = None) -> Any | None:
    """Compile all *.yar files under ``rules_dir`` once and cache."""
    global _compiled_yara
    if not _YARA_AVAILABLE:
        return None
    if _compiled_yara is not None and rules_dir is None:
        return _compiled_yara
    rules_dir = rules_dir or _default_rules_dir()
    files = {p.stem: str(p) for p in rules_dir.glob("*.yar")}
    if not files:
        return None
    compiled = yara.compile(filepaths=files)
    if rules_dir == _default_rules_dir():
        _compiled_yara = compiled
    return compiled


# ── Parsing helpers ───────────────────────────────────────────────────────────


def _parse_message(raw: bytes) -> email.message.EmailMessage:
    return email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[return-value,unused-ignore]


def _flatten_text(msg: email.message.EmailMessage) -> str:
    """Concatenate every text/* part. HTML is left as-is — the YARA
    rule-set inspects raw HTML for credential forms."""
    chunks: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype.startswith("text/"):
            try:
                chunks.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    chunks.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def _attachments(msg: email.message.EmailMessage) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.iter_attachments():
        raw = part.get_payload(decode=True)
        payload: bytes = raw if isinstance(raw, bytes) else b""
        out.append(
            Attachment(
                filename=part.get_filename() or "unnamed",
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return out


def _extract_urls(text: str) -> list[str]:
    cleaned = (u.rstrip(_URL_TRAILING_PUNCT) for u in _URL_EXTRACT_RE.findall(text))
    return list(dict.fromkeys(cleaned))


def _received_chain(msg: email.message.EmailMessage) -> list[str]:
    headers = msg.get_all("Received") or []
    return [str(h).strip() for h in headers]


def _extract_originating_ips(received: list[str]) -> list[str]:
    """Pull RFC-routable IPs out of the Received chain.

    We exclude RFC1918, loopback, and link-local explicitly rather than
    using ``ip.is_private`` — Python's ``is_private`` is broad and
    includes RFC5737 documentation ranges (e.g. 203.0.113.0/24), which
    are exactly the addresses our integration fixtures use.
    """
    seen: set[str] = set()
    out: list[str] = []
    for hop in received:
        for candidate in _IP_EXTRACT_RE.findall(hop):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                continue
            if isinstance(ip, ipaddress.IPv4Address) and any(
                ip in net for net in _RFC1918_V4
            ):
                continue
            text = str(ip)
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


_RFC1918_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _parse_auth_results(msg: email.message.EmailMessage) -> AuthResults:
    raw = msg.get("Authentication-Results", "") or ""
    spf = _first_match(raw, r"\bspf\s*=\s*([a-z]+)")
    dkim = _first_match(raw, r"\bdkim\s*=\s*([a-z]+)")
    dmarc = _first_match(raw, r"\bdmarc\s*=\s*([a-z]+)")
    return AuthResults(spf=spf, dkim=dkim, dmarc=dmarc)


def _first_match(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).lower() if m else None


# ── Classification ────────────────────────────────────────────────────────────


def _yara_classifications(matches: Iterable[Any]) -> list[str]:
    """Read the per-rule ``classification`` meta into a deduped list."""
    out: list[str] = []
    seen: set[str] = set()
    for m in matches:
        meta = getattr(m, "meta", {}) or {}
        cls = meta.get("classification")
        if isinstance(cls, str) and cls not in seen:
            seen.add(cls)
            out.append(cls)
    return out


def _confidence_for(
    yara_classes: list[str],
    auth: AuthResults,
    sender: str,
    return_path: str | None,
) -> float:
    """Heuristic confidence on the multi-label classification.

    We start from a baseline derived from how many rules fired, then
    adjust on auth-results sanity (a SPF-fail + DKIM-fail mail with
    'phishing' or 'malware' tags is high-confidence), and on
    From-vs-Return-Path divergence (a classic spoofing tell).
    """
    if not yara_classes:
        return 0.0
    base = min(0.4 + 0.2 * len(yara_classes), 0.8)
    fails = sum(1 for v in (auth.spf, auth.dkim, auth.dmarc) if v == "fail")
    base += 0.05 * fails
    if return_path:
        s_dom = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
        rp_dom = return_path.rsplit("@", 1)[-1].lower() if "@" in return_path else ""
        if s_dom and rp_dom and s_dom != rp_dom:
            base += 0.1
    if "legitimate" in yara_classes and len(yara_classes) > 1:
        # Conflicting signal — back off the overall confidence.
        base -= 0.2
    return round(min(max(base, 0.0), 1.0), 3)


def _resolve_classification(yara_classes: list[str]) -> list[str]:
    """Return the labels in priority order; default to 'unknown'."""
    if not yara_classes:
        return ["unknown"]
    priority = ["malware", "phishing", "scam", "legitimate"]
    ordered = [c for c in priority if c in yara_classes]
    return ordered or yara_classes


# ── Public entry point ────────────────────────────────────────────────────────


def triage_email(raw: bytes, *, rules_dir: Path | None = None) -> TriageResult:
    """Parse, scan, and classify one RFC822 message."""
    msg = _parse_message(raw)
    subject = str(msg.get("Subject", "")).strip()
    from_address = parseaddr(str(msg.get("From", "")))[1]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1] or None

    received = _received_chain(msg)
    originating_ips = _extract_originating_ips(received)
    body_text = _flatten_text(msg)
    urls = _extract_urls(body_text)
    attachments = _attachments(msg)
    auth = _parse_auth_results(msg)

    rules = load_rules(rules_dir)
    yara_match_names: list[str] = []
    yara_classes: list[str] = []
    if rules is not None:
        # Scan the entire raw mail (headers + body) so rules that match
        # on Content-Disposition + base64 payload still fire.
        try:
            matches = rules.match(data=raw)
        except Exception:
            matches = []
        yara_match_names = [str(m.rule) for m in matches]
        yara_classes = _yara_classifications(matches)

    classification = _resolve_classification(yara_classes)
    confidence = _confidence_for(yara_classes, auth, from_address, return_path)

    iocs: list[str] = []
    iocs.extend(originating_ips)
    iocs.extend(urls)
    for att in attachments:
        if att.sha256:
            iocs.append(att.sha256)

    return TriageResult(
        subject=subject,
        from_address=from_address,
        return_path=return_path,
        received_chain=received,
        originating_ips=originating_ips,
        auth_results=auth,
        urls=urls,
        attachments=attachments,
        yara_matches=yara_match_names,
        classification=classification,
        confidence=confidence,
        iocs=list(dict.fromkeys(iocs)),
    )
