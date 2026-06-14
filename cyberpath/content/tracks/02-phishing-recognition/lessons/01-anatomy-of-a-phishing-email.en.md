---
id: 01-anatomy-of-a-phishing-email
order: 1
duration_minutes: 35
---

# Lesson 1: Anatomy of a Phishing Email

## Learning Objectives

- Identify the key structural components of a phishing email: headers, sender address, display name spoofing, and body content
- Explain how attackers manipulate email headers and authentication signals (SPF, DKIM, DMARC) to evade detection
- Recognise urgency and authority tactics used to pressure recipients into acting without thinking
- Describe the technical indicators that distinguish a phishing email from a legitimate one

## Email Headers: What You Don't See Is What Hurts You

Every email message carries a set of headers that record its journey from sender to recipient. Most mail clients hide these by default, showing only the friendly "From" display name — which is precisely what attackers exploit. Understanding headers is the first step in dissecting a suspicious message.

The **From** header contains the sender's displayed name and email address, but the displayed name is entirely attacker-controlled. An email can display `"IT Support <it-support@albtech.al>"` in the interface while the actual sending address in the technical From header reads `it-support@albtech-secure.com` — a lookalike domain registered by the attacker. Recipients who do not inspect the actual address fall for this every time.

The **Return-Path** (envelope sender) is where delivery failures go. Attackers often use a throwaway address here, creating a mismatch with the From header that is a strong phishing signal if you look for it.

**Email authentication protocols** — SPF, DKIM, and DMARC — were designed to make sender spoofing detectable. SPF (Sender Policy Framework) checks whether the sending mail server is authorised to send on behalf of the domain. DKIM (DomainKeys Identified Mail) adds a cryptographic signature verifying the email was not modified in transit. DMARC (Domain-based Message Authentication, Reporting and Conformance) tells receiving servers what to do when SPF or DKIM fails. A phishing email from a lookalike domain (`albtech-secure.com`) will pass SPF for its own domain — because the attacker controls that domain's DNS records — even though it is clearly not the legitimate organisation's domain. This is why technical authentication alone is insufficient: you must also verify the domain itself, not just its authentication status.

## Spoofing Techniques: Lookalike Domains and Display Name Fraud

Attackers use several domain spoofing techniques, each exploiting a different aspect of how humans read text quickly:

**Typosquatting:** Registering a domain with a common typo — `albetch.al`, `albteech.al`. Users scanning quickly miss the transposition.

**Homograph attacks:** Replacing Latin characters with visually identical Unicode characters — the Cyrillic "а" (U+0430) is indistinguishable from the Latin "a" (U+0061) in most fonts. The URL looks identical but resolves to a different domain.

**Subdomain abuse:** Using a legitimate-looking subdomain on a malicious domain — `albtech.al.attacker-domain.com`. The eye is drawn to the familiar brand name and ignores what follows.

**Display name spoofing:** Setting the display name to a trusted person's name without owning their domain. `"Fatmir Hoxha, CEO" <random@gmail.com>` — the name is convincing; the address is not.

## Urgency, Authority, and Psychological Pressure

Phishing emails succeed not because of technical sophistication but because of psychological manipulation. The three most effective pressure mechanisms are:

**Urgency:** "Your account will be suspended in 2 hours." "Respond immediately or your transfer will be cancelled." Urgency bypasses rational analysis — recipients act before they think. Any email demanding immediate action is a red flag, regardless of how official it appears.

**Authority:** Impersonating a CEO, a regulator (AKCESK, a bank, a court), or an IT department creates a power dynamic that inhibits questioning. Most people hesitate to verify a request that appears to come from their boss or a government authority.

**Scarcity and fear:** "Final notice." "You are under investigation." "Your files have been encrypted." Fear-inducing content triggers fight-or-flight responses that override security habits.

A reliable recognition heuristic: if an email makes you feel urgency, fear, or the need to act quickly without verifying, treat that emotional response as a warning signal, not a reason to comply.

## Key Takeaways

- Always verify the actual sending address — not just the display name — before acting on any email request.
- Lookalike domains pass SPF authentication; domain verification must be done manually by reading the full address character by character.
- Urgency and authority are the primary psychological levers phishing uses; a legitimate organisation will always tolerate a brief verification delay.
- When in doubt: do not click any link. Open the relevant site directly in a browser, or call the sender on a known phone number to verify.
- Report suspicious emails to your security team or via the designated phishing report button — every report helps protect your colleagues.
