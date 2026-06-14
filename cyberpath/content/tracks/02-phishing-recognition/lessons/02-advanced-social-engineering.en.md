---
id: 02-advanced-social-engineering
order: 2
duration_minutes: 40
---

# Lesson 2: Advanced Social Engineering — Spear Phishing, Vishing, and BEC

## Learning Objectives

- Distinguish between mass phishing campaigns and targeted spear-phishing attacks and explain why spear phishing is significantly more dangerous
- Describe how business email compromise (BEC) works and identify the specific verification steps that prevent it
- Explain vishing (voice phishing) techniques and how attackers build credibility over the phone
- Apply a consistent decision framework when any communication — email, phone, or message — requests a sensitive action

## Spear Phishing: When the Attacker Knows You

Mass phishing is a numbers game: send millions of generic emails and a small percentage will click. Spear phishing inverts this: send one highly personalised email to a specific high-value target. The attacker invests time in reconnaissance before sending anything.

Attackers build targeting profiles from multiple open sources: LinkedIn for job titles, reporting lines, and recent activity; company websites for project names and partner relationships; social media for personal details (recent travel, interests, family names) that add authenticity to the message; and public procurement portals or press releases that reveal ongoing business relationships. A spear-phishing email referencing a real project name, a colleague's name, and a plausible business context is convincing to the point where even security-aware recipients have been deceived.

The distinguishing characteristic of a spear-phishing email is personalisation that could not exist in a mass campaign. If an email correctly names your direct manager, references a project you are actually working on, and arrives at a moment when you are under deadline pressure, the attacker has done their homework. The defensive response is not to be impressed but to apply verification steps regardless: verify the sender's identity through a separate channel before acting.

## Business Email Compromise: The Most Expensive Phishing Variant

Business Email Compromise (BEC) is a category of spear phishing that specifically targets financial transactions or data exfiltration through impersonation of executives, finance counterparts, or trusted suppliers. BEC losses run into billions of dollars annually and are one of the highest-impact threat categories for organisations of all sizes.

The classic BEC scenario: an attacker compromises or spoofs the email account of a company's CEO. They then email the CFO or a finance team member with an urgent request to transfer funds to a new account — framed as a confidential acquisition, a regulatory settlement, or an overdue supplier payment. The email explains why normal approval processes must be bypassed. The money moves before anyone realises the request was fraudulent.

Variants include **supplier impersonation BEC** (the attacker spoofs a known supplier and sends a revised payment instruction with a new bank account number) and **employee data harvesting BEC** (an attacker impersonating HR requests all employees' tax forms or payroll data).

The defence against BEC is procedural, not technical: establish and enforce a **call-back verification rule** for all payment instructions and changes to payment details. Before processing any wire transfer or changing a supplier's bank account, call the requestor on a phone number from your address book — not from the email — and verbally confirm the instruction. This single control defeats BEC regardless of how convincing the email appears.

## Vishing: Social Engineering Over the Phone

Vishing (voice phishing) is social engineering conducted over a phone call. The attacker calls the target impersonating IT support, a bank fraud team, a government agency (AKCESK, the tax authority), or a known colleague. Caller ID spoofing allows attackers to display any number they choose, including internal extensions or legitimate government numbers.

Common vishing scripts:
- "I'm from IT support. We've detected unusual activity on your account. I need your current password to lock it down before the attack spreads."
- "This is your bank's fraud team. We've detected a suspicious transaction. I need to verify your card number and PIN to stop the payment."
- "I'm calling from AKCESK. We've received a report that your organisation's systems are compromised. I need remote access to investigate."

The common thread: urgency, authority, and a request for credentials, payment, or access. Legitimate IT support, banks, and regulators never ask for passwords over the phone. Legitimate IT support can reset accounts without your current password. Any caller who insists they need your password or remote access is — without exception — a threat actor or making an error.

The defensive rule for phone calls: never provide credentials, payment information, or remote access in response to an inbound call. Hang up and call back on a known-good number independently retrieved. This applies even if the caller ID appears legitimate — it can be spoofed.

## Decision Framework for Suspicious Communications

Apply this four-question framework to any unexpected communication requesting a sensitive action:

1. **Is this request unexpected?** Legitimate processes rarely arrive as surprises. An unexpected request is a signal to slow down.
2. **Does it involve urgency, secrecy, or bypassing normal procedures?** Any of these is a social engineering red flag.
3. **Can I verify the sender's identity through a separate channel?** Always verify through a channel you initiate — not one provided by the potential attacker.
4. **What is the cost of verification versus the cost of being wrong?** Verification takes two minutes. An unrecovered BEC transfer or a ransomware deployment caused by a clicked link costs orders of magnitude more.

## Key Takeaways

- Spear phishing uses reconnaissance to create personalised, believable messages; the defence is always out-of-band verification, not better email scrutiny alone.
- BEC attacks are defeated by a single enforced procedural control: call-back verification on a known phone number before any payment instruction is acted on.
- Caller ID can be spoofed; never trust inbound callers claiming authority. Always hang up and call back on an independently obtained number.
- Urgency, authority, and requests to bypass normal procedures are universal social engineering signals — they apply equally to email, phone, and messaging platforms.
- Report all suspected social engineering attempts to the security team promptly; what targets you once will target your colleagues next.
