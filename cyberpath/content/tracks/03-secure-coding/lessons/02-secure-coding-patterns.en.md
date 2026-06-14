---
id: 02-secure-coding-patterns
order: 2
duration_minutes: 90
---

# Lesson 2: Secure Coding Patterns — Input Validation, Parameterised Queries, and Secrets Management

## Learning Objectives

- Implement parameterised queries correctly in common languages and explain why they eliminate SQL injection
- Apply input validation strategies — allowlist validation, type enforcement, length limits — as a defence-in-depth layer
- Describe context-aware output encoding for XSS prevention and implement it using standard library functions
- Apply secrets management principles: never hardcode credentials, use environment variables and secrets vaults, and rotate secrets on compromise

## Parameterised Queries: Eliminating SQL Injection at the Source

The definitive fix for SQL injection is the parameterised query (also called a prepared statement). Instead of building a SQL string by concatenation, the query structure is defined separately from the data. The database driver treats user-supplied values as data, never as SQL syntax, regardless of what characters they contain.

**Python with psycopg2 (PostgreSQL):**
```python
# VULNERABLE — never do this
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# SECURE — parameterised query
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

**Java with PreparedStatement (JDBC):**
```java
// VULNERABLE
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// SECURE
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();
```

**Node.js with pg (PostgreSQL):**
```javascript
// VULNERABLE
const result = await client.query(`SELECT * FROM accounts WHERE email = '${email}'`);

// SECURE
const result = await client.query('SELECT * FROM accounts WHERE email = $1', [email]);
```

The pattern is consistent across all languages and database drivers: the query template uses placeholders, and values are passed as separate arguments. The database driver handles escaping correctly for every data type, every character, and every database engine version. An ORM (Object-Relational Mapper) provides the same protection when used correctly — but raw query methods that accept user input as part of the query string reintroduce the vulnerability.

Stored procedures are not automatically safe: stored procedures that concatenate input internally are vulnerable. The safe rule is to use parameterisation at every point where user input touches a query, whether in application code or in the database procedure itself.

## Input Validation: Defence in Depth Above the Data Layer

Parameterised queries prevent SQL injection; input validation is a complementary control that reduces the attack surface for multiple vulnerability classes simultaneously. It is not a replacement for parameterisation — it is an additional layer.

**Allowlist validation** defines what valid input looks like and rejects everything else. A username field that accepts only alphanumeric characters and underscores, length 3–32:

```python
import re

def validate_username(username: str) -> bool:
    pattern = r'^[a-zA-Z0-9_]{3,32}$'
    return bool(re.match(pattern, username))
```

This is far stronger than a denylist (blocklist) approach that tries to identify and reject known-bad characters or patterns. Denylists are inherently incomplete — attackers find bypasses. An allowlist that only permits known-good input has no bypass surface.

**Type enforcement:** Wherever a value should be numeric, convert it to an integer before any use — do not pass it as a string. If the conversion fails, reject the input:

```python
try:
    invoice_id = int(request.args.get('id'))
except (TypeError, ValueError):
    abort(400)  # Bad Request
```

This single pattern prevents a class of injection attacks, IDOR parameter tampering, and type confusion errors simultaneously.

**Length limits:** Set maximum lengths on all string inputs at the application layer, matching (and not exceeding) what the data schema defines. Excessively long inputs are a vector for buffer overflows in lower-level components, denial-of-service through expensive processing, and are almost never legitimate user data.

## Output Encoding: Preventing XSS at the Rendering Layer

Every piece of data that originated outside the application — user input, database content, API responses, URL parameters — must be encoded for its rendering context before being inserted into an HTML response.

**HTML context (element content):** Use HTML entity encoding. In Python with Jinja2 (autoescaping enabled):
```html
<!-- Jinja2 with autoescaping: safe -->
<p>{{ user_comment }}</p>

<!-- Manual escape when autoescaping is off -->
<p>{{ user_comment | e }}</p>
```

**HTML attribute context:** Values inserted into HTML attributes require attribute encoding. Never construct HTML attributes by string concatenation — use template engines that handle this automatically.

**JavaScript context:** Data inserted into JavaScript strings requires JavaScript encoding — different from HTML encoding. Inserting HTML-encoded content into a JavaScript string does not prevent XSS; `&lt;` in a JS string is still `<` to the JavaScript interpreter.

**URL context:** Values inserted into URLs must be percent-encoded using the platform's URL encoding function, not general HTML encoding.

The practical rule: use a template engine with autoescaping enabled by default (Jinja2, Django templates, Angular, React). These handle most common contexts correctly. For cases where you must build HTML manually, use the platform's dedicated escaping functions for each context — and never use `innerHTML` or equivalent raw HTML insertion for content that includes user data.

## Secrets Management: Never Hardcode, Always Rotate

Hardcoded credentials are a persistent, high-severity vulnerability: API keys, database passwords, cryptographic keys, and OAuth secrets embedded in source code are exposed in every copy of the repository, including git history, CI/CD logs, and any developer machine that has cloned the project.

**Rule one: never hardcode secrets.** Not in source files, not in configuration files committed to version control, not in Dockerfiles. If a secret is in your repository, treat it as compromised immediately and rotate it.

**Environment variables** are the minimum acceptable approach for non-production environments:
```python
import os
DATABASE_URL = os.environ['DATABASE_URL']  # Raises KeyError if missing — fail fast
API_KEY = os.environ.get('API_KEY')         # Returns None if missing — handle explicitly
```

Failing loudly on missing environment variables (using `os.environ['KEY']` rather than `os.environ.get('KEY')`) prevents silent fallbacks to insecure defaults.

**Secrets vaults** are the production standard: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or equivalent. Secrets are stored encrypted at rest, access is controlled by IAM policy, and every secret access is logged. Applications retrieve secrets at runtime via vault API calls or sidecar injection — the secret value never persists in environment variables or configuration files on disk.

**Rotation:** Every secret must have a defined maximum lifetime. Database passwords: rotate every 90 days or on personnel change. API keys: rotate on suspected compromise, at minimum annually. TLS certificates: automate rotation before expiry. Rotation procedures must be documented and tested before they are needed; a manual rotation process under incident pressure is an availability risk.

**Scanning for leaked secrets:** Integrate secret detection into the CI/CD pipeline. Tools such as `truffleHog`, `git-secrets`, or GitHub's built-in secret scanning detect common secret patterns (AWS key formats, private key PEM headers, API key patterns) before they reach main branches or production registries.

## Key Takeaways

- Parameterised queries with placeholder syntax — not string concatenation — are the only reliable defence against SQL injection, in every language and framework.
- Allowlist input validation is a defence-in-depth layer; define what valid input looks like and reject everything else rather than trying to identify what is invalid.
- Output encoding is context-dependent: HTML encoding, JavaScript encoding, URL encoding, and attribute encoding are different operations applied in different contexts.
- Hardcoded secrets in source code are a critical vulnerability; use environment variables at minimum and a secrets vault in production, and scan for leaked secrets in CI/CD.
- These patterns are not optional security enhancements — they are the baseline expected of NIS2-compliant software under Art.21(2)(e), and their absence constitutes a documented risk management failure.
