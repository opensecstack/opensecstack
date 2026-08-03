import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'gate-sequence', label: 'Gate sequence' },
  { id: 'gate-1-authn', label: 'Gate 1 — AuthN' },
  { id: 'gate-2-authz', label: 'Gate 2 — AuthZ' },
  { id: 'gate-3-nds', label: 'Gate 3 — NDS' },
  { id: 'gate-4-augur', label: 'Gate 4 — AUGUR' },
  { id: 'gate-5-worm', label: 'Gate 5 — WORM' },
  { id: 'kerkese-schema', label: 'Kerkese schema' },
  { id: 'worked-example', label: 'Worked example' },
  { id: 'verdicts-and-response', label: 'Verdicts and response envelope' },
  { id: 'outcome-resolution', label: 'Outcome resolution' },
  { id: 'dry-run-mode', label: 'Dry-run mode' },
  { id: 'performance', label: 'Performance' },
]

export default function MarshalPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'MARSHAL Engine']}
      toc={toc}
      editPath="citadel/MarshalPage.tsx"
      prev={{ label: 'Overview', path: '/docs/governance' }}
      next={{ label: 'WORM Chain & TripleHash', path: '/docs/citadel/worm' }}
    >
      <Helmet>
        <title>MARSHAL Engine | opensecstack Docs</title>
        <meta
          name="description"
          content="How CITADEL's MARSHAL 5-gate engine evaluates every governed action (Kerkese) — AuthN, AuthZ, NDS separation of duties, AUGUR heuristics, and WORM recording."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/citadel/marshal" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/citadel/marshal" />
        <meta property="og:title" content="MARSHAL Engine | opensecstack Docs" />
        <meta
          property="og:description"
          content="How CITADEL's MARSHAL 5-gate engine evaluates every governed action (Kerkese) — AuthN, AuthZ, NDS separation of duties, AUGUR heuristics, and WORM recording."
        />
      </Helmet>
      <h1>MARSHAL Engine</h1>
      <p>
        <strong>MARSHAL</strong> is CITADEL's 5-gate cryptographic authorisation engine. Every
        privileged action from every platform in the opensecstack ecosystem passes through it
        before execution. The outcome — <code>EXECUTE</code>, <code>REFUSE</code>, or{' '}
        <code>HARD_STOP</code> — plus the gate-by-gate reasoning is unconditionally appended to
        the <a href="/docs/citadel/worm">WORM audit chain</a> at Gate 5, regardless of whether prior gates passed.
      </p>
      <div className="callout-note">
        <strong>Note:</strong> MARSHAL was called <strong>ARBITER</strong> in early CITADEL
        designs. The renaming happened before v1.0.0. If you encounter "ARBITER" in an older ADR
        or external reference, it refers to this engine. All code, logs, and metrics use
        <code> MARSHAL</code> exclusively.
      </div>

      <h2 id="overview">Overview</h2>
      <p>
        Each governance request — called a <strong>Kerkese</strong> — flows through five sequential
        gates. Gates 1 through 4 can short-circuit the outcome verdict, but evaluation always
        continues through to Gate 5. Gate 5 <strong>always runs</strong>: an unrecorded rejection
        is worse than an unrecorded execution because it leaves no trace of attempted abuse. The
        final outcome is the maximum severity observed across all gates.
      </p>
      <p>
        MARSHAL is invoked by calling <code>POST /api/v1/marshal/evaluate</code> on port{' '}
        <code>8099</code>. See the <a href="/docs/citadel-integration">CITADEL Integration</a> guide for how platforms register and connect.
        Every platform connector must include an{' '}
        <code>X-Citadel-Signature</code> HMAC-SHA256 header computed over{' '}
        <code>key_id + timestamp + body_hash</code>. Requests outside a ±300-second timestamp
        window are rejected before any gate runs.
      </p>

      <h2 id="gate-sequence">Gate sequence</h2>
      <CodeBlock
        language="bash"
        filename="MARSHAL gate sequence"
        code={`Kerkese → Gate 1 (AuthN) → Gate 2 (AuthZ) → Gate 3 (NDS) → Gate 4 (AUGUR) → Gate 5 (WORM)
          (session)     (RBAC)         (SoD)        (heuristics)   (audit — always runs)
                                                                           ↓
                                                                    Final decision written`}
      />
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Gate</th>
              <th>Name</th>
              <th>Responsibility</th>
              <th>Fail verdict</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>1</td>
              <td>AuthN</td>
              <td>Ed25519 session verification — confirms <code>actor.user_id</code> has a valid session and the claimed role matches the session's recorded role</td>
              <td><code>REFUSE</code></td>
            </tr>
            <tr>
              <td>2</td>
              <td>AuthZ</td>
              <td>RBAC permission check — confirms the actor's role is permitted to perform the requested <code>action.type</code></td>
              <td><code>REFUSE</code></td>
            </tr>
            <tr>
              <td>3</td>
              <td>NDS</td>
              <td><a href="/docs/citadel/sod">Separation of Duties</a> — <code>operator_user_id ≠ verifier_user_id</code> and the two identities must belong to different role groups</td>
              <td><code>HARD_STOP</code></td>
            </tr>
            <tr>
              <td>4</td>
              <td>AUGUR</td>
              <td><a href="/docs/citadel/augur-vigil">Behavioural heuristics</a> — flags off-hours actions, high-frequency submissions, and <code>DATA_EXPORT</code> without a linked incident</td>
              <td><code>WARN</code> / <code>HARD_STOP</code></td>
            </tr>
            <tr>
              <td>5</td>
              <td>WORM</td>
              <td>Unconditional append — writes the full decision (Kerkese, outcome, all gate results, reasons) to the immutable audit chain regardless of the outcome</td>
              <td><code>WARN</code> (does not reverse prior outcome)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="gate-1-authn">Gate 1 — AuthN (Authentication)</h2>
      <p>
        Gate 1 asks: does <code>actor.user_id</code> have a valid session, and does the claimed
        <code> role</code> match what the session recorded?
      </p>
      <p>
        Implementation: <code>Store.SessionExists(ctx, userID)</code> returns the session's
        recorded <code>(role, roleGroup, exists, err)</code> tuple. If the lookup returns an error,
        or no session exists, or the claimed role in the Kerkese does not equal the session role,
        Gate 1 fails.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Condition</th>
              <th>Reason string</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Session lookup error</td>
              <td><code>AUTH_ERROR: session lookup failed for user_id=N</code></td>
            </tr>
            <tr>
              <td>No session exists</td>
              <td><code>AUTH_FAIL: no valid session for user_id=N</code></td>
            </tr>
            <tr>
              <td>Claimed role ≠ session role</td>
              <td><code>AUTH_FAIL: claimed role "X" does not match session role "Y"</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Outcome on fail: <code>REFUSE</code>. Approximate latency on an in-memory store:{' '}
        <strong>~0.8 µs</strong>.
      </p>

      <h2 id="gate-2-authz">Gate 2 — AuthZ (Authorisation)</h2>
      <p>
        Gate 2 asks: is <code>actor.role</code> permitted to perform <code>action.type</code>?
        The check is implemented as an in-code RBAC map (<code>roleAllowed(role, actionType)</code>).
        Typical mapping: <code>admin</code> can perform any action; <code>operator</code> can
        execute <code>CONTAIN</code>, <code>PATCH</code>, <code>CREATE_INCIDENT</code>; an{' '}
        <code>verifier</code> can execute <code>VERIFY</code>.
      </p>
      <p>
        If the role/action pair is absent from the map, Gate 2 returns{' '}
        <code>REFUSE</code> with reason{' '}
        <code>AUTHZ_FAIL: role "X" is not permitted to perform "Y"</code>. Approximate
        latency: <strong>~0.3 µs</strong>.
      </p>

      <h2 id="gate-3-nds">Gate 3 — NDS (Separation of Duties)</h2>
      <p>
        Gate 3 enforces the two-key principle: the action must be backed by two distinct
        identities that belong to different role groups. The checks run in order:
      </p>
      <CodeBlock
        language="go"
        filename="internal/marshal/marshal.go (Gate 3 sketch)"
        code={`// 1. Same-identity check — HARD_STOP
if sod.OperatorUserID == sod.VerifierUserID {
    return HARD_STOP("NDS_SAME_IDENTITY: operator and verifier are the same user")
}

// 2. Both parties must have valid sessions
opSession := store.SessionExists(operatorUserID)
vfSession  := store.SessionExists(verifierUserID)

// 3. Role-group check — HARD_STOP
if opSession.roleGroup == vfSession.roleGroup && opSession.roleGroup != "unknown" {
    return HARD_STOP("NDS_SAME_GROUP: operator and verifier are both in role group X")
}`}
      />
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Condition</th>
              <th>Status</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Operator ID == verifier ID</td>
              <td><code>HARD_STOP</code></td>
              <td><code>NDS_SAME_IDENTITY: operator and verifier are the same user</code></td>
            </tr>
            <tr>
              <td>Either user lacks a valid session</td>
              <td><code>FAIL</code></td>
              <td><code>NDS_FAIL: operator/verifier has no valid session</code></td>
            </tr>
            <tr>
              <td>Both users in the same role group (not "unknown")</td>
              <td><code>HARD_STOP</code></td>
              <td><code>NDS_SAME_GROUP: operator and verifier are both in role group "X"</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Same-identity is a <code>HARD_STOP</code>, not a <code>REFUSE</code>, because passing
        the same user ID for both parties is a deliberate attempt to defeat the separation
        control. Downgrading it to REFUSE would invite a retry loop. A HARD_STOP escalates
        to IRFlow's P1 incident auto-creation and a project freeze. Approximate Gate 3
        latency: <strong>~1.2 µs</strong>.
      </p>

      <h2 id="gate-4-augur">Gate 4 — AUGUR (Behavioural Heuristics)</h2>
      <p>
        Gate 4 applies pre-emptive behavioural analysis. AUGUR reads from a read-only mirror
        database and does not modify state. Three rules are evaluated in sequence; rule_03 can
        override the result of rules 01 and 02.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Trigger</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>rule_01</td>
              <td>Action initiated outside 07:00–19:00 UTC</td>
              <td><code>WARN</code></td>
            </tr>
            <tr>
              <td>rule_02</td>
              <td>Same actor performed more than 10 actions in 5 minutes</td>
              <td><code>WARN</code> (appended to existing reason)</td>
            </tr>
            <tr>
              <td>rule_03</td>
              <td><code>action.type == "DATA_EXPORT"</code> AND <code>action.incident_id</code> is empty</td>
              <td><code>HARD_STOP</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        rule_03 overrides anything set by rules 01 and 02 because data exfiltration without an
        incident context is the highest-risk pattern MARSHAL tracks. A <code>WARN</code> status
        from rules 01 or 02 does not block execution on its own — Gate 4's contribution is
        additive. The final outcome becomes <code>REFUSE</code> only if an earlier gate said
        so; <code>HARD_STOP</code> from rule_03 takes precedence unconditionally. Approximate
        Gate 4 latency: <strong>~1.5 µs</strong>.
      </p>

      <h2 id="gate-5-worm">Gate 5 — WORM (Audit)</h2>
      <p>
        Gate 5 commits the full decision to the append-only WORM chain:
      </p>
      <CodeBlock
        language="go"
        filename="Gate 5 append call"
        code={`Store.AppendWORM(ctx, source, eventType, projectID, payload)
// payload = full JSON of the decision:
//   kerkese, outcome, all five gate results, reason strings, latencies`}
      />
      <p>
        If the WORM append fails (e.g. the database is temporarily unreachable), Gate 5 logs
        a <code>WARN</code> result on itself but does <strong>not</strong> reverse the outcome
        of gates 1–4. The decision still stands; only the audit trail for that specific entry
        is lost. The metric <code>citadel_worm_append_failures_total</code> increments and an
        alert fires — Ops must resolve this urgently.
      </p>
      <p>
        The <code>project_id</code> field defaults to <code>"citadel"</code> when the Kerkese
        carries none. This lets auditors partition chain queries per tenant, service, or
        regulator jurisdiction without scanning the full log.
      </p>
      <p>
        Gate 5 is the dominant performance cost. With a synchronous PostgreSQL 16 write the
        typical latency is <strong>4.22 ms</strong>, dwarfing the sub-2 µs total of gates 1–4.
        Candidates for v1.1+ optimisation: batched appends and per-<code>project_id</code>{' '}
        sharded chains (v2.0).
      </p>

      <h2 id="kerkese-schema">Kerkese schema</h2>
      <p>
        A <strong>Kerkese</strong> (Albanian: <em>request</em>) is the canonical envelope every
        caller sends to <code>POST /api/v1/marshal/evaluate</code>. The schema is at v2.0.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Type</th>
              <th>Required</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>execution_id</code></td>
              <td>UUID</td>
              <td>Recommended</td>
              <td>Caller-supplied idempotency key. CITADEL generates one server-side if absent, but callers should always provide their own so retries across CITADEL restarts remain coherent.</td>
            </tr>
            <tr>
              <td><code>project_id</code></td>
              <td>string</td>
              <td>No</td>
              <td>Logical WORM chain partition. Defaults to <code>"citadel"</code>.</td>
            </tr>
            <tr>
              <td><code>actor.user_id</code></td>
              <td>int64</td>
              <td>Yes</td>
              <td>Primary key into CITADEL's session store. Gate 1 looks up the session.</td>
            </tr>
            <tr>
              <td><code>actor.role</code></td>
              <td>string</td>
              <td>Yes</td>
              <td>Claimed role. Gate 1 rejects if it does not match the session; Gate 2 uses it for RBAC.</td>
            </tr>
            <tr>
              <td><code>sod.operator_user_id</code></td>
              <td>int64</td>
              <td>Conditional</td>
              <td>The initiating user. Must equal <code>actor.user_id</code>. Required for SoD-sensitive action types.</td>
            </tr>
            <tr>
              <td><code>sod.verifier_user_id</code></td>
              <td>int64</td>
              <td>Conditional</td>
              <td>The approving counterparty. Must differ from <code>operator_user_id</code> and belong to a different role group.</td>
            </tr>
            <tr>
              <td><code>action.type</code></td>
              <td>string</td>
              <td>Yes</td>
              <td>Canonical verb: <code>CREATE_INCIDENT</code>, <code>CONTAIN</code>, <code>RESTORE</code>, <code>DATA_EXPORT</code>, <code>VERIFY</code>, etc.</td>
            </tr>
            <tr>
              <td><code>action.incident_id</code></td>
              <td>string</td>
              <td>Conditional</td>
              <td>Scope binding. Required for <code>DATA_EXPORT</code> (AUGUR rule_03 causes HARD_STOP if absent). Recommended for every mutation.</td>
            </tr>
            <tr>
              <td><code>action.payload_hash</code></td>
              <td>string</td>
              <td>No</td>
              <td>Digest of the caller's action payload (e.g. <code>sha256:...</code>). Not used for gate evaluation — anchored to WORM for forensics.</td>
            </tr>
            <tr>
              <td><code>dry_run</code></td>
              <td>boolean</td>
              <td>No</td>
              <td>When <code>true</code>, MARSHAL returns a full Decision but skips the Gate 5 WORM append. Never <code>true</code> on a production path.</td>
            </tr>
            <tr>
              <td><code>ts_utc</code></td>
              <td>RFC3339</td>
              <td>Yes</td>
              <td>Time the caller built the Kerkese. AUGUR rule_01 uses the hour portion to check operating-hours compliance.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        At ingress, CITADEL validates: JSON parses; <code>actor.user_id {'>'} 0</code>;{' '}
        <code>actor.role != ""</code>; <code>action.type != ""</code>; <code>ts_utc</code> is
        valid RFC3339. All other checks are gate-level.
      </p>

      <h2 id="worked-example">Worked example</h2>
      <p>
        The following Kerkese represents <a href="/docs/platforms/irflow">IRFlow</a> asking CITADEL to authorise a containment action
        on incident <code>inc_2026_0123</code>. Operator user 42 (role: <code>operator</code>)
        initiates; verifier user 77 (a different role group) approves.
      </p>
      <CodeBlock
        language="bash"
        filename="POST /api/v1/marshal/evaluate — request body"
        code={`{
  "execution_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98",
  "project_id":   "prod",

  "actor": {
    "user_id": 42,
    "role":    "operator"
  },

  "sod": {
    "operator_user_id": 42,
    "verifier_user_id": 77
  },

  "action": {
    "type":         "CONTAIN",
    "incident_id":  "inc_2026_0123",
    "payload_hash": "sha256:abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890"
  },

  "dry_run": false,
  "ts_utc":  "2026-04-19T10:12:03Z"
}`}
      />

      <h2 id="verdicts-and-response">Verdicts and response envelope</h2>
      <p>
        MARSHAL returns one of three verdicts for every Kerkese evaluation:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>EXECUTE</code></td>
              <td>All gates passed — the action is authorised and has been WORM-logged. The caller may proceed.</td>
            </tr>
            <tr>
              <td><code>REFUSE</code></td>
              <td>A gate check failed (insufficient role, AUGUR advisory) — the action is denied and logged. The caller must not proceed.</td>
            </tr>
            <tr>
              <td><code>HARD_STOP</code></td>
              <td>A critical violation was detected (SoD breach, <code>DATA_EXPORT</code> without incident, spoofing) — the action is denied, a P1 incident is auto-created in IRFlow, and the chain is anchored immediately. Irreversible.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="callout-warning">
        <strong>Warning:</strong> A <code>HARD_STOP</code> verdict is irreversible. It locks the
        action context and creates an immutable incident record in the WORM chain. Operators must
        resolve the incident through normal governance channels — there is no administrative
        override.
      </div>
      <p>
        The response envelope for the worked example above (all gates passing) looks like:
      </p>
      <CodeBlock
        language="bash"
        filename="Decision response (EXECUTE)"
        code={`{
  "execution_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98",
  "outcome":      "EXECUTE",
  "dry_run":      false,
  "ts_utc":       "2026-04-19T10:12:03.412Z",
  "gates": [
    { "gate": 1, "name": "AuthN",  "status": "PASS", "latency_ms": 0.84 },
    { "gate": 2, "name": "AuthZ",  "status": "PASS", "latency_ms": 0.21 },
    { "gate": 3, "name": "NDS",    "status": "PASS", "latency_ms": 1.12 },
    { "gate": 4, "name": "AUGUR",  "status": "PASS", "latency_ms": 1.43 },
    { "gate": 5, "name": "WORM",   "status": "PASS", "latency_ms": 4.22 }
  ],
  "reasons":       [],
  "worm_entry_id": "wo_0000017234"
}`}
      />
      <p>
        <code>reasons</code> is empty when <code>outcome == EXECUTE</code>. Otherwise it contains
        the concatenated reason strings from all failing gates in gate order. The{' '}
        <code>worm_entry_id</code> is present whenever Gate 5 succeeded — callers can quote this
        ID when later retrieving the WORM entry for <a href="/docs/citadel/evidence">forensics</a>. The entry is present even when
        gates 1–4 rejected the call, because Gate 5 always runs.
      </p>
      <p>
        A REFUSE from Gate 2 (wrong role) would look like:
      </p>
      <CodeBlock
        language="bash"
        filename="Decision response (REFUSE)"
        code={`{
  "execution_id": "9b3c1f2a-0011-4e78-b42a-d88e9cf10003",
  "outcome":      "REFUSE",
  "dry_run":      false,
  "ts_utc":       "2026-04-19T11:05:44.107Z",
  "gates": [
    { "gate": 1, "name": "AuthN",  "status": "PASS",   "latency_ms": 0.79 },
    { "gate": 2, "name": "AuthZ",  "status": "REFUSE",  "latency_ms": 0.18,
      "reason": "AUTHZ_FAIL: role \\"viewer\\" is not permitted to perform \\"CONTAIN\\"" },
    { "gate": 3, "name": "NDS",    "status": "SKIP",   "latency_ms": 0.00 },
    { "gate": 4, "name": "AUGUR",  "status": "SKIP",   "latency_ms": 0.00 },
    { "gate": 5, "name": "WORM",   "status": "PASS",   "latency_ms": 4.19 }
  ],
  "reasons":       ["AUTHZ_FAIL: role \\"viewer\\" is not permitted to perform \\"CONTAIN\\""],
  "worm_entry_id": "wo_0000017235"
}`}
      />

      <h2 id="outcome-resolution">Outcome resolution</h2>
      <p>
        The final outcome is the <strong>maximum severity</strong> observed across gates 1–4:
      </p>
      <CodeBlock
        language="bash"
        filename="Severity ordering"
        code={`EXECUTE  <  REFUSE  <  HARD_STOP`}
      />
      <p>
        If any gate escalated to <code>HARD_STOP</code>, the outcome is <code>HARD_STOP</code>{' '}
        — even if a later gate would have returned <code>REFUSE</code> or <code>EXECUTE</code>.
        Reason strings from every failing gate are concatenated into{' '}
        <code>decision.reasons[]</code> for debugging and forensic review.
      </p>

      <h2 id="dry-run-mode">Dry-run mode</h2>
      <p>
        Setting <code>dry_run: true</code> in the Kerkese instructs MARSHAL to produce a full
        Decision without calling the Gate 5 WORM append. Use cases:
      </p>
      <ul>
        <li>Caller-side integration tests.</li>
        <li>Policy validation before rollout ("what would happen if…?").</li>
        <li>Reproducing an audit finding locally without polluting the live chain.</li>
      </ul>
      <div className="callout-warning">
        <strong>Warning:</strong> Dry-run decisions leave no trace. <code>worm_entry_id</code>{' '}
        will be absent from the response. Never set <code>dry_run: true</code> on a production
        path — doing so means the action will happen with no audit record.
      </div>

      <h2 id="performance">Performance</h2>
      <p>
        Measured on Go 1.24.4, Intel Core i7-7600U, in-memory mock store unless noted.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Step</th>
              <th>Latency</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Gate 1 — AuthN</td>
              <td>~0.8 µs</td>
              <td>In-memory session lookup</td>
            </tr>
            <tr>
              <td>Gate 2 — AuthZ</td>
              <td>~0.3 µs</td>
              <td>Static RBAC map lookup</td>
            </tr>
            <tr>
              <td>Gate 3 — NDS</td>
              <td>~1.2 µs</td>
              <td>Two session lookups + group check</td>
            </tr>
            <tr>
              <td>Gate 4 — AUGUR</td>
              <td>~1.5 µs</td>
              <td>Three rule evaluations in sequence</td>
            </tr>
            <tr>
              <td>Gate 5 — WORM (PostgreSQL 16, sync)</td>
              <td>4.22 ms</td>
              <td>Includes immutability trigger and fsync</td>
            </tr>
            <tr>
              <td><strong>Total evaluate (mocked store)</strong></td>
              <td><strong>7.55 µs</strong></td>
              <td>All 5 gates, no real DB</td>
            </tr>
            <tr>
              <td><strong>Total evaluate (real DB)</strong></td>
              <td><strong>~5 ms</strong></td>
              <td>Dominated by Gate 5 PostgreSQL append</td>
            </tr>
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
