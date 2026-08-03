import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'the-two-key-principle', label: 'The two-key principle' },
  { id: 'role-groups', label: 'Canonical role groups' },
  { id: 'gate-3-checks', label: 'Gate 3 checks in order' },
  { id: 'why-hard-stop', label: 'Why HARD_STOP not REFUSE?' },
  { id: 'allowed-vs-refused', label: 'Allowed vs refused pairs' },
  { id: 'sod-scoped-actions', label: 'SoD-scoped action types' },
  { id: 'protocol-not-policy', label: 'Protocol-level, not policy-level' },
  { id: 'caller-responsibility', label: "Caller's responsibility" },
  { id: 'attack-surface', label: 'Attack surface and mitigations' },
  { id: 'auditing', label: 'Auditing SoD decisions' },
]

export default function SodPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'Separation of Duties']}
      toc={toc}
      editPath="citadel/SodPage.tsx"
      prev={{ label: 'WORM Chain & TripleHash', path: '/docs/citadel/worm' }}
      next={{ label: 'AUGUR & VIGIL', path: '/docs/citadel/augur-vigil' }}
    >
      <Helmet>
        <title>Separation of Duties | opensecstack Docs</title>
        <meta
          name="description"
          content="CITADEL's NDS gate enforces cryptographic separation of duties with a two-key principle across canonical role groups, refusing single-operator privileged actions."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/citadel/sod" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/citadel/sod" />
        <meta property="og:title" content="Separation of Duties | opensecstack Docs" />
        <meta
          property="og:description"
          content="CITADEL's NDS gate enforces cryptographic separation of duties with a two-key principle across canonical role groups, refusing single-operator privileged actions."
        />
      </Helmet>
      <h1>Separation of Duties</h1>
      <p>
        <strong>NDS</strong> (Ndarja e Detyrimeve të Sigurisë — Separation of Security Duties)
        is <a href="/docs/citadel/marshal">MARSHAL</a>'s Gate 3. It ensures that no single operator can unilaterally authorise a
        governance-relevant action: every such action requires an <strong>initiating</strong>{' '}
        identity (the operator) and a <strong>verifying</strong> identity (the verifier) that
        are cryptographically distinct at both the user and role-group levels.
      </p>
      <p>
        Unlike an access-control policy that an administrator can relax or override, NDS is
        enforced at the cryptographic protocol level: a stolen operator credential cannot
        self-approve a privileged action because it cannot also control the verifier account.
        Violating the SoD constraint causes an immediate <code>HARD_STOP</code> verdict and
        an automatic P1 incident in <a href="/docs/platforms/irflow">IRFlow</a> — not a permission-denied error that an operator
        might attempt to route around.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Gate 3 runs after Gate 1 (AuthN) and Gate 2 (AuthZ). By the time NDS evaluates, the
        actor's session has been confirmed valid and the requested action type is known to be
        permitted for the actor's role. NDS then asks: is the action backed by two genuinely
        independent identities?
      </p>
      <p>
        The check is expressed as two constraints:
      </p>
      <ol>
        <li>
          <code>sod.operator_user_id ≠ sod.verifier_user_id</code> — the same person cannot
          be both proposer and approver.
        </li>
        <li>
          The operator and verifier must belong to <strong>different role groups</strong> —
          two colleagues in the same team (same group) cannot form a valid pair, because the
          assumption is they could trivially collude.
        </li>
      </ol>

      <h2 id="the-two-key-principle">The two-key principle</h2>
      <p>
        The NDS design follows the classical two-key principle from military and nuclear
        safety: no single person can launch the missile. Translated to software governance:
      </p>
      <ol>
        <li>An <strong>operator</strong> proposes an action by filling out a Kerkese.</li>
        <li>A <strong>verifier</strong> approves it by supplying their <code>user_id</code>.</li>
        <li>
          MARSHAL evaluates both identities independently — the verifier is not a
          rubber-stamp; they carry their own session and role, and MARSHAL checks both.
        </li>
      </ol>
      <p>
        If the operator and verifier are the same person — literally (same <code>user_id</code>)
        or effectively (same role group, so they could trivially cooperate in bad faith) —
        MARSHAL issues a <code>HARD_STOP</code>.
      </p>

      <h2 id="role-groups">Canonical role groups</h2>
      <p>
        A <strong>role group</strong> is a coarser classification than a role. CITADEL
        maintains the grouping out of band. Four groups are canonical in a typical deployment:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Role group</th>
              <th>Canonical identifier</th>
              <th>Roles it contains (example)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Operations</td>
              <td><code>sig_operator</code></td>
              <td><code>ops-oncall</code>, <code>ops-shift-lead</code>, <code>ops-junior</code></td>
            </tr>
            <tr>
              <td>Security</td>
              <td><code>sig_verifier</code></td>
              <td><code>security-engineer</code>, <code>soc-analyst</code>, <code>sec-lead</code></td>
            </tr>
            <tr>
              <td>Audit</td>
              <td><code>sig_auditor</code></td>
              <td><code>auditor</code>, <code>compliance-reviewer</code></td>
            </tr>
            <tr>
              <td>Administration</td>
              <td><code>sig_admin</code></td>
              <td><code>admin</code>, <code>superadmin</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Two operators both in <code>sig_operator</code> cannot form a valid SoD pair. A pair
        must span two groups, for example <code>sig_operator ↔ sig_verifier</code> or{' '}
        <code>sig_admin ↔ sig_verifier</code>.
      </p>
      <div className="callout-note">
        <strong>Note:</strong> The <code>"unknown"</code> group is a sentinel for
        misconfigured sessions. Gate 3 deliberately does not force a HARD_STOP on unknown
        groups to avoid breaking deployments during a migration. Set role groups explicitly
        in production — empty role groups log a <code>WARN</code> on CITADEL startup.
      </div>

      <h2 id="gate-3-checks">Gate 3 checks in order</h2>
      <CodeBlock
        language="go"
        filename="internal/marshal/marshal.go — Gate 3 (NDS)"
        code={`// 1. Same-identity check — HARD_STOP
if sod.OperatorUserID == sod.VerifierUserID {
    return HARD_STOP("NDS_SAME_IDENTITY: operator and verifier are the same user")
}

// 2. Both parties must have valid sessions — FAIL if not
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
              <th>Reason string</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Operator ID == verifier ID</td>
              <td><code>HARD_STOP</code></td>
              <td><code>NDS_SAME_IDENTITY: operator and verifier are the same user</code></td>
            </tr>
            <tr>
              <td>Operator or verifier has no valid session</td>
              <td><code>FAIL</code></td>
              <td><code>NDS_FAIL: operator/verifier has no valid session</code></td>
            </tr>
            <tr>
              <td>Both users in the same role group (not "unknown")</td>
              <td><code>HARD_STOP</code></td>
              <td><code>NDS_SAME_GROUP: operator and verifier are both in role group "X"</code></td>
            </tr>
            <tr>
              <td>Both IDs are zero (read-only / single-principal action)</td>
              <td><code>PASS</code></td>
              <td>Gate short-circuits — SoD not required for this action type</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="why-hard-stop">Why HARD_STOP not REFUSE?</h2>
      <p>
        Passing the same <code>user_id</code> for both operator and verifier is not a
        configuration mistake — it is a deliberate attempt to defeat the separation control.
        Downgrading it to <code>REFUSE</code> would invite a retry loop where the caller
        keeps submitting variations until one slips through.
      </p>
      <p>
        <code>HARD_STOP</code> escalates immediately:
      </p>
      <ul>
        <li>IRFlow auto-creates a P1 incident record.</li>
        <li>The WORM chain is anchored immediately — not at the next 100-entry boundary.</li>
        <li>The action context is locked; no further evaluation of this Kerkese is possible.</li>
        <li>Operators must resolve the incident through normal governance channels — there is no administrative override.</li>
      </ul>

      <h2 id="allowed-vs-refused">Allowed vs refused pairs</h2>
      <p>
        The following table shows example operator/verifier combinations and their Gate 3
        outcome:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Operator (user_id / group)</th>
              <th>Verifier (user_id / group)</th>
              <th>Gate 3 outcome</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>user 42 / <code>sig_operator</code></td>
              <td>user 77 / <code>sig_verifier</code></td>
              <td><code>PASS</code></td>
              <td>Different IDs, different groups — valid pair</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_operator</code></td>
              <td>user 99 / <code>sig_admin</code></td>
              <td><code>PASS</code></td>
              <td>Different IDs, different groups — valid pair</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_admin</code></td>
              <td>user 43 / <code>sig_auditor</code></td>
              <td><code>PASS</code></td>
              <td>Different IDs, different groups — valid pair</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_operator</code></td>
              <td>user 42 / <code>sig_verifier</code></td>
              <td><code>HARD_STOP</code></td>
              <td>Same user_id regardless of role group</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_operator</code></td>
              <td>user 55 / <code>sig_operator</code></td>
              <td><code>HARD_STOP</code></td>
              <td>Different IDs but same role group</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_verifier</code></td>
              <td>user 66 / <code>sig_verifier</code></td>
              <td><code>HARD_STOP</code></td>
              <td>Different IDs but same role group</td>
            </tr>
            <tr>
              <td>user 42 / <code>sig_operator</code></td>
              <td>user 77 / <code>unknown</code></td>
              <td><code>PASS</code> (with WARN)</td>
              <td>Unknown group treated as distinct — gate does not block, but logs a warning</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="sod-scoped-actions">SoD-scoped action types</h2>
      <p>
        By convention, the following action types always require SoD. Gate 2 (AuthZ) encodes
        this intent in the RBAC matrix; Gate 3 then enforces it:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Action type</th>
              <th>Why SoD is required</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>CONTAIN</code></td>
              <td>Disruptive to production; mistakes cost availability</td>
            </tr>
            <tr>
              <td><code>DELETE_RESOURCE</code></td>
              <td>Destructive — cannot be undone</td>
            </tr>
            <tr>
              <td><code>DATA_EXPORT</code></td>
              <td>Exfiltration risk — also subject to AUGUR rule_03 (HARD_STOP if no incident_id)</td>
            </tr>
            <tr>
              <td><code>CREDENTIAL_ROTATE</code></td>
              <td>Breaks active sessions; peer review prevents accidental lockouts</td>
            </tr>
            <tr>
              <td><code>POLICY_OVERRIDE</code></td>
              <td>Affects the rule that just rejected something — especially sensitive</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Read-only actions such as <code>GET_INCIDENT</code> or <code>LIST_IOCS</code> should
        not carry SoD. Gate 3 short-circuits <code>PASS</code> when both{' '}
        <code>sod.operator_user_id</code> and <code>sod.verifier_user_id</code> are zero.
      </p>

      <h2 id="protocol-not-policy">Protocol-level, not policy-level</h2>
      <p>
        Most SoD implementations are policy-level: an administrator configures a rule, and
        the same administrator can turn the rule off. CITADEL's NDS is different in a
        critical respect: it is enforced by the <strong>cryptographic session model</strong>,
        not by a configurable rule.
      </p>
      <p>
        The operator and verifier are required to have independently authenticated sessions
        — a JWT for user 42 cannot impersonate user 77. Constructing a Kerkese where the
        same human controls both sides requires a session theft, not a policy change. This
        means:
      </p>
      <ul>
        <li>No admin flag can weaken the check for a single request.</li>
        <li>
          A compromised operator credential alone is insufficient — the attacker also needs
          a separate verifier credential in a different role group.
        </li>
        <li>
          The constraint is auditable: every Gate 3 evaluation appears in the <a href="/docs/citadel/worm">WORM chain</a>,
          and every <code>HARD_STOP</code> creates an immutable incident record.
        </li>
      </ul>

      <h2 id="caller-responsibility">Caller's responsibility</h2>
      <p>
        SoD works only if the initiating and verifying identities are cryptographically
        distinct before the Kerkese reaches CITADEL. IRFlow enforces this at the service
        layer as the first line of defence:
      </p>
      <ol>
        <li>Operator logs in, receives a JWT with <code>sub=alice</code>.</li>
        <li>Operator drafts an action and POSTs it to IRFlow.</li>
        <li>
          IRFlow checks <code>actor_id (from JWT) ≠ verifier_id (from request body)</code>{' '}
          at the application layer — before calling CITADEL at all.
        </li>
        <li>
          The verifier must have separately authenticated and provided their ID. A genuinely
          distinct identity check cannot be spoofed from within a single session.
        </li>
      </ol>
      <p>
        CITADEL's Gate 3 is the second line of defence: even if IRFlow were bypassed entirely,
        MARSHAL still checks the identities against the session store.
      </p>
      <p>
        The Kerkese <code>sod</code> block looks like:
      </p>
      <CodeBlock
        language="bash"
        filename="Kerkese sod block"
        code={`"sod": {
  "operator_user_id": 42,
  "verifier_user_id": 77
}`}
      />

      <h2 id="attack-surface">Attack surface and mitigations</h2>
      <p>
        Gate 3 catches all same-identity and same-role-group attempts automatically. Two
        residual attack surfaces are worth understanding:
      </p>
      <p>
        <strong>Collusion between role groups.</strong> Gate 3 cannot detect two distinct
        users in different role groups deliberately cooperating in bad faith. Example: a
        security engineer and an operations lead agree to exfiltrate data and approve each
        other's actions.
      </p>
      <p>
        Mitigation: <strong>AUGUR rule_03</strong> forces a <code>HARD_STOP</code> on any{' '}
        <code>DATA_EXPORT</code> without an <code>incident_id</code>, regardless of SoD. The
        attack then requires fabricating an incident, which is visible to anyone querying the
        incident list. The raised visibility significantly increases detection risk.
      </p>
      <p>
        Future work (v1.2+): third-party approval for extremely sensitive actions — for
        example <code>POLICY_OVERRIDE</code> might require three distinct signatures, not two.
      </p>
      <p>
        <strong>Session hijack.</strong> An attacker holding valid JWTs for both the operator
        and verifier passes Gate 3 trivially.
      </p>
      <p>
        Mitigations: short token TTL (8 h default in sinauth), MFA on token issuance, WORM
        audit log review, anomaly detection via AUGUR rule_01 (off-hours) and rule_02
        (high-frequency submissions).
      </p>
      <p>
        <strong>Role-group misconfiguration.</strong> If role groups are not configured, Gate
        3 falls back to the same-identity check only — collusion between two users with the
        same role but different IDs becomes possible. Empty role groups log a <code>WARN</code>{' '}
        on CITADEL startup for exactly this reason.
      </p>

      <h2 id="auditing">Auditing SoD decisions</h2>
      <p>
        Every Gate 3 decision is recorded in the WORM chain. To find all HARD_STOP events
        from Gate 3:
      </p>
      <CodeBlock
        language="bash"
        filename="Query WORM for Gate 3 HARD_STOP entries"
        code={`SELECT ts_utc, payload
  FROM worm_entries
 WHERE event_type = 'marshal.decision'
   AND payload::jsonb -> 'gates' @> '[{"gate":3,"status":"HARD_STOP"}]';`}
      />
      <p>
        Any result is a potential insider threat event. The false-positive rate is
        approximately zero — every match represents a Kerkese where someone attempted a
        single-identity or same-group SoD bypass. Investigate every one.
      </p>
      <div className="callout-warning">
        <strong>Warning:</strong> A <code>HARD_STOP</code> from Gate 3 automatically creates
        a P1 incident in IRFlow. Do not close the incident without a documented investigation.
        The WORM entry is immutable and will be available to auditors for the full retention
        period.
      </div>
    </DocsLayout>
  )
}
