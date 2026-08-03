import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'augur-gate-4', label: 'AUGUR — Gate 4 in MARSHAL' },
  { id: 'rule-catalogue', label: 'Rule catalogue (v1.0.0)' },
  { id: 'rule-01-off-hours', label: 'rule_01 — Off-hours action', level: 3 as const },
  { id: 'rule-02-high-frequency', label: 'rule_02 — High frequency', level: 3 as const },
  { id: 'rule-03-data-export', label: 'rule_03 — DATA_EXPORT without incident', level: 3 as const },
  { id: 'severity-table', label: 'Status severity' },
  { id: 'verdict-influence', label: 'How heuristics influence the verdict' },
  { id: 'irflow-interaction', label: 'Interaction with IRFlow' },
  { id: 'observability', label: 'Observability' },
  { id: 'tuning', label: 'Tuning guidance' },
  { id: 'vigil', label: 'VIGIL — Ecosystem health monitor' },
  { id: 'vigil-states', label: 'GREEN / AMBER / RED states', level: 3 as const },
  { id: 'vigil-inputs', label: 'Telemetry inputs', level: 3 as const },
  { id: 'vigil-marshal', label: 'Interaction with MARSHAL', level: 3 as const },
  { id: 'vigil-timeline', label: 'Implementation timeline', level: 3 as const },
]

export default function AugurVigilPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'AUGUR & VIGIL']}
      toc={toc}
      editPath="citadel/AugurVigilPage.tsx"
      prev={{ label: 'Separation of Duties', path: '/docs/citadel/sod' }}
      next={{ label: 'Evidence & Audit', path: '/docs/citadel/evidence' }}
    >
      <Helmet>
        <title>AUGUR &amp; VIGIL | opensecstack Docs</title>
        <meta
          name="description"
          content="AUGUR's behavioural heuristics for pre-emptive anomaly detection at MARSHAL Gate 4, and VIGIL, the GREEN/AMBER/RED ecosystem health monitor."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/citadel/augur-vigil" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/citadel/augur-vigil" />
        <meta property="og:title" content="AUGUR & VIGIL | opensecstack Docs" />
        <meta
          property="og:description"
          content="AUGUR's behavioural heuristics for pre-emptive anomaly detection at MARSHAL Gate 4, and VIGIL, the GREEN/AMBER/RED ecosystem health monitor."
        />
      </Helmet>
      <h1>AUGUR &amp; VIGIL</h1>
      <p>
        This page covers the two behavioural and health-monitoring subsystems of CITADEL.
        <strong> AUGUR</strong> is the behavioural-heuristics layer at Gate 4 of the <a href="/docs/citadel/marshal">MARSHAL
        engine</a> — it asks whether a request <em>fits the normal pattern</em> of how the caller
        behaves, catching insider abuse and credential-compromise attacks that pass cleanly
        through the first three gates. <strong>VIGIL</strong> is the ecosystem-wide health
        monitor that synthesises telemetry from every SIN platform into a single colour-coded
        signal (GREEN / AMBER / RED).
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Gates 1–3 of MARSHAL answer an authorisation question: <em>"is this caller allowed
        to do this?"</em>. AUGUR at Gate 4 asks a different question: <em>"does this action
        fit the normal behavioural pattern for this caller?"</em>. A credential-compromise
        or insider attack may clear every permission check while still exhibiting observable
        anomalies — unusual timing, burst frequency, or a data export with no associated
        investigation. AUGUR surfaces those signals before the action reaches the <a href="/docs/citadel/worm">WORM log</a>.
      </p>
      <p>
        AUGUR reads from a <strong>read-only mirror database</strong>. It does not hold locks
        on the main write path and cannot itself delay or block WORM appends. Its influence on
        MARSHAL outcomes is mediated entirely through the verdict mechanism described below.
      </p>

      <h2 id="augur-gate-4">AUGUR — Gate 4 in MARSHAL</h2>
      <p>
        AUGUR is the fourth gate in the five-gate MARSHAL pipeline. The gate sequence is:
      </p>
      <CodeBlock
        language="bash"
        filename="MARSHAL gate sequence"
        code={`Request
  → Gate 1: AuthN   (Ed25519 signature)
  → Gate 2: AuthZ   (RBAC permission check)
  → Gate 3: NDS     (actor ≠ verifier, SoD enforcement)
  → Gate 4: AUGUR   (behavioural heuristics)
  → Gate 5: WORM    (unconditional append — every request is logged)`}
      />
      <p>
        AUGUR evaluates its rule catalogue against the incoming{' '}
        <strong>Kerkese</strong> (the CITADEL governance request object) and emits one of three
        statuses: <code>PASS</code>, <code>WARN</code>, or <code>HARD_STOP</code>. That status
        is then factored into the overall MARSHAL verdict before the WORM append at Gate 5.
      </p>

      <h2 id="rule-catalogue">Rule catalogue (v1.0.0)</h2>
      <p>
        Three rules ship with v1.0.0. They are intentionally conservative — an enterprise
        can tune thresholds through configuration, but the rule <em>shape</em> is stable and
        WORM-observable so auditors can reproduce decisions without re-running the engine.
        Expanding the catalogue is explicitly out of scope until v1.2, at which point a
        rule-as-code plugin system becomes justifiable.
      </p>

      <h3 id="rule-01-off-hours">rule_01 — Off-hours action</h3>
      <p>
        <strong>Condition:</strong> the request's <code>ts_utc</code> falls outside the
        07:00–19:00 UTC business-hours window.
      </p>
      <CodeBlock
        language="go"
        filename="rule_01 condition"
        code={`// Gate 4 — rule_01
if kerkese.TsUtc.Hour() < 7 || kerkese.TsUtc.Hour() >= 19 {
    reasons = append(reasons,
        fmt.Sprintf("AUGUR_rule_01: action initiated outside business hours (hour=%d UTC)",
            kerkese.TsUtc.Hour()))
    status = WARN
}`}
      />
      <p>
        <strong>Rationale:</strong> most legitimate operator activity happens during business
        hours. An action at 03:00 UTC is worth flagging even if it passes every other gate.
        The rule deliberately emits a <code>WARN</code> rather than a block — a hard block on
        off-hours would cause too many false positives for 24/7 operations, but the warn
        surface is sufficient for after-the-fact review.
      </p>
      <p>
        <strong>Reason string:</strong>{' '}
        <code>AUGUR_rule_01: action initiated outside business hours (hour=N UTC)</code>
      </p>
      <p>
        <strong>Future tuning:</strong> the business-hours window will be configurable via{' '}
        <code>CITADEL_AUGUR_BUSINESS_HOURS_START</code> and{' '}
        <code>CITADEL_AUGUR_BUSINESS_HOURS_END</code> environment variables in v1.1+.
      </p>

      <h3 id="rule-02-high-frequency">rule_02 — High frequency</h3>
      <p>
        <strong>Condition:</strong> the same <code>actor.user_id</code> has logged more than
        10 Kerkese evaluations in the last 5 minutes.
      </p>
      <CodeBlock
        language="go"
        filename="rule_02 condition"
        code={`// Gate 4 — rule_02
count, err := store.ActionCount(ctx, kerkese.Actor.UserID, 5*time.Minute)
if err == nil && count > 10 {
    reasons = append(reasons,
        fmt.Sprintf("AUGUR_rule_02: high frequency (%d actions in 5min)", count))
    if status < WARN {
        status = WARN
    }
}`}
      />
      <p>
        <strong>Rationale:</strong> human operators rarely sustain more than 10 governed
        actions in 5 minutes. Spikes indicate either a scripted attack attempting to race past
        a window, or a legitimate automation that should be migrated to a <code>service</code>{' '}
        role token. The frequency counter is maintained by the WORM append path as a sliding
        window — no separate time-series store is required.
      </p>
      <p>
        <strong>Reason string addition:</strong>{' '}
        <code>AUGUR_rule_02: high frequency (N actions in 5min)</code>
      </p>

      <h3 id="rule-03-data-export">rule_03 — DATA_EXPORT without incident</h3>
      <p>
        <strong>Condition:</strong> <code>action.type == "DATA_EXPORT"</code> AND{' '}
        <code>action.incident_id</code> is empty.
      </p>
      <CodeBlock
        language="go"
        filename="rule_03 condition"
        code={`// Gate 4 — rule_03
if kerkese.Action.Type == "DATA_EXPORT" && kerkese.Action.IncidentID == "" {
    reasons = append(reasons,
        "AUGUR_rule_03: DATA_EXPORT attempted without incident_id — HARD_STOP")
    status = HARD_STOP // overrides any prior WARN
}`}
      />
      <p>
        <strong>Rationale:</strong> data exfiltration without an active incident context is the
        single highest-risk pattern in the threat model. An attacker who has captured a live
        session will often attempt a bulk export first; an honest operator always ties exports to
        a specific investigation. This rule is the only AUGUR rule that forces a{' '}
        <code>HARD_STOP</code> outcome.
      </p>
      <div className="callout-warning">
        <strong>Warning:</strong> rule_03's <code>HARD_STOP</code> threshold is intentionally
        non-configurable. The rule exists precisely to make <code>DATA_EXPORT</code> without an
        incident impossible — not difficult, not warned-about, impossible. Do not add a
        configuration path to disable it.
      </div>

      <h2 id="severity-table">Status severity</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>AUGUR status</th>
              <th>Meaning</th>
              <th>Effect on MARSHAL outcome</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>PASS</code></td>
              <td>All rules evaluated cleanly — no anomalies detected</td>
              <td>No change; outcome determined by other gates</td>
            </tr>
            <tr>
              <td><code>WARN</code></td>
              <td>rule_01 or rule_02 fired (or both)</td>
              <td>
                Reason strings appended to <code>decision.reasons[]</code>; outcome
                unchanged (still <code>EXECUTE</code> or <code>REFUSE</code> from prior gates)
              </td>
            </tr>
            <tr>
              <td><code>HARD_STOP</code></td>
              <td>rule_03 fired — <code>DATA_EXPORT</code> without <code>incident_id</code></td>
              <td>
                Outcome forced to <code>HARD_STOP</code> regardless of all other gates;
                P1 incident auto-created; chain anchored immediately
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="verdict-influence">How heuristics influence the verdict</h2>
      <p>
        AUGUR's status severity maps directly onto MARSHAL's verdict semantics, but with an
        important distinction: <code>WARN</code> is <strong>advisory</strong> — it enriches the
        audit record and surfaces anomalies to reviewers without blocking the operation.{' '}
        <code>HARD_STOP</code> is <strong>blocking</strong> and overrides any permissive result
        from earlier gates.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Prior gates result</th>
              <th>AUGUR status</th>
              <th>Final MARSHAL verdict</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>All passed</td>
              <td><code>PASS</code></td>
              <td><code>EXECUTE</code></td>
            </tr>
            <tr>
              <td>All passed</td>
              <td><code>WARN</code></td>
              <td><code>EXECUTE</code> — with AUGUR reason strings in the WORM entry</td>
            </tr>
            <tr>
              <td>Gate 1–3 failure</td>
              <td>any</td>
              <td><code>REFUSE</code> — prior gate failure takes precedence</td>
            </tr>
            <tr>
              <td>Any</td>
              <td><code>HARD_STOP</code></td>
              <td><code>HARD_STOP</code> — overrides everything, including prior <code>EXECUTE</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        The <code>WARN</code> advisory model is deliberate. AUGUR is designed to complement the
        permission model, not duplicate it. Operators reviewing a week's audit log can search for{' '}
        <code>AUGUR_rule_01</code> to identify after-hours patterns without having been paged at
        the time — the signal is preserved in the WORM chain and accessible later.
      </p>

      <h2 id="irflow-interaction">Interaction with IRFlow</h2>
      <p>
        When AUGUR emits <code>HARD_STOP</code>, the downstream effect in <a href="/docs/platforms/irflow">IRFlow</a> is automatic:
      </p>
      <ol>
        <li>
          <code>POST /api/v1/incidents/.../actions</code> returns{' '}
          <code>403 ErrMarshalHardStop</code>.
        </li>
        <li>
          If the CITADEL → IRFlow <code>HARD_STOP</code> webhook is configured, IRFlow receives
          a <code>citadel.marshal.hard_stop</code> event and creates a P1 incident automatically.
        </li>
        <li>A project-freeze runbook fires if configured on the incident type.</li>
        <li>On-call is paged via the incident's notification policy.</li>
      </ol>
      <p>
        <code>WARN</code> statuses are audit-only: IRFlow logs them into the action's{' '}
        <code>marshal_decision</code> field but does not escalate. The warn is visible to
        anyone reviewing the action after the fact.
      </p>

      <h2 id="observability">Observability</h2>
      <p>AUGUR exposes two Prometheus counters:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Metric</th>
              <th>Labels</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>citadel_augur_rule_fires_total</code></td>
              <td><code>rule</code>, <code>status</code></td>
              <td>Counter incremented each time a rule fires, labelled by rule ID and resulting status</td>
            </tr>
            <tr>
              <td><code>citadel_augur_hard_stops_total</code></td>
              <td>—</td>
              <td>Convenience counter for rule_03 <code>HARD_STOP</code> events specifically</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Recommended alerting rule:{' '}
        <code>rate(citadel_augur_hard_stops_total[5m]) {'>'} 0</code> — any <code>HARD_STOP</code>{' '}
        event is per-se incident-worthy and warrants immediate review. rule_01 and rule_02{' '}
        <code>WARN</code>s are expected background noise; alert only when they exceed 10 % of all
        MARSHAL decisions over a sustained window.
      </p>

      <h2 id="tuning">Tuning guidance</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Parameter</th>
              <th>Default</th>
              <th>When to change</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Business-hours window (rule_01)</td>
              <td>07:00–19:00 UTC</td>
              <td>
                Organisations operating primarily in a non-UTC timezone; shift to match local
                business hours. Configurable in v1.1+ via{' '}
                <code>CITADEL_AUGUR_BUSINESS_HOURS_START</code> /{' '}
                <code>CITADEL_AUGUR_BUSINESS_HOURS_END</code>.
              </td>
            </tr>
            <tr>
              <td>High-frequency threshold (rule_02)</td>
              <td>10 actions / 5 min</td>
              <td>
                Raise to 20–30 for organisations with heavy automation under the{' '}
                <code>service</code> role. Consider a separate threshold for{' '}
                <code>service</code> role in v1.1.
              </td>
            </tr>
            <tr>
              <td><code>DATA_EXPORT</code> without incident (rule_03)</td>
              <td><code>HARD_STOP</code> always</td>
              <td>Do not change — this rule exists to make the behaviour impossible.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="vigil">VIGIL — Ecosystem health monitor</h2>

      <div className="callout-note">
        <strong>Planned feature — v2.0:</strong> VIGIL is fully specified and documented here
        so ecosystem callers can plan integration, but <strong>no VIGIL code exists in
        v1.0.0</strong>. Platforms publish their individual health via Prometheus metrics as
        usual. VIGIL is scheduled to reach <code>GET /api/v1/vigil/status</code> in v1.2,
        with full MARSHAL integration in v2.0.
      </div>

      <p>
        VIGIL answers one question for every platform in the opensecstack ecosystem:
        <em> "Is now a safe time to perform governance-relevant work?"</em> It synthesises
        telemetry from CITADEL, IRFlow, ThreatFlow, NIS2 Compass, and APIGuard into a single
        colour-coded health signal that MARSHAL will consult at decision time.
      </p>

      <h3 id="vigil-states">GREEN / AMBER / RED states</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Colour</th>
              <th>Meaning</th>
              <th>Effect on MARSHAL (v2.0)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>GREEN</strong></td>
              <td>Normal operation — all indicators within tolerance</td>
              <td>Baseline; no modification to decision outcomes</td>
            </tr>
            <tr>
              <td><strong>AMBER</strong></td>
              <td>Elevated risk — one or more indicators above threshold</td>
              <td>
                MARSHAL appends VIGIL's colour to <code>decision.reasons[]</code>; outcomes
                unchanged
              </td>
            </tr>
            <tr>
              <td><strong>RED</strong></td>
              <td>
                Critical — unresolved <code>HARD_STOP</code>, severe WORM lag, or chain
                verification failure
              </td>
              <td>
                MARSHAL applies <code>VIGIL_RED_NONEMERGENCY_BLOCK</code>: non-emergency
                action types are <code>REFUSE</code>d until RED clears. Emergency types
                (<code>CONTAIN</code>, <code>ISOLATE</code>, <code>CREATE_INCIDENT</code>)
                bypass the rule.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Aggregation rule: <strong>RED dominates AMBER dominates GREEN</strong>. Any single RED
        input forces the overall status to RED. The individual input colours are exposed
        separately on the VIGIL endpoint so operators can see which dimension triggered the
        escalation.
      </p>

      <h3 id="vigil-inputs">Telemetry inputs</h3>
      <p>
        VIGIL is a consumer of telemetry, not a producer. Its planned inputs span five
        subsystems:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Input signal</th>
              <th>Threshold → state</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>IRFlow</td>
              <td>Unresolved P1 incident count</td>
              <td>{'> 0 → AMBER, > 3 → RED'}</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td>HARD_STOP events in the last hour</td>
              <td>{'> 0 → AMBER'}</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td>Average age of open P1 incidents</td>
              <td>{'> 24 h → AMBER'}</td>
            </tr>
            <tr>
              <td>CITADEL</td>
              <td>WORM chain verification status</td>
              <td>invalid → RED (always)</td>
            </tr>
            <tr>
              <td>CITADEL</td>
              <td>Anchor signature lag</td>
              <td>{'> 10 min since last anchor → AMBER'}</td>
            </tr>
            <tr>
              <td>CITADEL</td>
              <td>WORM append failure rate (5-min window)</td>
              <td>{'> 1 % → AMBER'}</td>
            </tr>
            <tr>
              <td>APIGuard</td>
              <td>Critical finding rate</td>
              <td>{'> 3 criticals / hour → AMBER'}</td>
            </tr>
            <tr>
              <td>APIGuard</td>
              <td>Active scan failure rate</td>
              <td>{'> 10 % → AMBER'}</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td>High-confidence IOC feed gap</td>
              <td>{'no new feed in > 6 h → AMBER'}</td>
            </tr>
            <tr>
              <td>NIS2 Compass</td>
              <td>Article 23 notification success rate (24 h)</td>
              <td>{'< 90 % → AMBER'}</td>
            </tr>
            <tr>
              <td>NIS2 Compass</td>
              <td>Assessment freshness age</td>
              <td>{'> 90 days → AMBER, > 180 days → RED'}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        The planned endpoint response surface looks like this (v1.2+):
      </p>
      <CodeBlock
        language="bash"
        filename="GET /api/v1/vigil/status — planned response"
        code={`{
  "overall":    "AMBER",
  "updated_at": "2026-04-19T10:15:00Z",
  "components": [
    { "name": "worm_chain",    "status": "GREEN", "since": "2026-04-12T00:00:00Z" },
    { "name": "irflow_p1",     "status": "AMBER", "value": 2,    "threshold": "> 0",  "since": "2026-04-19T08:22:00Z" },
    { "name": "nis2_success",  "status": "GREEN", "value": 99.2 },
    { "name": "apiguard_crit", "status": "GREEN", "value": 1 },
    { "name": "threatflow",    "status": "GREEN", "since": "2026-04-12T00:00:00Z" }
  ]
}`}
      />

      <h3 id="vigil-marshal">Interaction with MARSHAL</h3>
      <p>
        In v2.0, VIGIL's output becomes an explicit input to MARSHAL gate evaluation. The
        interaction is designed to be in-band — VIGIL's state is available to MARSHAL at
        decision time, not just to a monitoring pager. Any VIGIL-driven MARSHAL outcome carries
        the colour state in the WORM entry, so auditors can reconstruct what VIGIL showed at
        the exact moment of any decision.
      </p>
      <p>
        This design separates VIGIL from Prometheus alerting. Prometheus dashboards show
        per-service numbers; VIGIL combines them into a single cross-platform signal that
        influences governance decisions and is recorded in the immutable audit chain.
      </p>

      <h3 id="vigil-timeline">Implementation timeline</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>VIGIL scope</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>v1.0.0 (current)</strong></td>
              <td>Design only. No code. Platforms publish health via Prometheus metrics as usual.</td>
            </tr>
            <tr>
              <td><strong>v1.1</strong></td>
              <td>
                Consumer-side scraping infrastructure in CITADEL — a background worker polls
                other platforms' <code>/health/detail</code> endpoints.
              </td>
            </tr>
            <tr>
              <td><strong>v1.2</strong></td>
              <td>
                VIGIL computes colour state and exposes <code>GET /api/v1/vigil/status</code>.
                No MARSHAL integration yet.
              </td>
            </tr>
            <tr>
              <td><strong>v2.0</strong></td>
              <td>
                Full MARSHAL rule integration (<code>VIGIL_RED_NONEMERGENCY_BLOCK</code>).
                This is the last step because it changes decision semantics for every caller
                and requires a careful rollout plan alongside the rule-as-code plugin system
                and multi-writer chain.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
