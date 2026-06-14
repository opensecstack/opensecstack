import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'what-is-citadel', label: 'What is CITADEL?' },
  { id: 'marshal-engine', label: 'MARSHAL 5-gate engine' },
  { id: 'worm-chain', label: 'WORM audit chain' },
  { id: 'nds-separation-of-duties', label: 'NDS — separation of duties' },
  { id: 'augur-heuristics', label: 'AUGUR behavioural heuristics' },
  { id: 'verdicts', label: 'Verdicts' },
  { id: 'benchmarks', label: 'Benchmarks' },
  { id: 'api-reference', label: 'API reference' },
]

export default function GovernancePage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'Overview']}
      toc={toc}
      editPath="GovernancePage.tsx"
      prev={{ label: 'Identity (sinauth)', path: '/docs/identity' }}
      next={{ label: 'MARSHAL Engine', path: '/docs/citadel/marshal' }}
    >
      <h1>Governance (CITADEL)</h1>
      <p>
        <strong>CITADEL</strong> is the cryptographic governance engine for the opensecstack
        ecosystem. Every privileged action across all SIN platforms passes through CITADEL's
        5-gate <a href="/docs/citadel/marshal"><strong>MARSHAL</strong></a> decision engine before execution, and every decision
        is recorded in an append-only <a href="/docs/citadel/worm"><strong>WORM</strong></a> audit chain with cryptographic
        integrity guarantees.
      </p>
      <p>
        CITADEL runs on port <code>8099</code>. Licence: AGPL-3.0.
      </p>

      <h2 id="what-is-citadel">What is CITADEL?</h2>
      <p>
        CITADEL provides the audit and authorisation layer that every other platform
        depends on. Its four active components are:
      </p>
      <ul>
        <li><strong>MARSHAL</strong> — the 5-gate decision engine that evaluates every governance request (Kerkese)</li>
        <li><strong>WORM chain</strong> — the append-only audit log with TripleHash integrity and Ed25519 chain anchors</li>
        <li><a href="/docs/citadel/sod"><strong>NDS</strong></a> — cryptographic separation-of-duties enforcement</li>
        <li><a href="/docs/citadel/augur-vigil"><strong>AUGUR</strong></a> — behavioural heuristics for pre-emptive anomaly detection</li>
      </ul>
      <p>
        A fifth component, <strong>VIGIL</strong> (ecosystem health monitor,
        GREEN / AMBER / RED), is in design-stage for v2.0.
      </p>

      <h2 id="marshal-engine">MARSHAL 5-gate engine</h2>
      <p>
        Every governance request — called a <strong>Kerkese</strong> — flows through five
        sequential gates. A gate failure stops evaluation immediately and returns the
        appropriate verdict.
      </p>
      <CodeBlock
        language="bash"
        filename="MARSHAL gate sequence"
        code={`Request → Gate 1 (AuthN) → Gate 2 (AuthZ) → Gate 3 (NDS) → Gate 4 (AUGUR) → Gate 5 (WORM)
                                                                                    ↓
                                                                            Always logged`}
      />
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Gate</th>
              <th>Name</th>
              <th>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>1</td>
              <td>AuthN</td>
              <td>Ed25519 signature verification — confirms the request came from a registered platform</td>
            </tr>
            <tr>
              <td>2</td>
              <td>AuthZ</td>
              <td>RBAC permission check — confirms the actor holds the required role for the action</td>
            </tr>
            <tr>
              <td>3</td>
              <td>NDS</td>
              <td>Separation of Duties — <code>actor.user_id ≠ verifier.user_id</code>, enforced cryptographically</td>
            </tr>
            <tr>
              <td>4</td>
              <td>AUGUR</td>
              <td>Behavioural heuristics — flags off-hours actions, high-frequency submissions, and <code>DATA_EXPORT</code> without an associated incident</td>
            </tr>
            <tr>
              <td>5</td>
              <td>WORM</td>
              <td>Unconditional append to the immutable audit chain with TripleHash integrity — every request is logged regardless of verdict</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="worm-chain">WORM audit chain</h2>
      <p>
        The WORM (Write Once, Read Many) chain is an append-only PostgreSQL table with an
        immutability trigger that rejects any <code>UPDATE</code> or <code>DELETE</code>
        statement. Every entry is cryptographically linked to the previous entry.
      </p>
      <p>
        <strong>TripleHash</strong> computes a 128-byte composite digest for each entry
        using three independent algorithms simultaneously:
      </p>
      <CodeBlock
        language="bash"
        filename="TripleHash and chain structure"
        code={`# Per-entry integrity
triple_hash = SHA-256(payload) || SHA-512(payload) || BLAKE3(payload)   # 128 bytes

# Chain linkage
chain_hash_n = SHA-256(chain_hash_{n-1} || payload_bytes)

# Ed25519 chain anchors — written every 100 entries
anchor = Ed25519_sign(master_key, chain_hash_at_entry_n)`}
      />
      <p>
        All three hash algorithms must be broken simultaneously to forge an entry — an
        attacker cannot selectively modify only one hash component. The Ed25519 anchor every
        100 entries binds the chain to the CITADEL signing key, enabling external
        notarisation.
      </p>
      <p>
        After any disaster recovery — even from the coldest backup — the restored log can be
        cryptographically verified against the original chain anchors. Tampered recovery is
        detectable.
      </p>

      <h2 id="nds-separation-of-duties">NDS — separation of duties</h2>
      <p>
        Gate 3 (NDS) enforces the separation-of-duties protocol. The constraint
        is <code>actor.user_id ≠ verifier.user_id</code> and the actor and verifier must
        belong to different role groups (<code>group_sig_operator</code> vs
        <code> group_sig_verifier</code>). This is enforced at the cryptographic protocol
        level, not by policy — a stolen operator credential cannot self-approve a
        privileged action because it cannot also control the verifier account.
      </p>
      <p>
        A violation of this constraint causes an immediate <strong>HARD_STOP</strong>
        verdict and triggers an automatic P1 incident.
      </p>

      <h2 id="augur-heuristics">AUGUR behavioural heuristics</h2>
      <p>
        Gate 4 (AUGUR) applies pre-emptive behavioural analysis before any action reaches
        the WORM log. AUGUR reads from a read-only mirror database and does not affect
        MARSHAL gate decisions itself — it emits advisories (AUG-001 through AUG-009) that
        surface anomalies before they become violations.
      </p>
      <p>Examples of patterns AUGUR flags:</p>
      <ul>
        <li>Actions submitted outside normal operating hours</li>
        <li>High-frequency submissions from a single actor within a short window</li>
        <li><code>DATA_EXPORT</code> action requested without a linked open incident</li>
      </ul>

      <h2 id="verdicts">Verdicts</h2>
      <p>MARSHAL returns one of three verdicts for every Kerkese evaluation:</p>
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
              <td>All gates passed — the action is authorised and has been WORM-logged</td>
            </tr>
            <tr>
              <td><code>REFUSE</code></td>
              <td>A gate check failed (e.g. insufficient role, AUGUR advisory) — action is denied and logged</td>
            </tr>
            <tr>
              <td><code>HARD_STOP</code></td>
              <td>A critical violation detected (SoD breach, spoofing, contradictory <a href="/docs/citadel/evidence">evidence</a>) — action denied, P1 incident auto-created, chain anchored immediately</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="callout-warning">
        <strong>Warning:</strong> A <code>HARD_STOP</code> verdict is irreversible. It locks
        the action context and creates an immutable incident record in the WORM chain.
        Operators must resolve the incident through normal governance channels — there is no
        administrative override.
      </div>

      <h2 id="benchmarks">Benchmarks</h2>
      <p>
        Measured on Go 1.24.4, Intel Core i7-7600U. All benchmarks use an in-memory mock
        store unless noted.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Operation</th>
              <th>Result</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>TripleHash (100-byte payload)</td>
              <td>1.52 µs</td>
              <td>SHA-256 + SHA-512 + BLAKE3 in parallel</td>
            </tr>
            <tr>
              <td>WORM chain step</td>
              <td>427 ns, 0 allocations</td>
              <td>SHA-256 linkage only, no DB</td>
            </tr>
            <tr>
              <td>WORM append (PostgreSQL 16, sync)</td>
              <td>4.22 ms</td>
              <td>Includes immutability trigger and fsync</td>
            </tr>
            <tr>
              <td>MARSHAL 5-gate evaluation</td>
              <td>7.55 µs</td>
              <td>In-memory mock store</td>
            </tr>
            <tr>
              <td>Chain verification (1,000 entries)</td>
              <td>10.19 ms</td>
              <td>Full TripleHash recomputation</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="api-reference">API reference</h2>
      <p>
        CITADEL exposes a minimal HTTP API on port <code>8099</code>.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/health</code></td>
              <td>Server and database health check</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/marshal/evaluate</code></td>
              <td>Evaluate a Kerkese through the 5 MARSHAL gates</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/worm/emit</code></td>
              <td>Append an event to the WORM chain directly</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/worm/verify</code></td>
              <td>Verify chain integrity from genesis to current head</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        For how platforms connect to CITADEL, see the <a href="/docs/citadel-integration">CITADEL Integration</a> guide.
        All connector requests to CITADEL must include an <code>X-Citadel-Signature</code>{' '}
        HMAC-SHA256 header computed over <code>key_id + timestamp + body_hash</code>.
        Requests outside the ±300-second timestamp window are rejected.
      </p>
    </DocsLayout>
  )
}
