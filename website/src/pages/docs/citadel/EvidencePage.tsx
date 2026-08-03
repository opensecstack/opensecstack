import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'worm-fields', label: 'What CITADEL records automatically' },
  { id: 'chain-anchors', label: 'Chain anchors' },
  { id: 'export-bundle', label: 'Evidence export bundle' },
  { id: 'custody-manifest', label: 'Custody manifest format' },
  { id: 'export-authorisation', label: 'Export authorisation' },
  { id: 'retention', label: 'Retention policy' },
  { id: 'key-rotation', label: 'Key rotation and revocation' },
  { id: 'auditor-walkthrough', label: 'Auditor walkthrough' },
  { id: 'step-1-bundle', label: 'Step 1 — Bundle integrity', level: 3 as const },
  { id: 'step-2-pubkeys', label: 'Step 2 — Pubkey registry', level: 3 as const },
  { id: 'step-3-anchors', label: 'Step 3 — Anchor signatures', level: 3 as const },
  { id: 'step-4-chain-walk', label: 'Step 4 — Linear chain walk', level: 3 as const },
  { id: 'step-5-anchor-coverage', label: 'Step 5 — Anchor-over-chain-walk', level: 3 as const },
  { id: 'step-6-time-range', label: 'Step 6 — Time-range sanity', level: 3 as const },
  { id: 'bundle-claims', label: 'Claims a green bundle supports' },
  { id: 'bundle-limits', label: 'Claims a bundle does not support' },
  { id: 'common-findings', label: 'Common findings' },
  { id: 'dos-donts', label: "Do's and don'ts" },
]

export default function EvidencePage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'Evidence & Audit']}
      toc={toc}
      editPath="citadel/EvidencePage.tsx"
      prev={{ label: 'AUGUR & VIGIL', path: '/docs/citadel/augur-vigil' }}
      next={{ label: 'Go SDK', path: '/docs/sdk/go' }}
    >
      <Helmet>
        <title>Evidence &amp; Audit | opensecstack Docs</title>
        <meta
          name="description"
          content="How to export and verify CITADEL evidence bundles — custody manifests, chain anchors, and the auditor walkthrough for validating WORM chain integrity."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/citadel/evidence" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/citadel/evidence" />
        <meta property="og:title" content="Evidence & Audit | opensecstack Docs" />
        <meta
          property="og:description"
          content="How to export and verify CITADEL evidence bundles — custody manifests, chain anchors, and the auditor walkthrough for validating WORM chain integrity."
        />
      </Helmet>
      <h1>Evidence &amp; Auditor Walkthrough</h1>
      <p>
        The <a href="/docs/citadel/worm">WORM chain</a> is evidence. Making it <em>admissible</em> evidence — for a regulator,
        a court, or an internal audit — requires a chain of custody that documents who had
        access to it, when, how integrity was verified at each handover, and what proof
        accompanies the data when it leaves CITADEL. This page explains the chain-of-custody
        model, the export bundle format, and provides a step-by-step auditor walkthrough for
        verifying a chain, validating anchors, and exporting a custody manifest.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Every WORM entry is cryptographically linked to its predecessor and content-addressed
        via <strong>TripleHash</strong> (SHA-256 + SHA-512 + BLAKE3 in parallel). Every 100
        entries, CITADEL writes a <strong>chain anchor</strong> — an Ed25519 signature over
        the current chain state — that elevates an internally consistent chain into an
        externally attestable one. When evidence leaves CITADEL, it travels with those anchors,
        the corresponding public keys, and a custody manifest that records who authorised the
        export, who received it, and a bundle-level hash the receiver can recompute to detect
        transit tampering.
      </p>

      <h2 id="worm-fields">What CITADEL records automatically</h2>
      <p>
        Every WORM entry carries the following fields. Each field serves a specific custody
        purpose that an auditor can verify independently:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Type</th>
              <th>Custody purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>id</code></td>
              <td>UUID</td>
              <td>Unique reference that cannot be re-used; identifies the exact evidence item</td>
            </tr>
            <tr>
              <td><code>sequence_num</code></td>
              <td>int64</td>
              <td>Position in the chain; gaps are detectable — a missing sequence number is a finding</td>
            </tr>
            <tr>
              <td><code>ts_utc</code></td>
              <td>timestamp</td>
              <td>CITADEL's server-authoritative time — not the caller's — establishing when the entry was committed</td>
            </tr>
            <tr>
              <td><code>source</code> + <code>event_type</code></td>
              <td>string</td>
              <td>Provenance — which subsystem produced this evidence and what class of event it records</td>
            </tr>
            <tr>
              <td><code>project_id</code></td>
              <td>UUID</td>
              <td>Scope — which investigation this evidence belongs to, enabling targeted export</td>
            </tr>
            <tr>
              <td><code>payload</code></td>
              <td>BYTEA</td>
              <td>The evidence itself, byte-for-byte, as submitted by the originating platform</td>
            </tr>
            <tr>
              <td><code>triple_hash</code></td>
              <td>hex string</td>
              <td>Content-addressable digest — 128-byte composite of SHA-256 + SHA-512 + BLAKE3; proof the bytes have not changed</td>
            </tr>
            <tr>
              <td><code>chain_hash</code></td>
              <td>hex string</td>
              <td>SHA-256 of the previous chain_hash concatenated with this entry's payload; proves the entry exists at this sequence position</td>
            </tr>
            <tr>
              <td><code>prev_hash</code></td>
              <td>hex string</td>
              <td>The chain_hash of the immediately preceding entry; proves this entry came after the prior one</td>
            </tr>
            <tr>
              <td><code>created_at</code></td>
              <td>timestamp</td>
              <td>DB-level insert timestamp; must match <code>ts_utc</code> — divergence is an integrity flag</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="chain-anchors">Chain anchors</h2>
      <p>
        Every 100 entries, CITADEL writes a <strong>chain anchor</strong>: an Ed25519 signature
        over <code>(sequence_num, ts_utc, chain_hash)</code> using the master CITADEL signing
        key. Anchors are what elevate an internally consistent chain into an externally
        attestable one — they bind the chain state to a private key only CITADEL holds,
        enabling external notarisation.
      </p>
      <CodeBlock
        language="bash"
        filename="TripleHash and chain structure"
        code={`# Per-entry integrity (128-byte composite digest)
triple_hash = SHA-256(payload) || SHA-512(payload) || BLAKE3(payload)

# Chain linkage (forward hash)
chain_hash[n] = SHA-256(chain_hash[n-1] || payload_bytes[n])

# Ed25519 anchor — written every 100 entries
anchor_payload = sequence_num + "|" + ts_utc + "|" + chain_hash
anchor_digest  = SHA-512(anchor_payload)
anchor_sig     = Ed25519_Sign(master_key, anchor_digest)`}
      />
      <p>
        All three hash algorithms in TripleHash must be broken simultaneously to forge an
        entry. The Ed25519 anchor every 100 entries binds the chain to the CITADEL signing key.
        After any disaster recovery — even from a cold backup — the restored log can be
        verified against the original anchors; tampered recovery is detectable.
      </p>

      <h2 id="export-bundle">Evidence export bundle</h2>
      <p>
        When evidence leaves CITADEL — to an auditor, a court, or a regulator — the export
        bundle must contain all five components for the evidence to be attestable:
      </p>
      <ol>
        <li>
          <strong>WORM entries</strong> (<code>worm_entries.jsonl</code>) — the evidence itself,
          one JSON object per line, sorted by <code>sequence_num</code> ASC.
        </li>
        <li>
          <strong>Chain anchors</strong> (<code>chain_anchors.jsonl</code>) — every anchor
          covering the exported range, one JSON object per line.
        </li>
        <li>
          <strong>Public keys</strong> (<code>pubkeys.yaml</code>) — all Ed25519 public keys
          that signed anchors covering this range, with <code>id</code>,{' '}
          <code>pubkey_hex</code>, <code>issued</code>, <code>revoked</code>, and{' '}
          <code>replaced_by</code>.
        </li>
        <li>
          <strong>Bundle hash</strong> (<code>bundle.sha256</code>) — SHA-256 over the
          concatenated bytes of <code>worm_entries.jsonl</code>,{' '}
          <code>chain_anchors.jsonl</code>, and <code>pubkeys.yaml</code>. The receiver
          recomputes this to detect transit tampering.
        </li>
        <li>
          <strong>Custody manifest</strong> (<code>manifest.yaml</code>) — who authorised the
          export, who received it, when, and a reference to the bundle hash. This is the
          operator's responsibility; CITADEL does not generate it automatically.
        </li>
      </ol>
      <div className="callout-note">
        <strong>Note:</strong> Do not hand out raw database dumps in lieu of a proper bundle.
        The manifest and anchor public keys are what make the evidence attestable. A raw dump
        contains the bytes but not the cryptographic proof.
      </div>

      <h2 id="custody-manifest">Custody manifest format</h2>
      <p>
        The custody manifest is a YAML document produced by the operator and included in every
        export bundle as <code>manifest.yaml</code>. It creates the{' '}
        <em>meta-chain-of-custody</em>: the manifest references the bundle hash, and the
        bundle contains the WORM entry that authorised the export. Any future dispute about
        whether an export was authorised can be resolved against the chain itself.
      </p>
      <CodeBlock
        language="yaml"
        filename="manifest.yaml — recommended format"
        code={`bundle_id:            "citadel-export-2026-04-19-0001"
produced_at:          "2026-04-19T14:32:00Z"
produced_by:
  user_id:            42
  role:               admin
  jwt_sub:            "alice@example.com"
authorised_by:
  user_id:            99
  role:               admin
  jwt_sub:            "bob@example.com"
received_by:
  name:               "EU DG-CONNECT audit team"
  contact:            "audit-lead@dg-connect.europa.eu"
  received_at:        "2026-04-19T14:35:00Z"

evidence:
  time_range:
    from:             "2026-01-01T00:00:00Z"
    to:               "2026-03-31T23:59:59Z"
  entries_count:      12847
  first_sequence_num: 10201
  last_sequence_num:  23047
  anchors_count:      129

integrity:
  bundle_sha256:      "<hex>"
  anchor_pubkeys:
    - id:             "citadel-anchor-2026Q1"
      pubkey_hex:     "<32-byte Ed25519 pubkey hex>"
      issued:         "2026-01-01"
      revoked:        null`}
      />

      <h2 id="export-authorisation">Export authorisation</h2>
      <p>
        Exporting evidence is itself a governance-relevant action. It passes through the full
        <a href="/docs/citadel/marshal"> MARSHAL</a> pipeline:
      </p>
      <ul>
        <li>
          <code>action.type</code> is <code>DATA_EXPORT</code> — picked up by AUGUR rule_03,
          which requires a non-empty <code>incident_id</code> (the reason for the export).
          Attempting a <code>DATA_EXPORT</code> without an associated incident results in an
          immediate <code>HARD_STOP</code>.
        </li>
        <li>
          Gate 3 (<a href="/docs/citadel/sod">NDS</a>) enforces separation of duties — two distinct identities must sign off:
          the operator requesting the export and a verifier from a different role group.
        </li>
        <li>
          Gate 5 (WORM) records the export action itself, including operator, verifier,
          reason, and the range exported, in the immutable audit chain.
        </li>
      </ul>
      <p>
        The WORM entry for the export is included in the bundle itself, so the bundle is
        self-referencing: the custody manifest references the bundle hash, and the bundle
        contains cryptographic proof that the export was properly authorised.
      </p>

      <h2 id="retention">Retention policy</h2>
      <p>
        Per NIS2 Directive Article 21(2)(b), incident-related evidence must be retained long
        enough to support authority review. CITADEL's default policy is{' '}
        <strong>indefinite</strong> — WORM entries are never deleted.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Retention window</th>
              <th>When to apply</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>7 years</strong></td>
              <td>Default for regulated entities (financial services, healthcare, critical infrastructure)</td>
            </tr>
            <tr>
              <td><strong>10 years</strong></td>
              <td>Where national law requires it (defence contractors, classified handling)</td>
            </tr>
            <tr>
              <td><strong>30 days</strong></td>
              <td>Development and staging environments only — must be a completely separate CITADEL instance</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        There is no TTL on WORM entries in v1.0.0. Archival tiering (moving entries older than
        one year to cold storage) is planned for v2.0; today, storage cost scales linearly
        with time.
      </p>

      <h2 id="key-rotation">Key rotation and revocation</h2>
      <p>
        <strong>Never delete an anchor public key</strong>, even after an Ed25519 key is
        rotated. Every anchor signed with the old key remains valid for the duration of the
        evidence retention period. The key's custody record shows:
      </p>
      <ul>
        <li><code>issued</code> — date the key came into use.</li>
        <li>
          <code>revoked</code> — date a replacement was issued. The old key no longer signs
          new anchors, but all existing signatures still verify against it.
        </li>
        <li><code>replaced_by</code> — the new <code>pubkey_id</code>.</li>
      </ul>
      <p>
        Export bundles for a given time range automatically include all public keys that signed
        anchors touching that range, including rotated keys. An auditor receiving a bundle for
        a range that spans a key rotation will see both the old and new key in{' '}
        <code>pubkeys.yaml</code>.
      </p>

      <h2 id="auditor-walkthrough">Auditor walkthrough</h2>
      <p>
        The following steps are written for external or internal auditors receiving a CITADEL
        evidence bundle. Complete all six steps in order — any failure at any step means the
        bundle should be rejected, either for re-export (if transit corruption is suspected) or
        for escalation (if tampering is suspected). A legitimate CITADEL deployment never
        produces a failing bundle.
      </p>

      <h3 id="step-1-bundle">Step 1 — Bundle integrity</h3>
      <p>
        Recompute the bundle hash and compare it against <code>bundle.sha256</code>:
      </p>
      <CodeBlock
        language="bash"
        filename="Step 1 — recompute bundle_sha256"
        code={`# Recompute the bundle hash (concatenated bytes of the three data files)
cat worm_entries.jsonl chain_anchors.jsonl pubkeys.yaml | sha256sum

# Compare the output against bundle.sha256
diff <(cat worm_entries.jsonl chain_anchors.jsonl pubkeys.yaml | sha256sum | awk '{print $1}') \
     <(cat bundle.sha256 | tr -d '[:space:]')

# Clean result: empty diff — no output, exit 0
# Mismatch: the bundle was modified in transit — reject and request re-export`}
      />

      <h3 id="step-2-pubkeys">Step 2 — Pubkey registry</h3>
      <p>For each public key in <code>pubkeys.yaml</code>, verify:</p>
      <ul>
        <li>
          <code>pubkey_hex</code> is a valid Ed25519 public key — exactly 32 bytes (64
          hexadecimal characters).
        </li>
        <li>
          <code>issued</code> and <code>revoked</code> dates are plausible: not in the future,
          no unexplained gaps between consecutive keys.
        </li>
        <li>
          If <code>revoked</code> is set, <code>replaced_by</code> must point at another key
          in the bundle whose <code>issued</code> date is on or after the revocation date.
        </li>
        <li>
          No anchor in <code>chain_anchors.jsonl</code> references a key outside that key's{' '}
          <code>[issued, revoked)</code> validity window.
        </li>
      </ul>

      <h3 id="step-3-anchors">Step 3 — Anchor signatures</h3>
      <p>
        For each anchor in <code>chain_anchors.jsonl</code>, verify the Ed25519 signature:
      </p>
      <CodeBlock
        language="bash"
        filename="Step 3 — verify anchor signatures (verification script)"
        code={`# The verification script (provided with the bundle) runs this for all anchors:
#
#   payload = sequence_num + "|" + ts_utc + "|" + chain_hash
#   digest  = SHA-512(payload)
#   ed25519.Verify(pubkey_for(anchor.pubkey_id), digest, anchor.signature) == true
#
# Run the bundled script:
./citadel-verify anchors --bundle ./export-bundle/

# Expected output on success:
# [OK] 129/129 anchors verified`}
      />
      <p>
        Every anchor must verify. A single failing anchor voids the integrity claim for
        the range that anchor covers. Reject the bundle on any anchor failure.
      </p>

      <h3 id="step-4-chain-walk">Step 4 — Linear chain walk</h3>
      <p>
        Iterate entries in <code>worm_entries.jsonl</code> sorted by <code>sequence_num</code>{' '}
        ascending. For each entry:
      </p>
      <ol>
        <li>
          <strong>Recompute TripleHash</strong> from the raw payload bytes and confirm it
          matches the stored <code>triple_hash</code>:
          <CodeBlock
            language="bash"
            filename="TripleHash recomputation"
            code={`# For each entry:
expected_triple = sha256(payload) || sha512(payload) || blake3(payload)
assert expected_triple == entry.triple_hash`}
          />
        </li>
        <li>
          <strong>Recompute chain_hash</strong> from the previous entry's chain_hash and
          this entry's payload:
          <CodeBlock
            language="bash"
            filename="chain_hash recomputation"
            code={`# For each entry:
expected_chain = sha256(hex_decode(entry.prev_hash) || entry.payload_bytes)
assert expected_chain == entry.chain_hash`}
          />
        </li>
        <li>
          <strong>Check continuity</strong> — each entry's <code>prev_hash</code> must equal
          the preceding entry's <code>chain_hash</code>:
          <CodeBlock
            language="bash"
            filename="Continuity check"
            code={`# For each entry[i] where i > 0:
assert entry[i].prev_hash == entry[i-1].chain_hash

# Any mismatch indicates insertion, deletion, or re-ordering — reject the bundle`}
          />
        </li>
      </ol>
      <CodeBlock
        language="bash"
        filename="Step 4 — full chain walk via verification script"
        code={`./citadel-verify chain-walk --bundle ./export-bundle/ --verbose

# Expected output on success:
# [OK] 12847 entries walked
# [OK] TripleHash verified: 12847/12847
# [OK] chain_hash verified: 12847/12847
# [OK] Continuity: no gaps or sequence breaks`}
      />

      <h3 id="step-5-anchor-coverage">Step 5 — Anchor-over-chain-walk</h3>
      <p>
        Confirm that the first and last entries in the bundle are covered by anchors that
        verified in Step 3. An anchor covers entries{' '}
        <code>[anchor.prev_sequence_num + 1, anchor.sequence_num]</code>. The{' '}
        <code>chain_hash</code> at <code>anchor.sequence_num</code> must match the value
        derived from the chain walk in Step 4.
      </p>
      <p>
        Any chain_hash from the walk that does not appear in the anchor set means anchor
        coverage is incomplete. The bundle is valid as far as the walk proves, but the
        uncovered range has weaker evidence than anchor-sealed range — flag this as a
        finding and ask the deployer to re-export with complete anchor coverage.
      </p>
      <CodeBlock
        language="bash"
        filename="Step 5 — anchor coverage check"
        code={`./citadel-verify anchor-coverage --bundle ./export-bundle/

# Expected output on success:
# [OK] First entry sequence 10201 covered by anchor at sequence 10300
# [OK] Last entry sequence 23047 covered by anchor at sequence 23100
# [OK] No gaps in anchor coverage`}
      />

      <h3 id="step-6-time-range">Step 6 — Time-range sanity</h3>
      <p>
        Confirm the bundle's claimed range (from <code>manifest.yaml</code>'s{' '}
        <code>evidence.time_range</code>) is consistent with the actual entries:
      </p>
      <ul>
        <li>
          <code>evidence.first_sequence_num</code> ≤ the first entry's{' '}
          <code>sequence_num</code> in <code>worm_entries.jsonl</code>.
        </li>
        <li>
          <code>evidence.last_sequence_num</code> ≥ the last entry's{' '}
          <code>sequence_num</code>.
        </li>
        <li>
          <code>evidence.time_range.from</code> ≤ the first entry's <code>ts_utc</code>.
        </li>
        <li>
          <code>evidence.time_range.to</code> ≥ the last entry's <code>ts_utc</code>.
        </li>
      </ul>
      <CodeBlock
        language="bash"
        filename="Step 6 — time range sanity check"
        code={`./citadel-verify time-range --bundle ./export-bundle/

# Expected output on success:
# [OK] Manifest range 2026-01-01T00:00:00Z → 2026-03-31T23:59:59Z
# [OK] First entry: seq=10201, ts=2026-01-01T00:01:14Z  (within range)
# [OK] Last  entry: seq=23047, ts=2026-03-31T23:58:02Z  (within range)
# [OK] Entry count matches manifest: 12847`}
      />

      <h2 id="bundle-claims">Claims a green bundle supports</h2>
      <p>
        A bundle that passes all six steps supports the following claims in an audit or legal
        context:
      </p>
      <ol>
        <li>
          <strong>These specific payloads existed at their timestamps.</strong> The{' '}
          <code>chain_hash</code> at each <code>sequence_num</code> encodes the full history
          up to that point; re-deriving it from the payloads and the genesis hash yields the
          same value.
        </li>
        <li>
          <strong>The timestamps are CITADEL-authoritative.</strong> <code>ts_utc</code> is set
          by CITADEL's server clock at append time — not by the calling platform.
        </li>
        <li>
          <strong>The payloads have not been altered since committal.</strong> TripleHash is
          content-addressable; any mutation would fail the chain walk at Step 4.
        </li>
        <li>
          <strong>The chain was not re-ordered or spliced.</strong> Continuity checks (Step 4.3)
          detect insertion, deletion, and re-ordering at any position in the range.
        </li>
        <li>
          <strong>The range is cryptographically sealed.</strong> The Ed25519 anchor signatures
          (Step 3) bind the chain_hashes to a private key only CITADEL holds; an attacker would
          need that key to forge anchors over a modified chain.
        </li>
      </ol>

      <h2 id="bundle-limits">Claims a bundle does not support</h2>
      <p>
        Be explicit with stakeholders about what the bundle cannot prove:
      </p>
      <ul>
        <li>
          <strong>The payloads are truthful.</strong> CITADEL proves a payload was submitted and
          committed, not that its business-semantic content is accurate. If a platform submitted
          incorrect data, the WORM entry faithfully records the inaccuracy.
        </li>
        <li>
          <strong>The actor was who they claimed to be.</strong> CITADEL uses whatever identity
          the calling platform's IdP asserted. A compromised credential produces genuine-looking
          WORM entries.
        </li>
        <li>
          <strong>Actions were carried out.</strong> The WORM records the MARSHAL decision, not
          the execution outcome. Evidence for the effect of a decision lives in the downstream
          system's own records — you need both layers for a complete picture.
        </li>
      </ul>

      <h2 id="common-findings">Common findings</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Likely cause</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Gaps in <code>sequence_num</code> (e.g. 1234 → 1236, 1235 missing)</td>
              <td>
                Gaps should not occur — the WORM table serialises appends and assigns sequence
                numbers monotonically with <code>LOCK TABLE</code>
              </td>
              <td>Raise as a finding; the export may have missed entries, or the chain has been tampered with</td>
            </tr>
            <tr>
              <td>Two anchors with identical <code>sequence_num</code></td>
              <td>Cannot happen legitimately — each anchor covers a unique range</td>
              <td>Duplicate entries in the anchor table; this is itself an incident — escalate immediately</td>
            </tr>
            <tr>
              <td>Payload is not UTF-8 / not JSON</td>
              <td>
                <code>payload</code> is <code>BYTEA</code> — legally any bytes; in practice
                always JSON, but the format does not enforce this
              </td>
              <td>Chain integrity is still valid; the payload is opaque to this analysis but the custody proof holds</td>
            </tr>
            <tr>
              <td>Bundle SHA-256 mismatch on receipt</td>
              <td>Transit corruption or tampering</td>
              <td>Reject and request re-export; if the deployer cannot produce a matching bundle, treat as a security incident</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="dos-donts">Do's and don'ts</h2>
      <div className="callout-warning">
        <strong>Do not re-sign anchors.</strong> If a deployer or counterparty requests a
        "fresh signature" over historical entries — decline. The whole point of anchors is
        that the signature is fixed at the time the entry range was sealed. A request to
        re-sign historical anchors is a red flag and should be treated as a potential incident.
      </div>
      <ul>
        <li>
          <strong>Do</strong> verify the bundle hash before beginning any other step — transit
          corruption is the most common non-adversarial failure mode.
        </li>
        <li>
          <strong>Do</strong> include the WORM entry for the export action itself in the bundle
          so the custody chain is self-referencing.
        </li>
        <li>
          <strong>Do</strong> retain rotated Ed25519 public keys indefinitely alongside the
          anchors they signed.
        </li>
        <li>
          <strong>Do not</strong> hand out raw database dumps. A dump has the bytes but not the
          cryptographic proof chain.
        </li>
        <li>
          <strong>Do not</strong> modify or redact a payload in place. Redaction is done via a
          compensating WORM entry that references the old entry and marks it superseded — the
          original entry remains in the chain unchanged.
        </li>
        <li>
          <strong>Do not</strong> attempt a <code>DATA_EXPORT</code> without an associated
          incident ID. AUGUR rule_03 will force a <code>HARD_STOP</code> and create a P1
          incident automatically.
        </li>
      </ul>
    </DocsLayout>
  )
}
