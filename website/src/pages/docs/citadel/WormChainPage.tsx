import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'table-structure', label: 'Table structure' },
  { id: 'genesis-hash', label: 'Genesis hash' },
  { id: 'triple-hash', label: 'TripleHash construction' },
  { id: 'why-three-hashes', label: 'Why three hashes?' },
  { id: 'chain-linkage', label: 'Per-entry chain linkage' },
  { id: 'append-operation', label: 'Append operation' },
  { id: 'chain-anchors', label: 'Ed25519 chain anchors' },
  { id: 'anchor-storage', label: 'Anchor storage' },
  { id: 'verification', label: 'Chain verification' },
  { id: 'key-management', label: 'Key management' },
  { id: 'what-worm-does-not-do', label: 'What WORM does not do' },
  { id: 'benchmarks', label: 'Benchmarks' },
]

export default function WormChainPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'CITADEL Governance', 'WORM Chain & TripleHash']}
      toc={toc}
      editPath="citadel/WormChainPage.tsx"
      prev={{ label: 'MARSHAL Engine', path: '/docs/citadel/marshal' }}
      next={{ label: 'Separation of Duties', path: '/docs/citadel/sod' }}
    >
      <Helmet>
        <title>WORM Chain &amp; TripleHash | opensecstack Docs</title>
        <meta
          name="description"
          content="The append-only WORM audit chain's TripleHash construction (SHA-256, SHA-512, BLAKE3), per-entry chain linkage, and Ed25519 chain anchors for tamper-evident verification."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/citadel/worm" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/citadel/worm" />
        <meta property="og:title" content="WORM Chain & TripleHash | opensecstack Docs" />
        <meta
          property="og:description"
          content="The append-only WORM audit chain's TripleHash construction (SHA-256, SHA-512, BLAKE3), per-entry chain linkage, and Ed25519 chain anchors for tamper-evident verification."
        />
      </Helmet>
      <h1>WORM Chain &amp; TripleHash</h1>
      <p>
        Every <a href="/docs/citadel/marshal">MARSHAL</a> decision and every cross-platform governance event is recorded in
        CITADEL's <strong>WORM</strong> (Write-Once, Read-Many) audit chain — an append-only
        PostgreSQL table where no entry is ever mutable. Integrity is provable by recomputing
        hashes from the raw payload bytes: each entry carries a 128-byte{' '}
        <strong>TripleHash</strong> (SHA-256 + SHA-512 + BLAKE3) and a SHA-256 chain linkage
        that binds it to every preceding entry. <strong>Ed25519 chain anchors</strong> seal
        blocks of 100 entries, turning the log from tamper-evident into tamper-resistant.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Three layers of cryptographic protection stack on top of each other:
      </p>
      <ul>
        <li>
          <strong>TripleHash</strong> — per-entry content-addressable digest computed from
          three independent algorithms simultaneously. A forged payload must collide against
          all three.
        </li>
        <li>
          <strong>Chain hash</strong> — SHA-256 of (<code>prev_chain_hash ‖ payload_bytes</code>)
          links every entry to all prior entries. Editing any byte of any past entry forces
          every subsequent chain_hash to change.
        </li>
        <li>
          <strong>Ed25519 anchor</strong> — a cryptographic signature over the current
          chain_hash emitted every 100 entries. An attacker who rewrites the chain must also
          forge the anchor signature, which requires the private key.
        </li>
      </ul>

      <h2 id="table-structure">Table structure</h2>
      <CodeBlock
        language="bash"
        filename="worm_entries DDL"
        code={`CREATE TABLE worm_entries (
    id           UUID        PRIMARY KEY,
    sequence_num BIGINT      NOT NULL UNIQUE,
    ts_utc       TIMESTAMPTZ NOT NULL,
    source       TEXT        NOT NULL,  -- e.g. "citadel.marshal", "irflow.incident"
    event_type   TEXT        NOT NULL,  -- e.g. "marshal.decision", "incident.created"
    project_id   TEXT        NOT NULL,
    payload      BYTEA       NOT NULL,  -- raw JSON, byte-for-byte
    triple_hash  TEXT        NOT NULL,  -- 256 hex chars
    chain_hash   TEXT        NOT NULL,  -- 64 hex chars
    prev_hash    TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);`}
      />
      <p>
        <code>sequence_num</code> is monotonic from 1 upward. The table has a PostgreSQL
        immutability trigger that rejects any <code>UPDATE</code> or <code>DELETE</code>{' '}
        statement — append-only is enforced at the database level, not only by the application.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>id</code></td>
              <td>Caller-facing UUID — returned as <code>worm_entry_id</code> to IRFlow etc. Primary key but not used in chain math.</td>
            </tr>
            <tr>
              <td><code>sequence_num</code></td>
              <td>Monotonic ordinal; the chain walks entries in <code>sequence_num</code> ASC order.</td>
            </tr>
            <tr>
              <td><code>ts_utc</code></td>
              <td>When CITADEL accepted the entry — not when the caller built the payload.</td>
            </tr>
            <tr>
              <td><code>source</code></td>
              <td>Subsystem or platform that emitted this entry, e.g. <code>citadel.marshal</code>, <code>irflow.incident</code>.</td>
            </tr>
            <tr>
              <td><code>event_type</code></td>
              <td>Specific event taxonomy, e.g. <code>marshal.decision</code>, <code>incident.created</code>. Enables per-type queries without payload parsing.</td>
            </tr>
            <tr>
              <td><code>project_id</code></td>
              <td>Logical partition for auditor queries.</td>
            </tr>
            <tr>
              <td><code>payload</code></td>
              <td>Raw bytes the caller sent. Never canonicalised, never re-serialised.</td>
            </tr>
            <tr>
              <td><code>triple_hash</code></td>
              <td>Content-addressable composite digest — 256 hex characters.</td>
            </tr>
            <tr>
              <td><code>chain_hash</code></td>
              <td>Tamper-evident link to all prior entries.</td>
            </tr>
            <tr>
              <td><code>prev_hash</code></td>
              <td>The previous entry's <code>chain_hash</code>, or the genesis hash for entry 1.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="genesis-hash">Genesis hash</h2>
      <p>
        The chain starts at <code>sequence_num = 1</code>. Its <code>prev_hash</code> is the
        fixed genesis hash:
      </p>
      <CodeBlock
        language="bash"
        filename="Genesis hash"
        code={`genesis = SHA-256("CITADEL-GENESIS-SIN-v1")
        = f0c8e9...  (64 hex chars)`}
      />
      <p>
        <a href="/docs/citadel/evidence">Auditors</a> can independently compute this value. Changing the genesis constant would
        change every downstream hash in the chain, so the constant is implicitly covered by
        any chain verification pass.
      </p>

      <h2 id="triple-hash">TripleHash construction</h2>
      <p>
        TripleHash produces a 128-byte composite digest for every WORM entry. The three
        algorithms run over the identical payload bytes and their outputs are concatenated in
        a fixed order:
      </p>
      <CodeBlock
        language="bash"
        filename="TripleHash layout (128 bytes)"
        code={`      0               32                              96         128
      ├──── SHA-256 ───┼──────── SHA-512 ────────────────┼── BLAKE3 ─┤
      │   32 bytes     │          64 bytes               │  32 bytes │

# On-disk form: hex-encoded → 256 hex characters`}
      />
      <CodeBlock
        language="go"
        filename="internal/db/worm.go — TripleHash"
        code={`h256 := sha256.Sum256(payload)  // 32 bytes
h512 := sha512.Sum512(payload)  // 64 bytes
hB3  := blake3.Sum256(payload)  // 32 bytes

composite := append(h256[:], append(h512[:], hB3[:]...)...)
return hex.EncodeToString(composite) // 256 hex chars`}
      />
      <p>
        The order is fixed: SHA-256, then SHA-512, then BLAKE3. Any other ordering yields a
        different digest and fails verification.
      </p>

      <h2 id="why-three-hashes">Why three hashes?</h2>
      <p>
        Cryptographic hashes fail in three fundamentally different ways: collision attacks,
        preimage attacks, and algorithmic breaks (as happened to MD5 and SHA-1). TripleHash
        uses three algorithms with <strong>independent design histories</strong>:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Hash</th>
              <th>Family</th>
              <th>Design pedigree</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>SHA-256</td>
              <td>Merkle–Damgård</td>
              <td>NIST FIPS 180-4, widely scrutinised since 2001. Mandatory for regulatory acceptance.</td>
            </tr>
            <tr>
              <td>SHA-512</td>
              <td>Merkle–Damgård (wider word size)</td>
              <td>Same family as SHA-256 but different internal word size — a break in SHA-256 does not automatically break SHA-512.</td>
            </tr>
            <tr>
              <td>BLAKE3</td>
              <td>Sponge / Merkle-tree (ChaCha permutation)</td>
              <td>Completely different internal structure; resistant to length-extension attacks that SHA-2 tolerates. Faster than SHA-256 on modern hardware.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        An attacker who wants to substitute a forged payload must find a triple where all
        three independent digests collide simultaneously — the difficulty multiplies, not
        adds. A hypothetical collision in SHA-256 gives no leverage against SHA-512 or BLAKE3
        on the same payload.
      </p>
      <p>
        Other triples were considered and rejected:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Candidate</th>
              <th>Reason excluded</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>SHA-256 + SHA-3-256 + BLAKE3</td>
              <td>SHA-3 is excellent, but BLAKE3 is faster and has wider library support in Go.</td>
            </tr>
            <tr>
              <td>SHA-256 + SHA-512 + Keccak-256</td>
              <td>Keccak has hardware adoption bias; keeps the ecosystem tied to Ethereum-style tooling.</td>
            </tr>
            <tr>
              <td>SHA-512/256 + BLAKE3 + Argon2</td>
              <td>Argon2 is a KDF, not a hash — including it confuses the semantics.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="callout-note">
        <strong>Note:</strong> TripleHash is not a MAC — it uses no secret key. Two parties
        with the same payload compute the same digest. Authentication comes from the Ed25519
        chain anchor, not from TripleHash itself.
      </div>

      <h2 id="chain-linkage">Per-entry chain linkage</h2>
      <p>
        Each entry's <code>chain_hash</code> is computed as:
      </p>
      <CodeBlock
        language="bash"
        filename="Chain-hash formula"
        code={`chain_hash(i) = SHA-256( bytes(prev_hash(i))  ||  bytes(payload(i)) )

# where:
#   bytes(prev_hash(i)) = decoded 32-byte value of the previous chain_hash
#                         (or genesis bytes for entry 1)
#   bytes(payload(i))   = raw JSON byte stream, byte-for-byte as stored
#   ||                  = byte concatenation`}
      />
      <p>
        The key invariant: changing any byte of any earlier payload changes every subsequent{' '}
        <code>chain_hash</code>. An attacker who wants to retroactively edit entry N must
        re-hash N, N+1, N+2, … and also produce a valid Ed25519 anchor over the range that
        covers them. The anchor private key is what makes this impossible without a key
        compromise.
      </p>

      <h2 id="append-operation">Append operation</h2>
      <p>
        WORM appends run inside an exclusive table lock to guarantee strict single-writer
        ordering — concurrent appenders would produce divergent chains that cannot reconcile:
      </p>
      <CodeBlock
        language="bash"
        filename="WORM append (pseudocode)"
        code={`BEGIN;
LOCK TABLE worm_entries IN EXCLUSIVE MODE;

  -- get previous tail
  SELECT sequence_num, chain_hash
    FROM worm_entries
   ORDER BY sequence_num DESC
   LIMIT 1;
  -- if empty: seq = 0, prev_hash = genesisHash()

  seq := prev.seq + 1
  th  := TripleHash(payload)          -- 256 hex chars
  ch  := SHA-256(prev.chain_hash || payload)  -- 64 hex chars

  INSERT INTO worm_entries (
    id, sequence_num, ts_utc, source, event_type, project_id,
    payload, triple_hash, chain_hash, prev_hash, created_at
  ) VALUES (...);

COMMIT;`}
      />
      <p>
        Throughput scales vertically (faster disk, faster fsync) rather than horizontally.
        The v2.0 roadmap includes sharded chains per <code>project_id</code> as the path
        to horizontal scale.
      </p>

      <h2 id="chain-anchors">Ed25519 chain anchors</h2>
      <p>
        TripleHash + chain_hash linkage makes the WORM log <strong>tamper-evident</strong>:
        any change forces a cascade of mismatching hashes that a verification pass catches.
        However, an attacker who can also rewrite the chain_hash values would need more work
        but could potentially re-validate the tail against itself.
      </p>
      <p>
        Chain anchors close that gap. At a configurable interval (default: every 100 entries),
        CITADEL computes an Ed25519 signature over the latest <code>chain_hash</code> plus the{' '}
        <code>sequence_num</code> and <code>ts_utc</code>, then persists it to the{' '}
        <code>chain_anchors</code> table. An auditor holding the public key can verify the
        anchor independently — an attacker who does not have the private key cannot forge the
        signature no matter how many chain_hashes they rewrite, making the log{' '}
        <strong>tamper-resistant</strong>.
      </p>
      <CodeBlock
        language="bash"
        filename="Anchor flow"
        code={`# Every CITADEL_ANCHOR_INTERVAL entries (default: 100):

anchor_payload = sequence_num || ts_utc || chain_hash   # pipe-delimited string

signature = Ed25519.Sign(
    master_private_key,
    SHA-512(anchor_payload)
)

INSERT INTO chain_anchors (sequence_num, ts_utc, chain_hash, signature, pubkey_id, ...)`}
      />
      <div className="callout-warning">
        <strong>Warning:</strong> Without a valid <code>CITADEL_CITADEL_MASTER_KEY</code>{' '}
        configured, anchor emission is disabled. The WORM chain remains tamper-evident but
        not tamper-resistant. Do not run production CITADEL without an Ed25519 master key.
      </div>

      <h2 id="anchor-storage">Anchor storage</h2>
      <CodeBlock
        language="bash"
        filename="chain_anchors DDL"
        code={`CREATE TABLE chain_anchors (
    id           UUID        PRIMARY KEY,
    sequence_num BIGINT      NOT NULL REFERENCES worm_entries(sequence_num),
    ts_utc       TIMESTAMPTZ NOT NULL,
    chain_hash   TEXT        NOT NULL,   -- chain_hash at anchor time
    signature    BYTEA       NOT NULL,   -- 64-byte Ed25519 signature
    pubkey_id    TEXT        NOT NULL,   -- identifies the key that signed
    created_at   TIMESTAMPTZ NOT NULL
);`}
      />
      <p>
        Anchors reference the exact <code>sequence_num</code> and <code>chain_hash</code>{' '}
        they cover. An auditor queries the anchor they trust, reads its{' '}
        <code>(sequence_num, chain_hash)</code>, then runs chain verification up to that point.
      </p>

      <h2 id="verification">Chain verification</h2>
      <p>
        <code>GET /api/v1/worm/verify?from=...&amp;to=...</code> runs over the requested time
        range and returns:
      </p>
      <CodeBlock
        language="bash"
        filename="Verification response (success)"
        code={`{
  "valid":            true,
  "entries_verified": 12847,
  "anchor_verified":  true
}`}
      />
      <p>
        Verification steps, per entry in <code>[from, to]</code> by <code>sequence_num</code>{' '}
        ASC:
      </p>
      <ol>
        <li>
          <strong>Recompute TripleHash.</strong> If{' '}
          <code>TripleHash(payload) != stored triple_hash</code>, the payload bytes changed.
          Return <code>valid: false</code>.
        </li>
        <li>
          <strong>Recompute chain_hash.</strong> If{' '}
          <code>SHA-256(prev_hash ‖ payload) != stored chain_hash</code>, the chain linkage
          was tampered. Return <code>valid: false</code>.
        </li>
        <li>
          <strong>Continuity.</strong> <code>prev_hash(i) == chain_hash(i-1)</code> for{' '}
          <code>i {'>'} 1</code>. Otherwise an entry was spliced into a chain it does not
          belong to.
        </li>
      </ol>
      <CodeBlock
        language="bash"
        filename="Verification response (failure)"
        code={`{
  "valid":            false,
  "entries_verified": 12846,
  "break_at":         "sequence_num=12847: chain_hash mismatch",
  "anchor_verified":  false
}`}
      />
      <p>
        <code>break_at</code> points at the first broken entry, which is almost always the
        first entry an attacker tried to forge.
      </p>
      <p>
        To verify an anchor signature in Go:
      </p>
      <CodeBlock
        language="go"
        filename="Anchor verification"
        code={`pubKey := LoadTrustedPubKey("citadel-anchor-2026")
anchor := GetAnchor(sequenceNum)

payload := fmt.Sprintf("%d|%s|%s",
    anchor.SequenceNum,
    anchor.TsUTC.Format(time.RFC3339),
    anchor.ChainHash,
)
digest := sha512.Sum512([]byte(payload))

if !ed25519.Verify(pubKey, digest[:], anchor.Signature) {
    // anchor is forged, or the private key was rotated after this anchor
}`}
      />
      <p>
        For a tamper-resistant end-to-end check: pick a trusted anchor <em>A</em>; run linear
        chain verification from the previous anchor (or genesis) up to{' '}
        <code>A.sequence_num</code>; confirm the chain_hash you reach equals{' '}
        <code>A.chain_hash</code>; then verify <code>A.signature</code> with the matching
        pubkey. Any forged entry in the window invalidates the chain_hash, which invalidates
        the anchor signature.
      </p>
      <p>
        After any disaster recovery — even from the coldest backup — the restored log can
        be cryptographically verified against the original chain anchors. Tampered recovery
        is detectable.
      </p>

      <h2 id="key-management">Key management</h2>
      <p>
        The Ed25519 master key is the single most sensitive secret in the ecosystem. Losing
        it means all past anchors remain valid (their signatures verify against the public
        key), but no new anchors can be signed until a new key is provisioned.
      </p>
      <p>Key rotation procedure (manual in v1.0.0; automation planned for v1.1):</p>
      <CodeBlock
        language="bash"
        filename="Key rotation"
        code={`# 1. Generate a new Ed25519 keypair
openssl genpkey -algorithm ed25519 -out citadel-anchor-2027Q2.pem

# 2. Publish the new pubkey under a new pubkey_id in your key bundle
#    e.g. citadel-anchor-2027Q2

# 3. Update CITADEL_CITADEL_MASTER_KEY in your secret manager

# 4. Roll the CITADEL deployment (zero-downtime rolling update)

# DO NOT delete the old pubkey — every anchor signed with it remains
# valid and auditors need it for the entire retention period.`}
      />
      <div className="callout-warning">
        <strong>Warning:</strong> An anchor private-key compromise is the only attack that
        wholly defeats the chain. Best practice: store the master key in an HSM with a PKCS#11
        adapter. CITADEL v2.0 roadmap includes KMIP/PKCS#11 support so the private key never
        leaves the HSM.
      </div>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Adversary capability</th>
              <th>Covered by</th>
              <th>Recovery</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>DB-level read attacker</td>
              <td>TripleHash — payload changes are detected</td>
              <td>Re-issue anchor from the good state; restore from backup</td>
            </tr>
            <tr>
              <td>DB-level write — single payload</td>
              <td>chain_hash — break propagates to all later entries</td>
              <td>Verify chain; <code>break_at</code> pinpoints the forgery</td>
            </tr>
            <tr>
              <td>DB-level write — entire chain rewritten</td>
              <td>Ed25519 anchor — signature won't verify on the forged chain_hash</td>
              <td>Public key doesn't verify; chain is void</td>
            </tr>
            <tr>
              <td>Attacker with the anchor private key</td>
              <td><strong>Not covered</strong></td>
              <td>Rotate key, publish both old and new pubkeys; audit the interval of exposure</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="what-worm-does-not-do">What WORM does not do</h2>
      <ul>
        <li>
          <strong>No deletion.</strong> Even under GDPR right-to-be-forgotten, PII must not
          enter the payload in the first place — there is no erasure path. Pseudonymise at
          the caller layer before constructing the Kerkese or WORM payload.
        </li>
        <li>
          <strong>No compaction.</strong> Entries accumulate forever. For a 10-year horizon
          at 1 MiB/day, expect roughly 3.7 TB. Archival tiers for entries older than one year
          are planned for v2.0.
        </li>
        <li>
          <strong>No multi-writer.</strong> Two CITADEL primaries appending to the same chain
          produce divergent tails that cannot merge. The exclusive table lock is deliberate and
          non-negotiable.
        </li>
        <li>
          <strong>No conditional append.</strong> Every emission unconditionally appends.
          Decisions about whether an action should happen are made upstream in MARSHAL.
        </li>
      </ul>

      <h2 id="benchmarks">Benchmarks</h2>
      <p>
        Measured on Go 1.24.4, Intel Core i7-7600U.
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
              <td>SHA-256 only (100-byte payload)</td>
              <td>~0.35 µs</td>
              <td></td>
            </tr>
            <tr>
              <td>SHA-512 only (100-byte payload)</td>
              <td>~0.55 µs</td>
              <td>Dominates TripleHash time</td>
            </tr>
            <tr>
              <td>BLAKE3 only (100-byte payload)</td>
              <td>~0.40 µs</td>
              <td></td>
            </tr>
            <tr>
              <td>Hex encode (128 bytes)</td>
              <td>~0.22 µs</td>
              <td></td>
            </tr>
            <tr>
              <td><strong>TripleHash total (100-byte payload)</strong></td>
              <td><strong>1.52 µs</strong></td>
              <td>SHA-256 + SHA-512 + BLAKE3 in parallel</td>
            </tr>
            <tr>
              <td>WORM chain step (hash linkage only, no DB)</td>
              <td>427 ns, 0 allocations</td>
              <td>SHA-256 linkage of prev_hash + payload</td>
            </tr>
            <tr>
              <td>WORM append (PostgreSQL 16, synchronous)</td>
              <td>4.22 ms</td>
              <td>Includes immutability trigger and fsync</td>
            </tr>
            <tr>
              <td>Chain verification (1,000 entries)</td>
              <td>10.19 ms</td>
              <td>Full TripleHash recomputation per entry</td>
            </tr>
            <tr>
              <td>Ed25519 sign (one anchor)</td>
              <td>~50–80 µs</td>
              <td>Amortised over 100 entries: &lt;1 µs per entry</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        The WORM append at 4.22 ms dominates every real-world call — it is ~2,800× slower
        than TripleHash itself. The SHA-512 component dominates TripleHash time, but moving to
        a SIMD-accelerated library would have no meaningful impact against the surrounding DB
        append cost.
      </p>
    </DocsLayout>
  )
}
