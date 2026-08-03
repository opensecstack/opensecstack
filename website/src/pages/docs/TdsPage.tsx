import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'what-is-tds', label: 'What is TDS?' },
  { id: 'the-three-tiers', label: 'The three tiers' },
  { id: 'platform-assignments', label: 'Platform TDS assignments' },
  { id: 'implementation-patterns', label: 'Implementation patterns' },
  { id: 'cross-tier-decomposition', label: 'Cross-tier decomposition' },
  { id: 'triplehash-alignment', label: 'TripleHash alignment' },
  { id: 'tds-scanner', label: 'tds-scanner' },
  { id: 'ci-integration', label: 'CI/CD integration' },
]

export default function TdsPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Architecture', 'Time Dimension Segmentation']}
      toc={toc}
      editPath="TdsPage.tsx"
      prev={{ label: 'SDK & Contracts', path: '/docs/contracts' }}
      next={{ label: 'CITADEL Integration', path: '/docs/citadel-integration' }}
    >
      <Helmet>
        <title>Time Dimension Segmentation | opensecstack Docs</title>
        <meta
          name="description"
          content="Time Dimension Segmentation (TDS) assigns every opensecstack API endpoint and background job to one of three latency tiers, enforced at runtime by the tds-scanner tool."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/tds" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/tds" />
        <meta property="og:title" content="Time Dimension Segmentation | opensecstack Docs" />
        <meta
          property="og:description"
          content="Time Dimension Segmentation (TDS) assigns every opensecstack API endpoint and background job to one of three latency tiers, enforced at runtime by the tds-scanner tool."
        />
      </Helmet>
      <h1>Time Dimension Segmentation</h1>
      <p>
        <strong>Time Dimension Segmentation (TDS)</strong> is a cross-cutting architectural
        principle for all opensecstack platforms. It assigns every API endpoint and background
        job to one of three named latency tiers, prescribes the implementation pattern for each
        tier, and provides a tool — <code>tds-scanner</code> — to measure compliance at runtime.
        TDS is defined across the full <a href="/docs/architecture">Architecture</a> and applies
        to every platform in the ecosystem.
      </p>
      <p>
        The rationale and formal decision record are in{' '}
        <a
          href="https://github.com/opensecstack/opensecstack/blob/main/adrs/ADR-009-time-dimension-segmentation.md"
          target="_blank"
          rel="noopener noreferrer"
        >
          ADR-009
        </a>
        .
      </p>

      <h2 id="what-is-tds">What is TDS?</h2>
      <p>
        opensecstack platforms handle operations whose latency requirements span many orders of
        magnitude — from sub-millisecond hash computations to multi-minute full-platform audit
        scans. Without explicit latency contracts, teams repeatedly made the same mistakes:
        synchronous endpoints blocking on operations that should have been async, fast operations
        delayed by co-located slow work, and no shared vocabulary for discussing expected response
        times across codebases written in Go, Rust, Python, and TypeScript.
      </p>
      <p>
        TDS solves this by dividing operations into three tiers named after clock hands. Each tier
        carries an implicit latency contract and a prescribed implementation pattern. Saying "this
        endpoint is second-hand" communicates both the bound (<code>&lt;300ms</code>) and the
        required pattern (synchronous HTTP response) to anyone who has read this page once.
      </p>

      <h2 id="the-three-tiers">The three tiers</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Tier</th>
              <th>Latency bound</th>
              <th>Implementation pattern</th>
              <th>Example operations</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Second hand</strong></td>
              <td>&lt;300ms</td>
              <td>Synchronous HTTP response</td>
              <td>
                Health check, status poll, per-endpoint CVSS scoring,{' '}
                <a href="/docs/citadel/marshal">MARSHAL</a> gate evaluation,
                AUGUR advisory fetch, control status update
              </td>
            </tr>
            <tr>
              <td><strong>Minute hand</strong></td>
              <td>300ms – 30s</td>
              <td>
                Short-lived async job with polling endpoint, or synchronous with generous timeout
                (acceptable for operations &lt;10s)
              </td>
              <td>
                HTML/PDF report generation, full scan of a small API spec (&lt;50 endpoints),
                evidence artifact upload, audit log fetch, chain anchor age check
              </td>
            </tr>
            <tr>
              <td><strong>Hour hand</strong></td>
              <td>&gt;30s</td>
              <td>
                Background job with webhook callback or polling endpoint — never synchronous
              </td>
              <td>
                Full scan of a large API spec (&gt;200 endpoints), full compliance export,
                WORM chain verification (7-day window), VIGIL_DEEP full audit scan
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Rule:</strong> Any hour-hand operation inside a synchronous HTTP handler is
        automatically a design violation. The trigger must be second-hand; the slow work must run
        in the background.
      </div>

      <p>
        Prometheus alerting rules fire when a second-hand operation's P95 latency exceeds 250ms
        (warning) or 300ms (critical). All new API endpoints and background jobs must declare
        their TDS tier in the design document or ADR before a pull request can be merged.
      </p>

      <h2 id="platform-assignments">Platform TDS assignments</h2>

      <h3>APIGuard</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Tier</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Spec parse (Rust subprocess)</td><td>Second hand</td></tr>
            <tr><td>Per-endpoint analysis (Go)</td><td>Second hand</td></tr>
            <tr><td>CVSS scoring</td><td>Second hand</td></tr>
            <tr><td>Scan status API</td><td>Second hand</td></tr>
            <tr><td>HTML report generation</td><td>Minute hand</td></tr>
            <tr><td>PDF report generation</td><td>Minute hand</td></tr>
            <tr><td>Full scan — small spec (&lt;50 endpoints)</td><td>Minute hand</td></tr>
            <tr><td>Full scan — large spec (&gt;200 endpoints)</td><td>Hour hand</td></tr>
          </tbody>
        </table>
      </div>

      <h3>NIS2 Compass</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Tier</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Control status update</td><td>Second hand</td></tr>
            <tr><td>Organisation CRUD</td><td>Second hand</td></tr>
            <tr><td>Evidence artifact upload</td><td>Minute hand</td></tr>
            <tr><td>Audit log fetch</td><td>Minute hand</td></tr>
            <tr><td>Full compliance export</td><td>Hour hand</td></tr>
          </tbody>
        </table>
      </div>

      <h3>CITADEL</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Tier</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>MARSHAL gate evaluation</td><td>Second hand</td></tr>
            <tr><td>AUGUR advisory fetch</td><td>Second hand</td></tr>
            <tr><td>VIGIL_REALTIME status poll</td><td>Second hand</td></tr>
            <tr><td>Chain anchor age check</td><td>Minute hand</td></tr>
            <tr><td>WORM chain verify (7-day window)</td><td>Hour hand</td></tr>
            <tr><td>VIGIL_DEEP full audit scan</td><td>Hour hand</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="implementation-patterns">Implementation patterns</h2>

      <h3>Second-hand — synchronous handler</h3>
      <p>
        Must complete at P95 within 300ms. Avoid external HTTP calls (use cached data), full
        table scans without indexes, subprocess invocations longer than ~50ms, and loops over
        unbounded datasets.
      </p>
      <CodeBlock
        language="go"
        code={`// TDS: second-hand
func (h *Handler) GetVIGILStatus(w http.ResponseWriter, r *http.Request) {
    status, err := h.vigil.CurrentStatus(r.Context())
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(status)
}`}
      />

      <h3>Minute-hand — async job with polling</h3>
      <CodeBlock
        language="go"
        code={`// TDS: minute-hand — Pattern B: async job with polling
// POST /api/v1/reports — starts job, returns job ID immediately
func (h *Handler) StartReport(w http.ResponseWriter, r *http.Request) {
    jobID := h.jobs.Enqueue(reportJob)
    w.WriteHeader(http.StatusAccepted)
    json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// GET /api/v1/reports/{job_id} — poll for result
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
    job, _ := h.jobs.Get(jobID)
    if job.Status == "pending" {
        w.WriteHeader(http.StatusAccepted)
        return
    }
    json.NewEncoder(w).Encode(job.Result)
}`}
      />

      <h3>Hour-hand — background job, never synchronous</h3>
      <CodeBlock
        language="go"
        code={`// TDS: hour-hand
// POST /api/v1/vigil/deep-scan — enqueues scan, returns immediately
func (h *Handler) TriggerDeepScan(w http.ResponseWriter, r *http.Request) {
    scanID := h.deepScanner.Enqueue(DeepScanJob{Period: period})
    w.WriteHeader(http.StatusAccepted)
    json.NewEncoder(w).Encode(map[string]string{
        "scan_id":    scanID,
        "poll_url":   fmt.Sprintf("/api/v1/vigil/deep-scan/%s", scanID),
        "webhook_on": "vigil_deep_completed",
    })
}`}
      />

      <h2 id="cross-tier-decomposition">Cross-tier decomposition</h2>
      <p>
        Some operations have a fast trigger but slow execution. Decompose them so the caller
        always gets a fast response and the slow work runs in the background:
      </p>
      <CodeBlock
        language="bash"
        code={`# Second-hand:  POST /api/v1/scans          → {scan_id, status: "queued"}
# Second-hand:  GET  /api/v1/scans/{id}     → current status and progress
# Hour-hand:    [background] scan execution → updates status as it runs
# Second-hand:  GET  /api/v1/scans/{id}/findings → findings once complete`}
      />

      <h2 id="triplehash-alignment">TripleHash alignment</h2>
      <p>
        The <a href="/docs/governance">CITADEL</a> TripleHash scheme (BLAKE3 + SHA-256 + SHA-512) maps directly to TDS tiers,
        making the relationship between cryptographic assurance level and operational latency
        explicit:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Hash algorithm</th>
              <th>TDS tier</th>
              <th>Use</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>BLAKE3</td>
              <td>Second hand</td>
              <td>Per-request real-time integrity checks</td>
            </tr>
            <tr>
              <td>SHA-256</td>
              <td>Minute hand</td>
              <td>WORM chain hashing</td>
            </tr>
            <tr>
              <td>SHA-512</td>
              <td>Hour hand</td>
              <td>Long-term archival and Ed25519 anchor signing</td>
            </tr>
          </tbody>
        </table>
      </div>
      <CodeBlock
        language="go"
        code={`hash := vantage_hash.TripleHash.Compute(content)

// Second-hand: real-time integrity
realtimeCheck := hash.Blake3Hex()

// Minute-hand: WORM chain hashing
chainHash := hash.SHA256Hex()

// Hour-hand: archival / anchor signing
archivalHash := hash.SHA512Hex()`}
      />

      <h2 id="tds-scanner">tds-scanner</h2>
      <p>
        <code>tds-scanner</code> is a CLI tool in <code>sdk/tools/tds-scanner/</code> that
        measures actual operation latencies against tier bounds. It is the standard way to verify
        TDS compliance for a running deployment.
      </p>

      <h3>Installation</h3>
      <CodeBlock
        language="bash"
        code={`go install github.com/opensecstack/sdk/tools/tds-scanner@latest

# Or build from source
cd sdk/tools/tds-scanner
go build -o tds-scanner .`}
      />

      <h3>Running a scan</h3>
      <CodeBlock
        language="bash"
        code={`tds-scanner scan \\
  --target https://your-platform.internal \\
  --api-key $KEY \\
  --platform apiguard    # apiguard | nis2compass | citadel
  --iterations 5         # median of 5 runs per operation (default)
  --output text          # text | json | junit`}
      />

      <h3>Key flags</h3>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Flag</th>
              <th>Default</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>--target</code></td>
              <td>—</td>
              <td>Platform base URL (required)</td>
            </tr>
            <tr>
              <td><code>--api-key</code></td>
              <td>—</td>
              <td>API key for the platform (required)</td>
            </tr>
            <tr>
              <td><code>--platform</code></td>
              <td><code>apiguard</code></td>
              <td>Which platform's operation set to test</td>
            </tr>
            <tr>
              <td><code>--iterations</code></td>
              <td><code>5</code></td>
              <td>Runs per operation; median is reported</td>
            </tr>
            <tr>
              <td><code>--output</code></td>
              <td><code>text</code></td>
              <td>Output format: <code>text</code>, <code>json</code>, or <code>junit</code></td>
            </tr>
            <tr>
              <td><code>--fail-on-violation</code></td>
              <td><code>false</code></td>
              <td>Exit code 1 if any TDS violation is found</td>
            </tr>
            <tr>
              <td><code>--timeout</code></td>
              <td><code>300s</code></td>
              <td>Maximum total scan duration</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        A TDS violation does not mean the system is broken — it means an operation is taking
        longer than its tier contract allows. Common causes for second-hand violations are missing
        database indexes, network latency between scanner and platform, or the platform running
        under load.
      </p>

      <h3>JSON output format</h3>
      <CodeBlock
        language="typescript"
        code={`{
  "scan_id": "uuid",
  "ts_utc": "2026-03-30T14:00:00Z",
  "platform": "apiguard",
  "target": "https://apiguard.internal",
  "operations": [
    {
      "name": "scan_start",
      "tier": "second-hand",
      "tier_bound_ms": 300,
      "median_ms": 87,
      "p95_ms": 102,
      "status": "PASS"
    }
  ],
  "summary": {
    "total": 9,
    "pass": 9,
    "fail": 0,
    "tds_compliant": true
  }
}`}
      />

      <h2 id="ci-integration">CI/CD integration</h2>
      <p>
        Run <code>tds-scanner</code> in CI with <code>--fail-on-violation</code> to prevent TDS
        regressions from reaching production. The <code>junit</code> output format is compatible
        with GitHub Actions, GitLab CI, and Jenkins.
      </p>
      <CodeBlock
        language="yaml"
        filename=".github/workflows/tds.yml"
        code={`- name: TDS compliance scan
  run: |
    tds-scanner scan \\
      --target \${{ secrets.APIGUARD_URL }} \\
      --api-key \${{ secrets.APIGUARD_KEY }} \\
      --output junit \\
      --fail-on-violation \\
      > tds-results.xml

- name: Publish TDS results
  uses: mikepenz/action-junit-report@v4
  with:
    report_paths: tds-results.xml`}
      />
      <p>
        To capture a latency baseline for regression comparison use{' '}
        <code>tds-scanner baseline</code> and pass <code>--compare-baseline baseline.json</code>{' '}
        on subsequent scans.
      </p>
    </DocsLayout>
  )
}
