package reporter

import (
	"bytes"
	"html/template"
	"strings"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/version"
)

// HTMLReporter generates a self-contained HTML report using Go templates.
type HTMLReporter struct{}

// htmlData holds the template context for the HTML report.
type htmlData struct {
	ScanID      string
	Target      string
	SpecHash    string
	Status      string
	StartedAt   string
	CompletedAt string
	Duration    string
	Version     string
	GeneratedAt string

	Summary  domain.ScanSummary
	Findings []domain.Finding

	Critical []domain.Finding
	High     []domain.Finding
	Medium   []domain.Finding
	Low      []domain.Finding
	Info     []domain.Finding
}

// Generate produces a self-contained HTML report.
func (r *HTMLReporter) Generate(result *domain.ScanResult) ([]byte, error) {
	data := htmlData{
		ScanID:      result.ID,
		Target:      result.Target,
		SpecHash:    result.SpecHash,
		Status:      string(result.Status),
		StartedAt:   result.StartedAt.Format(time.RFC3339),
		CompletedAt: result.CompletedAt.Format(time.RFC3339),
		Duration:    result.CompletedAt.Sub(result.StartedAt).String(),
		Version:     version.Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     result.Summary,
		Findings:    result.Findings,
	}

	// Partition findings by severity.
	for _, f := range result.Findings {
		switch f.Severity {
		case domain.SeverityCritical:
			data.Critical = append(data.Critical, f)
		case domain.SeverityHigh:
			data.High = append(data.High, f)
		case domain.SeverityMedium:
			data.Medium = append(data.Medium, f)
		case domain.SeverityLow:
			data.Low = append(data.Low, f)
		case domain.SeverityInfo:
			data.Info = append(data.Info, f)
		}
	}

	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"severityClass": func(s domain.Severity) string {
			return strings.ToLower(string(s))
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APIGuard Scan Report - {{ .Target }}</title>
<style>
  :root {
    --color-critical: #d32f2f;
    --color-high: #e65100;
    --color-medium: #f9a825;
    --color-low: #1565c0;
    --color-info: #757575;
    --color-bg: #fafafa;
    --color-card: #ffffff;
    --color-text: #212121;
    --color-border: #e0e0e0;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --color-bg: #121212;
      --color-card: #1e1e1e;
      --color-text: #e0e0e0;
      --color-border: #333333;
    }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--color-bg);
    color: var(--color-text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  h1, h2, h3 { margin-bottom: 0.5rem; }
  h1 { font-size: 1.8rem; margin-bottom: 1rem; }
  h2 { font-size: 1.4rem; margin-top: 2rem; border-bottom: 2px solid var(--color-border); padding-bottom: 0.3rem; }
  h3 { font-size: 1.1rem; margin-top: 1.5rem; }
  .card {
    background: var(--color-card);
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
  }
  .summary-item {
    text-align: center;
    padding: 1rem;
    border-radius: 8px;
    background: var(--color-card);
    border: 1px solid var(--color-border);
  }
  .summary-item .count {
    font-size: 2rem;
    font-weight: bold;
    display: block;
  }
  .summary-item .label { font-size: 0.85rem; text-transform: uppercase; }
  .severity-critical .count { color: var(--color-critical); }
  .severity-high .count { color: var(--color-high); }
  .severity-medium .count { color: var(--color-medium); }
  .severity-low .count { color: var(--color-low); }
  .severity-info .count { color: var(--color-info); }
  .badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: bold;
    color: #fff;
    text-transform: uppercase;
  }
  .badge.critical { background: var(--color-critical); }
  .badge.high { background: var(--color-high); }
  .badge.medium { background: var(--color-medium); color: #000; }
  .badge.low { background: var(--color-low); }
  .badge.info { background: var(--color-info); }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
  }
  th, td {
    text-align: left;
    padding: 0.6rem 0.8rem;
    border-bottom: 1px solid var(--color-border);
  }
  th { font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
  tr:hover { background: rgba(0,0,0,0.03); }
  pre {
    background: #263238;
    color: #eeffff;
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 0.85rem;
    line-height: 1.4;
    margin: 0.5rem 0;
    white-space: pre-wrap;
    word-wrap: break-word;
  }
  .meta { font-size: 0.85rem; color: var(--color-info); margin-bottom: 0.5rem; }
  .finding-detail { margin-bottom: 2rem; }
  .cvss { font-weight: bold; }
  footer { margin-top: 3rem; font-size: 0.8rem; color: var(--color-info); text-align: center; }
  a { color: var(--color-low); }
  @media print {
    body { padding: 0; }
    .finding-detail { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<h1>APIGuard Scan Report</h1>

<div class="card">
  <h2 style="margin-top:0; border:none;">Executive Summary</h2>
  <p class="meta">Scan ID: {{ .ScanID }}</p>
  <p class="meta">Target: {{ .Target }}</p>
  <p class="meta">Started: {{ .StartedAt }} | Completed: {{ .CompletedAt }} | Duration: {{ .Duration }}</p>
  <p class="meta">Status: {{ upper .Status }}</p>

  <div class="summary-grid">
    <div class="summary-item severity-critical">
      <span class="count">{{ .Summary.Critical }}</span>
      <span class="label">Critical</span>
    </div>
    <div class="summary-item severity-high">
      <span class="count">{{ .Summary.High }}</span>
      <span class="label">High</span>
    </div>
    <div class="summary-item severity-medium">
      <span class="count">{{ .Summary.Medium }}</span>
      <span class="label">Medium</span>
    </div>
    <div class="summary-item severity-low">
      <span class="count">{{ .Summary.Low }}</span>
      <span class="label">Low</span>
    </div>
    <div class="summary-item severity-info">
      <span class="count">{{ .Summary.Info }}</span>
      <span class="label">Info</span>
    </div>
  </div>
  <p><strong>Total Findings: {{ .Summary.TotalFindings }}</strong></p>
</div>

{{ if .Findings }}
<h2>Findings Overview</h2>
<div class="card">
<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Title</th>
      <th>OWASP</th>
      <th>Endpoint</th>
      <th>CVSS</th>
    </tr>
  </thead>
  <tbody>
    {{ range .Findings }}
    <tr>
      <td><span class="badge {{ severityClass .Severity }}">{{ upper (severityClass .Severity) }}</span></td>
      <td><a href="#finding-{{ .ID }}">{{ .Title }}</a></td>
      <td>{{ .OWASPId }}</td>
      <td>{{ .EndpointMethod }} {{ .EndpointPath }}</td>
      <td class="cvss">{{ .CVSSScore }}</td>
    </tr>
    {{ end }}
  </tbody>
</table>
</div>

<h2>Finding Details</h2>

{{ range .Findings }}
<div class="card finding-detail" id="finding-{{ .ID }}">
  <h3><span class="badge {{ severityClass .Severity }}">{{ upper (severityClass .Severity) }}</span> {{ .Title }}</h3>
  <p class="meta">ID: {{ .ID }} | Module: {{ .ModuleID }} | OWASP: {{ .OWASPId }}</p>
  <p class="meta">Endpoint: {{ .EndpointMethod }} {{ .EndpointPath }}</p>
  <p class="meta">CVSS: <span class="cvss">{{ .CVSSScore }}</span> {{ .CVSSVector }}</p>

  <h3>Description</h3>
  <p>{{ .Description }}</p>

  {{ if .Evidence.Request }}
  <h3>Evidence - Request</h3>
  <pre>{{ .Evidence.Request }}</pre>
  {{ end }}

  {{ if .Evidence.Response }}
  <h3>Evidence - Response</h3>
  <pre>{{ .Evidence.Response }}</pre>
  {{ end }}

  {{ if .Remediation }}
  <h3>Remediation</h3>
  <p>{{ .Remediation }}</p>
  {{ end }}
</div>
{{ end }}

{{ else }}
<div class="card">
  <p>No findings were detected during this scan.</p>
</div>
{{ end }}

<footer>
  Generated by APIGuard {{ .Version }} at {{ .GeneratedAt }}
</footer>

</body>
</html>`
