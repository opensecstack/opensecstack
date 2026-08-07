// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting

import (
	"bytes"
	"fmt"
	"html"
	"time"
)

// GenerateHTML produces a self-contained HTML coverage report with a summary
// table and inline CSS bar charts showing detection rates per technique.
func GenerateHTML(report CoverageReport) ([]byte, error) {
	var b bytes.Buffer

	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
	}

	overallPct := report.OverallDetectionRate * 100
	overallColour := rateColour(report.OverallDetectionRate)

	w(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureLab — Detection Coverage Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }
  h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
  .subtitle { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }
  .summary { display: flex; gap: 2rem; margin-bottom: 2rem; }
  .stat-card { background: #1e2130; border-radius: 0.5rem; padding: 1.25rem 1.75rem; min-width: 160px; }
  .stat-card .label { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
  table { width: 100%%; border-collapse: collapse; }
  thead th { text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem;
             text-transform: uppercase; letter-spacing: 0.05em; color: #64748b;
             border-bottom: 1px solid #2d3446; }
  tbody tr:hover { background: #1a1f2e; }
  td { padding: 0.6rem 0.75rem; font-size: 0.875rem; border-bottom: 1px solid #1a1f2e; vertical-align: middle; }
  .bar-wrap { background: #1e2130; border-radius: 999px; height: 8px; width: 120px; overflow: hidden; }
  .bar-fill { height: 100%%; border-radius: 999px; }
  .green  { color: #4ade80; }
  .yellow { color: #facc15; }
  .red    { color: #f87171; }
  .mitre-id { font-family: monospace; font-size: 0.8rem; color: #7dd3fc; }
  a { color: #7dd3fc; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>SecureLab — Detection Coverage Report</h1>
<p class="subtitle">Generated %s &nbsp;|&nbsp; %d scenario runs</p>
<div class="summary">
  <div class="stat-card">
    <div class="label">Overall Detection Rate</div>
    <div class="value %s">%.1f%%</div>
  </div>
  <div class="stat-card">
    <div class="label">Total Runs</div>
    <div class="value">%d</div>
  </div>
  <div class="stat-card">
    <div class="label">Detected</div>
    <div class="value green">%d</div>
  </div>
  <div class="stat-card">
    <div class="label">Missed</div>
    <div class="value red">%d</div>
  </div>
</div>
<table>
<thead>
  <tr>
    <th>Attack Kind</th>
    <th>MITRE ID</th>
    <th>Technique Name</th>
    <th>Runs</th>
    <th>Detected</th>
    <th>Missed</th>
    <th>Detection Rate</th>
    <th>Coverage</th>
  </tr>
</thead>
<tbody>
`,
		time.Now().Format("2006-01-02 15:04 UTC"),
		report.TotalRuns,
		overallColour, overallPct,
		report.TotalRuns,
		report.TotalDetected,
		report.TotalRuns-report.TotalDetected,
	)

	for _, row := range report.Rows {
		pct := row.DetectionRate * 100
		colour := rateColour(row.DetectionRate)
		barColour := rateBarColour(row.DetectionRate)
		barWidth := int(pct)

		mitreCell := ""
		if row.TechniqueID != "" {
			entry, _ := LookupByKind(row.AttackKind)
			mitreCell = fmt.Sprintf(`<a class="mitre-id" href="%s" target="_blank">%s</a>`,
				html.EscapeString(entry.URL), html.EscapeString(row.TechniqueID))
		}

		w(`  <tr>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
    <td>%d</td>
    <td class="green">%d</td>
    <td class="red">%d</td>
    <td class="%s">%.1f%%</td>
    <td>
      <div class="bar-wrap">
        <div class="bar-fill" style="width:%d%%;background:%s;"></div>
      </div>
    </td>
  </tr>
`,
			html.EscapeString(row.AttackKind),
			mitreCell,
			html.EscapeString(row.TechniqueName),
			row.TotalRuns,
			row.DetectedRuns,
			row.MissedRuns,
			colour, pct,
			barWidth, barColour,
		)
	}

	w(`</tbody>
</table>
<p style="margin-top:2rem;font-size:0.75rem;color:#475569;">
  SecureLab attack simulation platform — opensecstack. All simulations target isolated lab environments only.
</p>
</body>
</html>
`)
	return b.Bytes(), nil
}

// rateColour returns the CSS class name for a detection rate.
func rateColour(rate float64) string {
	switch {
	case rate >= 0.75:
		return "green"
	case rate >= 0.4:
		return "yellow"
	default:
		return "red"
	}
}

// rateBarColour returns an inline CSS colour hex for bar fills.
func rateBarColour(rate float64) string {
	switch {
	case rate >= 0.75:
		return "#4ade80"
	case rate >= 0.4:
		return "#facc15"
	default:
		return "#f87171"
	}
}
