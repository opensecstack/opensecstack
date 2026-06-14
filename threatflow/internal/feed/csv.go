package feed

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CSV polls a feed URL that serves CSV rows of indicators. Each row is
// converted to a STIX 2.1 indicator; the batch becomes a single bundle.
//
// Supported layouts are auto-detected from the first header or first data row:
//   - abuse.ch urlhaus-csv: columns include "url", "threat"
//   - AlienVault OTX CSV: columns include "indicator", "type"
//   - generic: first column is the indicator value; a second column, when
//     present and matching a known type name, sets the IOC type.
type CSV struct {
	cfg Config
}

// NewCSV constructs a CSV poller.
func NewCSV(cfg Config) *CSV {
	return &CSV{cfg: cfg}
}

// Kind returns the feed_type string.
func (c *CSV) Kind() string { return "csv" }

// Poll fetches the CSV, parses each row into a STIX indicator, and returns
// the bundle payload.
func (c *CSV) Poll(ctx context.Context) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("csv GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("csv status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}

	records, err := readCSV(raw)
	if err != nil {
		return nil, 0, err
	}

	indicators := make([]json.RawMessage, 0, len(records))
	now := time.Now().UTC().Format(time.RFC3339)
	for i, row := range records {
		iocType, value := classifyRow(row)
		if value == "" {
			continue
		}
		pattern := fmt.Sprintf("[%s:value = '%s']", iocType, escapeSingleQuote(value))
		ind := map[string]any{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           deterministicIndicatorID(pattern),
			"created":      now,
			"modified":     now,
			"pattern":      pattern,
			"pattern_type": "stix",
			"valid_from":   now,
			"confidence":   c.cfg.ConfidenceBase,
		}
		if label := rowLabel(row); label != "" {
			ind["labels"] = []string{label}
		}
		buf, err := json.Marshal(ind)
		if err != nil {
			return nil, 0, fmt.Errorf("encode indicator[%d]: %w", i, err)
		}
		indicators = append(indicators, buf)
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           deterministicBundleID(c.cfg.Name, raw),
		"spec_version": "2.1",
		"objects":      indicators,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, 0, fmt.Errorf("encode bundle: %w", err)
	}
	return payload, len(indicators), nil
}

// readCSV parses the raw bytes, ignoring comment lines starting with '#'
// (abuse.ch prefixes its CSVs with banner comments) and returning only
// populated rows.
func readCSV(raw []byte) ([][]string, error) {
	reader := csv.NewReader(newCommentStripper(raw))
	reader.FieldsPerRecord = -1 // allow variable columns
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	return reader.ReadAll()
}

// classifyRow picks (type, value) from a CSV row using heuristics.
func classifyRow(row []string) (string, string) {
	if len(row) == 0 {
		return "", ""
	}
	// Two-column form: [type, value] or [value, type]
	if len(row) >= 2 {
		if t := normaliseType(row[0]); t != "" {
			return t, strings.TrimSpace(row[1])
		}
		if t := normaliseType(row[1]); t != "" {
			return t, strings.TrimSpace(row[0])
		}
	}
	// abuse.ch urlhaus: columns are id, dateadded, url, url_status, threat
	for _, cell := range row {
		cell = strings.TrimSpace(cell)
		if strings.HasPrefix(cell, "http://") || strings.HasPrefix(cell, "https://") {
			return "url", cell
		}
	}
	// generic single-value row — infer type
	val := strings.TrimSpace(row[0])
	return inferType(val), val
}

// rowLabel returns a suitable tag if the row has a trailing threat/category column.
func rowLabel(row []string) string {
	if len(row) < 3 {
		return ""
	}
	last := strings.TrimSpace(row[len(row)-1])
	if last == "" || strings.Contains(last, "://") {
		return ""
	}
	return strings.ToLower(last)
}

// normaliseType maps known OTX / abuse.ch type labels to STIX types.
func normaliseType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ipv4", "ipv4-addr", "ip", "ipaddr":
		return "ipv4-addr"
	case "ipv6", "ipv6-addr":
		return "ipv6-addr"
	case "domain", "domain-name", "hostname":
		return "domain-name"
	case "url", "uri":
		return "url"
	case "email", "email-addr":
		return "email-addr"
	case "filehash-md5", "md5":
		return "file"
	case "filehash-sha1", "sha1":
		return "file"
	case "filehash-sha256", "sha256":
		return "file"
	case "cve":
		return "vulnerability"
	}
	return ""
}

// inferType guesses a STIX type from the raw indicator value.
func inferType(v string) string {
	if strings.Contains(v, "://") {
		return "url"
	}
	if strings.Contains(v, "@") && strings.Contains(v, ".") {
		return "email-addr"
	}
	if looksLikeIPv4(v) {
		return "ipv4-addr"
	}
	if strings.Contains(v, ".") {
		return "domain-name"
	}
	return "x-unknown"
}

func looksLikeIPv4(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func escapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, `'`, `\'`)
}
