package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MISP polls a MISP instance's `/events/restSearch` (or equivalent) endpoint
// and converts MISP attributes into STIX 2.1 indicators. The URL should return
// MISP JSON either as `{"response": [...]}` (v2 classic) or directly as an
// array of events.
type MISP struct {
	cfg Config
}

// NewMISP constructs a MISP poller. The APIKey is sent in the Authorization
// header as MISP expects.
func NewMISP(cfg Config) *MISP {
	return &MISP{cfg: cfg}
}

// Kind returns the feed_type string.
func (m *MISP) Kind() string { return "misp" }

// mispEnvelope handles both `{"response": [events]}` and `[events]` forms.
type mispEnvelope struct {
	Response []mispEvent `json:"response"`
}

type mispEvent struct {
	Event mispEventBody `json:"Event"`
}

type mispEventBody struct {
	UUID       string          `json:"uuid"`
	Info       string          `json:"info"`
	Threat     string          `json:"threat_level_id"`
	Attributes []mispAttribute `json:"Attribute"`
}

type mispAttribute struct {
	UUID     string `json:"uuid"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Value    string `json:"value"`
	Comment  string `json:"comment"`
	ToIDS    bool   `json:"to_ids"`
}

// Poll fetches the MISP export and converts attributes to STIX indicators.
func (m *MISP) Poll(ctx context.Context) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.URL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if m.cfg.APIKey != "" {
		req.Header.Set("Authorization", m.cfg.APIKey)
	}
	for k, v := range m.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("misp GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("misp status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}

	events, err := decodeMISP(raw)
	if err != nil {
		return nil, 0, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	indicators := make([]json.RawMessage, 0)
	for _, ev := range events {
		tag := strings.ToLower(strings.TrimSpace(ev.Event.Info))
		for _, a := range ev.Event.Attributes {
			if !a.ToIDS {
				continue
			}
			iocType := mapMISPType(a.Type)
			if iocType == "" {
				continue
			}
			pattern := fmt.Sprintf("[%s:value = '%s']", iocType, escapeSingleQuote(a.Value))
			ind := map[string]any{
				"type":         "indicator",
				"spec_version": "2.1",
				"id":           deterministicIndicatorID(pattern),
				"created":      now,
				"modified":     now,
				"pattern":      pattern,
				"pattern_type": "stix",
				"valid_from":   now,
				"confidence":   m.cfg.ConfidenceBase,
				"description":  a.Comment,
			}
			if tag != "" {
				ind["labels"] = []string{tag}
			}
			buf, err := json.Marshal(ind)
			if err != nil {
				return nil, 0, fmt.Errorf("encode indicator: %w", err)
			}
			indicators = append(indicators, buf)
		}
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           deterministicBundleID(m.cfg.Name, raw),
		"spec_version": "2.1",
		"objects":      indicators,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, 0, fmt.Errorf("encode bundle: %w", err)
	}
	return payload, len(indicators), nil
}

// decodeMISP tolerates both `{"response": [...]}` and `[...]` payloads.
func decodeMISP(raw []byte) ([]mispEvent, error) {
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if strings.HasPrefix(trimmed, "[") {
		var events []mispEvent
		if err := json.Unmarshal(raw, &events); err != nil {
			return nil, fmt.Errorf("decode misp array: %w", err)
		}
		return events, nil
	}
	var env mispEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode misp envelope: %w", err)
	}
	return env.Response, nil
}

// mapMISPType maps MISP attribute types to STIX cyber-observable types.
// Unsupported types return "" and are skipped.
func mapMISPType(t string) string {
	switch strings.ToLower(t) {
	case "ip-src", "ip-dst":
		return "ipv4-addr"
	case "ip-src-ipv6", "ip-dst-ipv6":
		return "ipv6-addr"
	case "domain", "hostname":
		return "domain-name"
	case "url", "uri":
		return "url"
	case "email", "email-src", "email-dst":
		return "email-addr"
	case "md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256":
		return "file"
	case "vulnerability", "cve":
		return "vulnerability"
	}
	return ""
}
