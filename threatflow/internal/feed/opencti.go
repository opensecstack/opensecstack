package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OpenCTI polls an OpenCTI instance's GraphQL API for indicators and converts
// them into a STIX 2.1 bundle. Only indicators with pattern_type == "stix" are
// included; others are silently skipped because non-STIX patterns cannot be
// imported by the stix.Importer.
type OpenCTI struct {
	cfg Config
}

// NewOpenCTI constructs an OpenCTI poller.
func NewOpenCTI(cfg Config) *OpenCTI {
	return &OpenCTI{cfg: cfg}
}

func (o *OpenCTI) Kind() string { return "opencti" }

const openctiQuery = `{
  "query": "{ indicators(filters: {key: \"valid_until\", values: [\"now\"], operator: gt}, first: 500) { edges { node { id name pattern pattern_type valid_from confidence description created modified objectLabel { edges { node { value } } } } } } }"
}`

type openctiResponse struct {
	Data struct {
		Indicators struct {
			Edges []struct {
				Node openctiIndicator `json:"node"`
			} `json:"edges"`
		} `json:"indicators"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type openctiIndicator struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	PatternType string  `json:"pattern_type"`
	ValidFrom   string  `json:"valid_from"`
	Confidence  int     `json:"confidence"`
	Description string  `json:"description"`
	Created     string  `json:"created"`
	Modified    string  `json:"modified"`
	ObjectLabel struct {
		Edges []struct {
			Node struct {
				Value string `json:"value"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"objectLabel"`
}

// Poll queries OpenCTI's GraphQL endpoint and returns a STIX 2.1 bundle.
func (o *OpenCTI) Poll(ctx context.Context) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.URL+"/graphql",
		bytes.NewBufferString(openctiQuery))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if o.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)
	}
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("opencti POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("opencti status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}

	var gqlResp openctiResponse
	if err := json.Unmarshal(raw, &gqlResp); err != nil {
		return nil, 0, fmt.Errorf("decode response: %w", err)
	}
	if len(gqlResp.Errors) > 0 {
		return nil, 0, fmt.Errorf("opencti error: %s", gqlResp.Errors[0].Message)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	indicators := make([]json.RawMessage, 0)

	for _, edge := range gqlResp.Data.Indicators.Edges {
		n := edge.Node
		if n.PatternType != "stix" {
			continue
		}

		confidence := n.Confidence
		if confidence == 0 {
			confidence = o.cfg.ConfidenceBase
		}

		created := n.Created
		if created == "" {
			created = now
		}
		modified := n.Modified
		if modified == "" {
			modified = now
		}
		validFrom := n.ValidFrom
		if validFrom == "" {
			validFrom = now
		}

		var labels []string
		for _, le := range n.ObjectLabel.Edges {
			if v := le.Node.Value; v != "" {
				labels = append(labels, v)
			}
		}

		ind := map[string]any{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           deterministicIndicatorID(n.Pattern),
			"name":         n.Name,
			"created":      created,
			"modified":     modified,
			"pattern":      n.Pattern,
			"pattern_type": "stix",
			"valid_from":   validFrom,
			"confidence":   confidence,
			"description":  n.Description,
		}
		if len(labels) > 0 {
			ind["labels"] = labels
		}

		buf, err := json.Marshal(ind)
		if err != nil {
			return nil, 0, fmt.Errorf("encode indicator: %w", err)
		}
		indicators = append(indicators, buf)
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           deterministicBundleID(o.cfg.Name, raw),
		"spec_version": "2.1",
		"objects":      indicators,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, 0, fmt.Errorf("encode bundle: %w", err)
	}
	return payload, len(indicators), nil
}
