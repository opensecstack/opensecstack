package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TAXII is a minimal TAXII 2.1 client. It polls a single collection's objects
// endpoint and returns the response as a STIX bundle. The server is expected
// to emit `application/taxii+json;version=2.1` with a top-level `objects`
// array; most commercial and public TAXII servers comply.
type TAXII struct {
	cfg Config
}

// NewTAXII constructs a TAXII poller. The URL must be the full collection
// objects endpoint, e.g.
// https://cti.example/taxii2/collections/<id>/objects/
func NewTAXII(cfg Config) *TAXII {
	return &TAXII{cfg: cfg}
}

// Kind returns the feed_type string.
func (t *TAXII) Kind() string { return "taxii21" }

// taxiiEnvelope is the TAXII 2.1 objects response envelope.
type taxiiEnvelope struct {
	Objects []json.RawMessage `json:"objects"`
	More    bool              `json:"more,omitempty"`
	Next    string            `json:"next,omitempty"`
}

// Poll fetches the collection and wraps the objects array in a STIX bundle.
func (t *TAXII) Poll(ctx context.Context) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.cfg.URL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")
	if t.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.cfg.APIKey)
	}
	for k, v := range t.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("taxii GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, 0, fmt.Errorf("taxii status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}

	var env taxiiEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, 0, fmt.Errorf("decode taxii envelope: %w", err)
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           deterministicBundleID(t.cfg.Name, body),
		"spec_version": "2.1",
		"objects":      env.Objects,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, 0, fmt.Errorf("encode bundle: %w", err)
	}
	return payload, len(env.Objects), nil
}
