// Package feed implements external threat-intel feed ingestion. Each supported
// source (TAXII 2.1, CSV, MISP) has a Poller that fetches the latest indicators
// and emits a STIX 2.1 bundle. The scheduler ticks through enabled feeds in
// the database and hands each bundle to internal/stix.Importer.
package feed

import (
	"context"
	"net/http"
	"time"
)

// Poller fetches the latest indicators from a feed and returns a STIX 2.1
// bundle payload ready for stix.Importer. Callers must set a context deadline —
// pollers do not enforce their own timeout.
type Poller interface {
	// Poll returns a STIX bundle JSON payload and the number of indicators it
	// contains. A successful poll with zero indicators returns (nil, 0, nil).
	Poll(ctx context.Context) (payload []byte, count int, err error)

	// Kind returns the feed_type string stored in the feeds table
	// (e.g. "taxii21", "csv", "misp").
	Kind() string
}

// Config is the subset of fields from the feeds table that every poller needs.
type Config struct {
	Name           string
	URL            string
	ConfidenceBase int
	Headers        map[string]string
	APIKey         string
}

// defaultHTTPClient is used by every poller. 60-second per-request timeout
// catches hung TAXII/MISP servers without blocking the scheduler.
var defaultHTTPClient = &http.Client{Timeout: 60 * time.Second}

// HTTPClient lets tests swap the shared client. Call with nil to restore the
// default.
func HTTPClient() *http.Client { return defaultHTTPClient }

// SetHTTPClient overrides the shared HTTP client for all pollers — meant for
// tests only.
func SetHTTPClient(c *http.Client) {
	if c == nil {
		defaultHTTPClient = &http.Client{Timeout: 60 * time.Second}
		return
	}
	defaultHTTPClient = c
}
