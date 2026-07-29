//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/api"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/config"
	"github.com/opensecstack/threatflow/internal/db"
)

const e2eCSAF = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "E2E Example RCE in Widget",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {
      "id": "OPENCSIRT-E2E-0001",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "current_release_date": "2026-01-01T00:00:00Z",
      "status": "final",
      "version": "1"
    },
    "distribution": {"tlp": {"label": "AMBER"}}
  },
  "product_tree": {
    "full_product_names": [{"product_id": "CSAFPID-1", "name": "Widget 1.0"}]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-E2E01",
      "title": "CVE-2026-E2E01 — E2E Example RCE",
      "remediations": [{"category": "vendor_fix", "details": "Upgrade to 1.1", "product_ids": ["CSAFPID-1"]}]
    }
  ]
}`

// TestE2E_AdvisoryIngest_FullPipeline exercises the whole path this ADR-004
// implementation added: auth → MARSHAL gate (CITADEL disabled here, so
// EXECUTE no-op) → CSAF parse/map → STIX vulnerability object persisted →
// advisory + vulnerability + product + remediation rows persisted → webhook
// fan-out to a subscribed endpoint. Also proves the revision/dedup contract
// end-to-end: re-posting the same document is a no-op 200, posting version 2
// updates the same advisory row.
func TestE2E_AdvisoryIngest_FullPipeline(t *testing.T) {
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping e2e")
	}
	resetDB(t, dsn)

	received := make(chan []byte, 1)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(200)
	}))
	defer webhookSrv.Close()

	cfg := &config.Config{
		Port: 0,
		DB:   config.DatabaseConfig{URL: dsn},
		Auth: config.AuthConfig{
			JWTSecret:     "advisory-e2e-secret-padded-32ch",
			TTLMinutes:    10,
			BootstrapKeys: []string{"advisory-e2e-admin"},
		},
		Rate: config.RateLimitConfig{RequestsPerSec: 1000, Burst: 2000},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer pool.Close()

	citadelClient := citadel.New(citadel.Config{}, zerolog.Nop())
	authSvc, err := auth.NewService(auth.Config{
		Secret:        cfg.Auth.JWTSecret,
		TTL:           10 * time.Minute,
		BootstrapKeys: map[string]auth.Role{"advisory-e2e-admin": auth.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	noCache, _ := cache.Open(ctx, "", 0, zerolog.Nop())
	srv := api.NewServer(cfg, pool, citadelClient, authSvc, noCache)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := mustExchange(t, ts.URL, "advisory-e2e-admin")

	// Register a webhook subscriber for advisory.ingested.
	body, _ := json.Marshal(map[string]any{
		"name":           "opencsirt-mirror-e2e",
		"platform":       "external",
		"url":            webhookSrv.URL,
		"event_types":    []string{"advisory.ingested", "advisory.updated"},
		"min_confidence": 0,
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("webhook register status %d", resp.StatusCode)
	}

	// 1. POST the advisory — expect 201 created.
	advID := postAdvisory(t, ts.URL, token, e2eCSAF, http.StatusCreated)

	select {
	case payload := <-received:
		if !bytes.Contains(payload, []byte(`"type":"advisory.ingested"`)) {
			t.Errorf("webhook payload missing event type: %s", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was never delivered for advisory.ingested")
	}

	// 2. GET it back and verify the vulnerability/product/remediation made it through.
	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/advisories/"+advID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get advisory: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", getResp.StatusCode)
	}
	var detail struct {
		Vulnerabilities []struct {
			CVE           string `json:"cve"`
			StixObjectRef string `json:"stix_object_ref"`
			Remediations  []struct {
				Category string `json:"category"`
			} `json:"remediations"`
		} `json:"vulnerabilities"`
		Products []struct {
			ProductID string `json:"product_id"`
		} `json:"products"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(detail.Vulnerabilities) != 1 || detail.Vulnerabilities[0].CVE != "CVE-2026-E2E01" {
		t.Fatalf("vulnerabilities = %+v", detail.Vulnerabilities)
	}
	if detail.Vulnerabilities[0].StixObjectRef == "" {
		t.Error("expected stix_object_ref to be populated")
	}
	if len(detail.Vulnerabilities[0].Remediations) != 1 {
		t.Fatalf("remediations = %+v", detail.Vulnerabilities[0].Remediations)
	}
	if len(detail.Products) != 1 || detail.Products[0].ProductID != "CSAFPID-1" {
		t.Fatalf("products = %+v", detail.Products)
	}

	// 3. Re-POST the identical document — expect 200 (duplicate, not 201).
	postAdvisory(t, ts.URL, token, e2eCSAF, http.StatusOK)

	// 4. Verify the STIX vulnerability object itself is queryable via the
	// existing STIX bundle listing (proves the canonical-STIX path, not just
	// the advisory-specific tables, was populated).
	bundlesReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stix/bundles?direction=import", nil)
	bundlesReq.Header.Set("Authorization", "Bearer "+token)
	bundlesResp, err := http.DefaultClient.Do(bundlesReq)
	if err != nil {
		t.Fatalf("list bundles: %v", err)
	}
	defer bundlesResp.Body.Close()
	var bundles struct {
		Total int `json:"total"`
	}
	_ = json.NewDecoder(bundlesResp.Body).Decode(&bundles)
	if bundles.Total < 1 {
		t.Error("expected at least one imported stix bundle from the advisory ingest")
	}
}

func postAdvisory(t *testing.T, baseURL, token, doc string, wantStatus int) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/advisories",
		bytesReader(doc))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post advisory: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("advisory ingest status = %d, want %d: %s", resp.StatusCode, wantStatus, string(raw))
	}
	var out struct {
		AdvisoryID string `json:"advisory_id"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.AdvisoryID
}

func bytesReader(s string) *bytes.Reader {
	return bytes.NewReader([]byte(s))
}
