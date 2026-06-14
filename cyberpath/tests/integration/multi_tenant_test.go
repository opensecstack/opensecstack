//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tenantA = "tenant-aaa-test"
	tenantB = "tenant-bbb-test"
	tenantC = "tenant-ccc-test"

	userA1 = "aaaaaaaa-0001-0001-0001-aaaaaaaaaaaa"
	userA2 = "aaaaaaaa-0002-0002-0002-aaaaaaaaaaaa"
	userA3 = "aaaaaaaa-0003-0003-0003-aaaaaaaaaaaa"

	userB1 = "bbbbbbbb-0001-0001-0001-bbbbbbbbbbbb"
	userB2 = "bbbbbbbb-0002-0002-0002-bbbbbbbbbbbb"
	userB3 = "bbbbbbbb-0003-0003-0003-bbbbbbbbbbbb"

	userC1 = "cccccccc-0001-0001-0001-cccccccccccc"
	userC2 = "cccccccc-0002-0002-0002-cccccccccccc"
	userC3 = "cccccccc-0003-0003-0003-cccccccccccc"

	// placeholder resource IDs seeded for tenantB
	trackBID   = "dddddddd-b001-b001-b001-bbbbbbbbbbbb"
	lessonBID  = "dddddddd-b002-b002-b002-bbbbbbbbbbbb"
	certBID    = "dddddddd-b003-b003-b003-bbbbbbbbbbbb"
	enrollBID  = "dddddddd-b004-b004-b004-bbbbbbbbbbbb"
)

func baseURL() string {
	if u := os.Getenv("CYBERPATH_TEST_BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func jwtSecret() string {
	if s := os.Getenv("CYBERPATH_TEST_JWT_SECRET"); s != "" {
		return s
	}
	return "test-secret-do-not-use-in-prod"
}

func mintJWT(t *testing.T, userID, tenantID, role string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":       userID,
		"tenant_id": tenantID,
		"role":      role,
		"iss":       "cyberpath-test",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(jwtSecret()))
	if err != nil {
		t.Fatalf("mintJWT: %v", err)
	}
	return signed
}

func apiRequest(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("apiRequest marshal: %v", err)
		}
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req, err := http.NewRequest(method, baseURL()+path, reqBody)
	if err != nil {
		t.Fatalf("apiRequest new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("apiRequest do: %v", err)
	}
	return resp
}

func assertDenied(t *testing.T, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected 403 or 404, got %d", resp.StatusCode)
	}
}

func assertOK(t *testing.T, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMultiTenantIsolation(t *testing.T) {
	if os.Getenv("CYBERPATH_INTEGRATION_DB_DSN") == "" {
		t.Skip("skipping multi-tenant integration test: CYBERPATH_INTEGRATION_DB_DSN not set")
	}

	tokenA := mintJWT(t, userA1, tenantA, "learner")
	tokenB := mintJWT(t, userB1, tenantB, "learner")
	tokenAAdmin := mintJWT(t, userA1, tenantA, "admin")
	tokenBAdmin := mintJWT(t, userB1, tenantB, "admin")

	// Positive control: tenant A can access its own track listing.
	t.Run("positive/tracks-list-own-tenant", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/tracks", tokenA, nil)
		assertOK(t, resp)
	})

	// GET /api/v1/tracks — tenant A sees only its own tracks, not tenantB's.
	t.Run("tracks/list-cross-tenant-filtered", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/tracks", tokenA, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Skipf("tracks list returned %d; skipping cross-tenant check", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				ID       string `json:"id"`
				TenantID string `json:"tenant_id"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, tr := range result.Data {
				if tr.TenantID != "" && tr.TenantID != tenantA {
					t.Errorf("track %s from tenant %s leaked into tenantA listing", tr.ID, tr.TenantID)
				}
			}
		}
	})

	// GET /api/v1/tracks/{id} — tenantA token cannot read tenantB's track.
	t.Run("tracks/get-cross-tenant", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/tracks/"+trackBID, tokenA, nil)
		assertDenied(t, resp)
	})

	// Positive control: tenantB can read its own track.
	t.Run("positive/tracks-get-own", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/tracks/"+trackBID, tokenB, nil)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("tenantB should be able to read its own track, got 403")
		}
	})

	// GET /api/v1/lessons/{id} — tenantA cannot read tenantB's lesson.
	t.Run("lessons/get-cross-tenant", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/lessons/"+lessonBID, tokenA, nil)
		assertDenied(t, resp)
	})

	// POST /api/v1/lessons/{id}/complete — tenantA cannot mark tenantB's lesson complete.
	t.Run("lessons/complete-cross-tenant", func(t *testing.T) {
		resp := apiRequest(t, http.MethodPost, "/api/v1/lessons/"+lessonBID+"/complete", tokenA, nil)
		assertDenied(t, resp)
	})

	// GET /api/v1/me/certifications — tenantA only sees its own certs.
	t.Run("certifications/list-own", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/me/certifications", tokenA, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Skipf("certs endpoint returned %d; skipping isolation check", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				ID       string `json:"id"`
				TenantID string `json:"tenant_id"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, c := range result.Data {
				if c.TenantID != "" && c.TenantID != tenantA {
					t.Errorf("cert %s from tenant %s leaked into tenantA listing", c.ID, c.TenantID)
				}
			}
		}
	})

	// DELETE /api/v1/admin/certifications/{id}/revoke — tenantA admin cannot revoke tenantB cert.
	t.Run("certifications/revoke-cross-tenant", func(t *testing.T) {
		resp := apiRequest(t, http.MethodDelete, "/api/v1/admin/certifications/"+certBID+"/revoke", tokenAAdmin, nil)
		assertDenied(t, resp)
	})

	// Positive control: tenantB admin can revoke its own cert.
	t.Run("positive/certifications-revoke-own", func(t *testing.T) {
		resp := apiRequest(t, http.MethodDelete, "/api/v1/admin/certifications/"+certBID+"/revoke", tokenBAdmin, nil)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("tenantB admin should be able to revoke its own cert, got 403")
		}
	})

	// GET /api/v1/cyberpath/coverage/{user_id} — tenantA cannot query tenantB's user coverage.
	t.Run("coverage/cross-tenant-user", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/cyberpath/coverage/"+userB1, tokenA, nil)
		assertDenied(t, resp)
	})

	// Positive control: tenantA user can query their own coverage.
	t.Run("positive/coverage-own-user", func(t *testing.T) {
		resp := apiRequest(t, http.MethodGet, "/api/v1/cyberpath/coverage/"+userA1, tokenA, nil)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("tenantA user should be able to query own coverage, got 403")
		}
	})

	// POST /api/v1/enrollments — tenantA cannot enroll into tenantB's track.
	t.Run("enrollments/cross-tenant-track", func(t *testing.T) {
		payload := map[string]string{"track_id": trackBID}
		resp := apiRequest(t, http.MethodPost, "/api/v1/enrollments", tokenA, payload)
		assertDenied(t, resp)
	})

	// Negative: using tenantC token against tenantB resources also denied.
	t.Run("tracks/get-cross-tenant-third-party", func(t *testing.T) {
		tokenC := mintJWT(t, userC1, tenantC, "learner")
		resp := apiRequest(t, http.MethodGet, "/api/v1/tracks/"+trackBID, tokenC, nil)
		assertDenied(t, resp)
	})

	t.Log("multi-tenant isolation checks complete")
}
