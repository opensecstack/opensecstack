//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// clientsTestDeps wires the minimal real (DB-backed) ClientSvc that
// ListClients/CreateClient/DeleteClient touch. Authorization for these
// handlers (platform-admin only) is enforced entirely at the router level by
// middleware.RequireAdmin (see internal/api/server.go and
// internal/api/server_admin_test.go's TestRemainingAdminRoutes_RequireAdmin)
// — the handlers themselves are intentionally authz-agnostic, so these tests
// exercise validation/business logic, not authorization.
func clientsTestDeps(t *testing.T) Deps {
	t.Helper()
	pool := requireDB(t)
	return testDeps(t, pool)
}

func doClientsRequest(t *testing.T, h http.HandlerFunc, method, path, body string, pathValues map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestCreateClient_MissingClientID_Rejected(t *testing.T) {
	d := clientsTestDeps(t)
	body := `{"redirect_uris":["https://client.test/callback"]}`
	rec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateClient_MissingRedirectURIs_Rejected(t *testing.T) {
	d := clientsTestDeps(t)
	body := fmt.Sprintf(`{"client_id":"c-%d","redirect_uris":[]}`, time.Now().UnixNano())
	rec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateClient_MalformedJSON_Rejected(t *testing.T) {
	d := clientsTestDeps(t)
	rec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", `{not-json`, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// A confidential client's client_secret must never be stored or returned in
// plaintext — it must be bcrypt-hashed at rest.
func TestCreateClient_ConfidentialClient_SecretIsHashedNotPlaintext(t *testing.T) {
	d := clientsTestDeps(t)
	clientID := fmt.Sprintf("confidential-%d", time.Now().UnixNano())
	plainSecret := "super-secret-value-123"
	body := fmt.Sprintf(`{"client_id":%q,"name":"Confidential Client","redirect_uris":["https://client.test/callback"],
		"allowed_scopes":["openid","profile"],"grant_types":["authorization_code"],"is_confidential":true,"client_secret":%q}`, clientID, plainSecret)
	rec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })

	if strings.Contains(rec.Body.String(), plainSecret) {
		t.Fatalf("response body must not echo the plaintext client_secret: %s", rec.Body.String())
	}

	c, err := d.ClientSvc.GetByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if c.ClientSecret == "" || c.ClientSecret == plainSecret {
		t.Fatalf("stored ClientSecret must be a bcrypt hash, not empty or plaintext: %q", c.ClientSecret)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.ClientSecret), []byte(plainSecret)); err != nil {
		t.Fatalf("stored hash does not verify against the original secret: %v", err)
	}
}

func TestCreateClient_PublicClient_NoSecretStored(t *testing.T) {
	d := clientsTestDeps(t)
	clientID := fmt.Sprintf("public-%d", time.Now().UnixNano())
	// is_confidential omitted (false) — a public client (e.g. SPA/mobile) has no secret.
	body := fmt.Sprintf(`{"client_id":%q,"name":"Public Client","redirect_uris":["https://client.test/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code"]}`, clientID)
	rec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })

	c, err := d.ClientSvc.GetByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if c.ClientSecret != "" {
		t.Fatalf("public client must not have a stored secret, got %q", c.ClientSecret)
	}
}

func TestCreateClient_DuplicateClientID_Rejected(t *testing.T) {
	d := clientsTestDeps(t)
	clientID := fmt.Sprintf("dup-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://client.test/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code"]}`, clientID)

	rec1 := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d, want %d; body=%s", rec1.Code, http.StatusCreated, rec1.Body.String())
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })

	rec2 := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)
	if rec2.Code == http.StatusCreated {
		t.Fatalf("second create with the same client_id must not succeed; status=%d body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestListClients_ReturnsCreatedClient(t *testing.T) {
	d := clientsTestDeps(t)
	clientID := fmt.Sprintf("list-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"client_id":%q,"name":"Listable","redirect_uris":["https://client.test/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code"]}`, clientID)
	createRec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })

	listRec := doClientsRequest(t, ListClients(d), http.MethodGet, "/api/v1/admin/clients", "", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d; body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(listRec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, c := range out {
		if c["client_id"] == clientID {
			found = true
			if _, present := c["client_secret"]; present {
				t.Fatalf("ListClients response must not expose a client_secret field: %v", c)
			}
		}
	}
	if !found {
		t.Fatalf("created client %q not present in ListClients output: %v", clientID, out)
	}
}

func TestDeleteClient_RemovesClient(t *testing.T) {
	d := clientsTestDeps(t)
	clientID := fmt.Sprintf("del-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://client.test/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code"]}`, clientID)
	createRec := doClientsRequest(t, CreateClient(d), http.MethodPost, "/api/v1/admin/clients", body, nil)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	delRec := doClientsRequest(t, DeleteClient(d), http.MethodDelete, "/api/v1/admin/clients/"+clientID, "", map[string]string{"id": clientID})
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d; body=%s", delRec.Code, http.StatusOK, delRec.Body.String())
	}

	if _, err := d.ClientSvc.GetByClientID(context.Background(), clientID); err == nil {
		t.Fatalf("client %q should no longer exist after delete", clientID)
	}
}
