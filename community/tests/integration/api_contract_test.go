package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
)

var baseURL = func() string {
	if v := os.Getenv("COMMUNITY_TEST_URL"); v != "" {
		return v
	}
	return "http://localhost:8090"
}()

func login(t *testing.T, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status: %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Token
}

func authed(t *testing.T, token, method, path string, body any) *http.Response {
	t.Helper()
	var b *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		b = bytes.NewReader(data)
	} else {
		b = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, baseURL+path, b)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func TestHealth(t *testing.T) {
	resp, err := http.Get(baseURL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: got %d", resp.StatusCode)
	}
	var out struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
		DB      struct {
			OK        bool  `json:"ok"`
			LatencyMS int64 `json:"latency_ms"`
		} `json:"db"`
		Timestamp string `json:"timestamp"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !out.OK {
		t.Error("ok is false")
	}
	if out.Version == "" {
		t.Error("version is empty")
	}
	if !out.DB.OK {
		t.Error("db.ok is false")
	}
	if out.Timestamp == "" {
		t.Error("timestamp is empty")
	}
}

func TestReadiness(t *testing.T) {
	resp, err := http.Get(baseURL + "/api/v1/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready: got %d", resp.StatusCode)
	}
	var out struct {
		Ready bool `json:"ready"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !out.Ready {
		t.Error("ready is false")
	}
}

func TestAuthLogin(t *testing.T) {
	tok := login(t, "admin", "operator")
	if tok == "" {
		t.Fatal("empty token")
	}
}

func TestAuthLoginBadCreds(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestPostLifecycle(t *testing.T) {
	tok := login(t, "admin", "operator")

	// create draft
	resp := authed(t, tok, http.MethodPost, "/api/v1/posts", map[string]any{
		"title": "Test Post",
		"body":  "Hello opensecstack community.",
		"tags":  []string{"test", "opencsirt"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create post: %d", resp.StatusCode)
	}
	var created struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	if created.ID == "" {
		t.Fatal("no id returned")
	}

	// publish
	resp2 := authed(t, tok, http.MethodPost, fmt.Sprintf("/api/v1/posts/%s/publish", created.ID), nil)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("publish: %d", resp2.StatusCode)
	}

	// get by slug
	resp3, err := http.Get(baseURL + "/api/v1/posts/" + created.Slug)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("get post: %d", resp3.StatusCode)
	}

	// react
	resp4 := authed(t, tok, http.MethodPost, fmt.Sprintf("/api/v1/posts/%s/reactions", created.ID), map[string]string{"kind": "heart"})
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusNoContent {
		t.Errorf("react: %d", resp4.StatusCode)
	}

	// comment
	resp5 := authed(t, tok, http.MethodPost, fmt.Sprintf("/api/v1/posts/%s/comments", created.ID), map[string]string{"body": "Great post!"})
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusCreated {
		t.Errorf("comment: %d", resp5.StatusCode)
	}

	// delete
	resp6 := authed(t, tok, http.MethodDelete, fmt.Sprintf("/api/v1/posts/%s", created.ID), nil)
	defer resp6.Body.Close()
	if resp6.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d", resp6.StatusCode)
	}
}

func TestListFeed(t *testing.T) {
	resp, err := http.Get(baseURL + "/api/v1/feed")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("feed: %d", resp.StatusCode)
	}
	var out struct {
		Posts []any `json:"posts"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Posts == nil {
		t.Error("posts field missing")
	}
}

func TestTagsAndSearch(t *testing.T) {
	resp, err := http.Get(baseURL + "/api/v1/tags")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tags: %d", resp.StatusCode)
	}

	resp2, err := http.Get(baseURL + "/api/v1/search?q=opencsirt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("search: %d", resp2.StatusCode)
	}
}
