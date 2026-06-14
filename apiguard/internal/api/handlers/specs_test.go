package handlers

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestSpecsUpload_RawYAML(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	yamlContent := "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0.0\npaths: {}\n"
	req := httptest.NewRequest(http.MethodPost, "/specs/upload", strings.NewReader(yamlContent))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.Upload(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", resp.StatusCode, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for _, key := range []string{"spec_path", "spec_hash", "size"} {
		if _, ok := result[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

func TestSpecsUpload_RawJSON_ExtensionIsJSON(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	jsonContent := `{"openapi":"3.0.0","info":{"title":"Test","version":"1.0.0"},"paths":{}}`
	req := httptest.NewRequest(http.MethodPost, "/specs/upload", strings.NewReader(jsonContent))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Upload(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", resp.StatusCode, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	specPath, ok := result["spec_path"].(string)
	if !ok || specPath == "" {
		t.Fatal("spec_path missing or empty")
	}

	if !strings.HasSuffix(specPath, ".json") {
		t.Fatalf("expected .json extension, got path: %s", specPath)
	}
}

func TestSpecsUpload_MultipartForm(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("spec", "openapi.yaml")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	yamlContent := "openapi: 3.0.0\ninfo:\n  title: Multipart Test\n  version: 1.0.0\npaths: {}\n"
	fw.Write([]byte(yamlContent))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/specs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.Upload(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", resp.StatusCode, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := result["spec_path"]; !ok {
		t.Error("response missing 'spec_path' key")
	}
}

func TestSpecsUpload_EmptyBody_Returns422(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/specs/upload", strings.NewReader(""))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.Upload(w, req)

	if w.Result().StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Result().StatusCode)
	}
}

func TestSpecsUpload_Deduplication(t *testing.T) {
	logger := zerolog.Nop()
	dir := t.TempDir()
	h := NewSpecs(logger, dir)

	yamlContent := "openapi: 3.0.0\ninfo:\n  title: Dedup Test\n  version: 1.0.0\npaths: {}\n"

	doUpload := func() map[string]interface{} {
		req := httptest.NewRequest(http.MethodPost, "/specs/upload", strings.NewReader(yamlContent))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()
		h.Upload(w, req)
		if w.Result().StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Result().StatusCode)
		}
		var result map[string]interface{}
		if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return result
	}

	first := doUpload()
	second := doUpload()

	path1, _ := first["spec_path"].(string)
	path2, _ := second["spec_path"].(string)

	if path1 == "" || path2 == "" {
		t.Fatal("spec_path should not be empty")
	}
	if path1 != path2 {
		t.Fatalf("expected same spec_path for duplicate upload, got %q and %q", path1, path2)
	}
}

func TestSpecsUpload_FileExistsOnDisk(t *testing.T) {
	logger := zerolog.Nop()
	dir := t.TempDir()
	h := NewSpecs(logger, dir)

	yamlContent := "openapi: 3.0.0\ninfo:\n  title: Disk Test\n  version: 1.0.0\npaths: {}\n"
	req := httptest.NewRequest(http.MethodPost, "/specs/upload", strings.NewReader(yamlContent))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.Upload(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Result().StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	specPath, ok := result["spec_path"].(string)
	if !ok || specPath == "" {
		t.Fatal("spec_path missing or empty")
	}

	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Fatalf("uploaded file does not exist on disk at %s", specPath)
	}
}
