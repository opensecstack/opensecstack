package handlers_test

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

// newUploadRequest builds a multipart/form-data POST request with a single
// "file" field containing content, using declaredContentType as the part's
// own Content-Type header (this is the field an attacker fully controls).
func newUploadRequest(t *testing.T, filename, declaredContentType string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Build the form-data part manually so we can set an arbitrary
	// (attacker-controlled) Content-Type on it — mirrors what a hostile
	// client can send.
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="`+filename+`"`)
	if declaredContentType != "" {
		header.Set("Content-Type", declaredContentType)
	}
	part, err := w.CreatePart(header)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func validPNGBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestUploadImage_MissingFileField_Returns400(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("notfile", "x")
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing file field, got %d", rec.Code)
	}
}

func TestUploadImage_InvalidMultipartForm_Returns400(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", bytes.NewReader([]byte("not multipart")))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid multipart body, got %d", rec.Code)
	}
}

// TestUploadImage_ValidPNG_SavedWithSafeUUIDFilename proves the success path:
// a real PNG is accepted, processed, and saved under a server-generated UUID
// filename inside the configured upload dir — never anything derived from
// the client-supplied filename.
func TestUploadImage_ValidPNG_SavedWithSafeUUIDFilename(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	req := newUploadRequest(t, "photo.png", "image/png", validPNGBytes(t))
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	url := resp["url"]
	if !strings.HasPrefix(url, "/uploads/") {
		t.Fatalf("expected url under /uploads/, got %q", url)
	}
	// Successfully decoded images are always re-encoded as JPEG.
	if !strings.HasSuffix(url, ".jpg") {
		t.Errorf("expected re-encoded image to be saved as .jpg, got %q", url)
	}
	if strings.Contains(url, "photo") {
		t.Errorf("expected the saved filename to NOT be derived from the client-supplied filename %q, got %q", "photo.png", url)
	}

	saved := filepath.Join(dir, strings.TrimPrefix(url, "/uploads/"))
	if _, err := os.Stat(saved); err != nil {
		t.Errorf("expected file to exist at %s: %v", saved, err)
	}
}

// TestUploadImage_ContentTypeSpoofing_RawHTMLLabeledAsPNG_Rejected is the
// key security-regression test for the fix in upload.go: a client that sets
// Content-Type: image/png on bytes that are not actually a PNG (e.g. an HTML
// document containing a <script> tag) must be rejected, not saved to disk
// under a spoofed .png extension. Before the fix, the handler trusted the
// client-declared Content-Type header over the sniffed bytes.
func TestUploadImage_ContentTypeSpoofing_RawHTMLLabeledAsPNG_Rejected(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	malicious := []byte(`<html><body><script>alert(document.cookie)</script></body></html>`)
	req := newUploadRequest(t, "totally-a-photo.png", "image/png", malicious)
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 rejecting HTML content spoofed as image/png, got %d — body: %s", rec.Code, rec.Body.String())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected nothing written to disk for a rejected upload, found %v", entries)
	}
}

// TestUploadImage_ContentTypeSpoofing_SVGLabeledAsPNG_Rejected covers the
// classic stored-XSS vector: SVG can carry <script>, and its true MIME type
// (image/svg+xml) is not in the allow-list, so the sniffed type — not the
// declared one — must decide the outcome.
func TestUploadImage_ContentTypeSpoofing_SVGLabeledAsPNG_Rejected(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	req := newUploadRequest(t, "avatar.png", "image/png", svg)
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 rejecting SVG content spoofed as image/png, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

// TestUploadImage_DeclaredTypeIgnoredWhenBytesAreValidPNG proves the
// converse of the spoofing tests: a real PNG is accepted regardless of what
// (or whether) a Content-Type is declared on the multipart part, because
// acceptance is driven purely by sniffing the actual bytes.
func TestUploadImage_DeclaredTypeIgnoredWhenBytesAreValidPNG(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	// Declare a bogus/unrelated content-type; the real PNG bytes must still
	// be sniffed correctly and accepted.
	req := newUploadRequest(t, "photo.bin", "application/octet-stream", validPNGBytes(t))
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a real PNG regardless of declared content-type, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadImage_UnsupportedType_Returns422(t *testing.T) {
	dir := t.TempDir()
	d := handlers.Deps{Cfg: &config.Config{UploadDir: dir}}

	req := newUploadRequest(t, "doc.txt", "text/plain", []byte("just some plain text content"))
	rec := httptest.NewRecorder()

	handlers.UploadImage(d)(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for unsupported type, got %d", rec.Code)
	}
}
