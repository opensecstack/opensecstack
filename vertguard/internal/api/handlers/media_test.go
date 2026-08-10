package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/media"
)

// withScanIDParam wraps a request with a chi route context carrying a
// {scan_id} URL param, matching how the router injects it in production.
func withScanIDParam(r *http.Request, scanID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scan_id", scanID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// fakeVerifier is a MediaVerifier test double returning a canned result.
type fakeVerifier struct {
	res *media.Result
	err error
}

func (f *fakeVerifier) Verify(_ context.Context, r io.Reader, _ string) (*media.Result, error) {
	// Drain the reader like a real verifier would, so callers that
	// depend on the counting/hashing wrapper still see accurate values.
	_, _ = io.Copy(io.Discard, r)
	if f.err != nil {
		return nil, f.err
	}
	return f.res, nil
}

// fakeMediaStore is an in-memory MediaStore test double.
type fakeMediaStore struct {
	saved   []*db.MediaScan
	saveErr error
	getRes  *db.MediaScan
	getErr  error
}

func (f *fakeMediaStore) SaveMediaScan(_ context.Context, s *db.MediaScan) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, s)
	return nil
}

func (f *fakeMediaStore) GetMediaScan(_ context.Context, _ string) (*db.MediaScan, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getRes, nil
}

func newMediaReq(t *testing.T, contentBytes []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/media/verify", bytes.NewReader(contentBytes))
	return r
}

// pngBytes returns a minimal valid PNG header so http.DetectContentType
// classifies it as image/png.
func pngBytes() []byte {
	return []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0}
}

func TestMediaVerify_NoVerifier_Returns503(t *testing.T) {
	h := &MediaHandler{MaxBodySize: 1 << 20}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMediaVerify_DisallowedContentType_Returns415(t *testing.T) {
	h := &MediaHandler{
		Verifier:    &fakeVerifier{res: &media.Result{}},
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	// Plain text is not in the image/video/audio/pdf allowlist.
	h.Verify(w, newMediaReq(t, []byte("just some plain text content, not a media file")))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMediaVerify_AllowedType_Returns200(t *testing.T) {
	h := &MediaHandler{
		Verifier: &fakeVerifier{res: &media.Result{
			HasManifest:    true,
			SignatureValid: true,
			TrustStatus:    media.TrustStatusTrusted,
		}},
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp mediaVerifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TrustStatus != media.TrustStatusTrusted {
		t.Errorf("TrustStatus = %q, want trusted", resp.TrustStatus)
	}
	if resp.ContentType != "image/png" {
		t.Errorf("ContentType = %q, want image/png", resp.ContentType)
	}
}

// TestMediaVerify_TrustStatusDefaulted_WhenVerifierOmitsIt covers the
// defensive fallback: a verifier that doesn't populate TrustStatus
// must still yield a stable non-empty enum in the response.
func TestMediaVerify_TrustStatusDefaulted_WhenVerifierOmitsIt(t *testing.T) {
	tests := []struct {
		name        string
		hasManifest bool
		want        string
	}{
		{"no_manifest_defaults_unsigned", false, media.TrustStatusUnsigned},
		{"manifest_no_trust_defaults_untrusted", true, media.TrustStatusUntrusted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &MediaHandler{
				Verifier: &fakeVerifier{res: &media.Result{
					HasManifest: tc.hasManifest,
					// TrustStatus deliberately left empty.
				}},
				MaxBodySize: 1 << 20,
				Logger:      zerolog.Nop(),
			}
			w := httptest.NewRecorder()
			h.Verify(w, newMediaReq(t, pngBytes()))
			var resp mediaVerifyResponse
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.TrustStatus != tc.want {
				t.Errorf("TrustStatus = %q, want %q", resp.TrustStatus, tc.want)
			}
		})
	}
}

// TestMediaVerify_RequireTrust_UntrustedReturns422 exercises the
// operator opt-in strict mode: untrusted/revoked verdicts must flip
// to 422 rather than a silent 200 when RequireTrust is enabled.
func TestMediaVerify_RequireTrust_UntrustedReturns422(t *testing.T) {
	tests := []struct {
		name        string
		trustStatus string
		wantCode    int
	}{
		{"untrusted_rejected", media.TrustStatusUntrusted, http.StatusUnprocessableEntity},
		{"revoked_rejected", media.TrustStatusRevoked, http.StatusUnprocessableEntity},
		{"trusted_allowed", media.TrustStatusTrusted, http.StatusOK},
		{"unsigned_allowed", media.TrustStatusUnsigned, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &MediaHandler{
				Verifier: &fakeVerifier{res: &media.Result{
					HasManifest: true,
					TrustStatus: tc.trustStatus,
				}},
				MaxBodySize:  1 << 20,
				Logger:       zerolog.Nop(),
				RequireTrust: true,
			}
			w := httptest.NewRecorder()
			h.Verify(w, newMediaReq(t, pngBytes()))
			if w.Code != tc.wantCode {
				t.Errorf("trust_status=%s RequireTrust=true: want %d, got %d body=%s", tc.trustStatus, tc.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestMediaVerify_RequireTrustFalse_AlwaysReturns200 confirms the
// default (RequireTrust=false) never downgrades the status code, even
// for untrusted/revoked verdicts — that's the opt-in behaviour only.
func TestMediaVerify_RequireTrustFalse_AlwaysReturns200(t *testing.T) {
	h := &MediaHandler{
		Verifier: &fakeVerifier{res: &media.Result{
			HasManifest: true,
			TrustStatus: media.TrustStatusRevoked,
		}},
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
		// RequireTrust deliberately left false (zero value).
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 when RequireTrust=false even for revoked, got %d", w.Code)
	}
}

func TestMediaVerify_VerifierFileTooLarge_Returns413(t *testing.T) {
	h := &MediaHandler{
		Verifier:    &fakeVerifier{err: media.ErrFileTooLarge},
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMediaVerify_VerifierGenericError_Returns502(t *testing.T) {
	h := &MediaHandler{
		Verifier:    &fakeVerifier{err: io.ErrUnexpectedEOF},
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMediaVerify_PersistsScanRecord(t *testing.T) {
	store := &fakeMediaStore{}
	h := &MediaHandler{
		Verifier: &fakeVerifier{res: &media.Result{
			HasManifest:    true,
			SignatureValid: true,
			TrustStatus:    media.TrustStatusTrusted,
		}},
		Store:       store,
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved records = %d, want 1", len(store.saved))
	}
	if store.saved[0].FileHash == "" {
		t.Error("FileHash was not populated on the persisted record")
	}
}

func TestMediaVerify_StorePersistFails_StillReturns200(t *testing.T) {
	store := &fakeMediaStore{saveErr: context.DeadlineExceeded}
	h := &MediaHandler{
		Verifier:    &fakeVerifier{res: &media.Result{TrustStatus: media.TrustStatusUnsigned}},
		Store:       store,
		MaxBodySize: 1 << 20,
		Logger:      zerolog.Nop(),
	}
	w := httptest.NewRecorder()
	h.Verify(w, newMediaReq(t, pngBytes()))
	if w.Code != http.StatusOK {
		t.Fatalf("persistence failures must be non-fatal: want 200, got %d", w.Code)
	}
}

// ─── GetScan ────────────────────────────────────────────────────────

func TestMediaGetScan_NilStore_Returns404(t *testing.T) {
	h := &MediaHandler{Logger: zerolog.Nop()}
	r := withScanIDParam(httptest.NewRequest(http.MethodGet, "/api/v1/media/scans/abc", nil), "abc")
	w := httptest.NewRecorder()
	h.GetScan(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestMediaGetScan_MissingScanID_Returns400(t *testing.T) {
	store := &fakeMediaStore{}
	h := &MediaHandler{Store: store, Logger: zerolog.Nop()}
	r := withScanIDParam(httptest.NewRequest(http.MethodGet, "/api/v1/media/scans/", nil), "")
	w := httptest.NewRecorder()
	h.GetScan(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMediaGetScan_NotFound_Returns404(t *testing.T) {
	store := &fakeMediaStore{getErr: context.DeadlineExceeded}
	h := &MediaHandler{Store: store, Logger: zerolog.Nop()}
	r := withScanIDParam(httptest.NewRequest(http.MethodGet, "/api/v1/media/scans/xyz", nil), "xyz")
	w := httptest.NewRecorder()
	h.GetScan(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestMediaGetScan_Found_Returns200(t *testing.T) {
	store := &fakeMediaStore{getRes: &db.MediaScan{ScanID: "xyz", FileHash: "deadbeef"}}
	h := &MediaHandler{Store: store, Logger: zerolog.Nop()}
	r := withScanIDParam(httptest.NewRequest(http.MethodGet, "/api/v1/media/scans/xyz", nil), "xyz")
	w := httptest.NewRecorder()
	h.GetScan(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got db.MediaScan
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ScanID != "xyz" {
		t.Errorf("ScanID = %q, want xyz", got.ScanID)
	}
}
