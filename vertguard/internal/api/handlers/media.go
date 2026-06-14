package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/media"
	"github.com/opensecstack/vertguard/internal/ml"
)

// MediaVerifier is the narrow interface MediaHandler depends on.
// media.Verifier satisfies it; tests can inject a fake.
type MediaVerifier interface {
	Verify(ctx context.Context, r io.Reader, hint string) (*media.Result, error)
}

// MediaStore is the narrow persistence interface for media scans.
type MediaStore interface {
	SaveMediaScan(ctx context.Context, s *db.MediaScan) error
	GetMediaScan(ctx context.Context, scanID string) (*db.MediaScan, error)
}

// MediaMLEnricher is the optional ML scoring hook for Phase 4.2 deepfake detection.
// *ml.Client satisfies this interface. Nil = C2PA-only mode.
type MediaMLEnricher interface {
	ScoreMedia(ctx context.Context, fileHash, mimeType string, fileSize int64, hasC2PA, c2paValid bool, correlationID, tenant string) (*ml.Result, error)
}

// MediaHandler serves POST /api/v1/media/verify and
// GET /api/v1/media/scans/{scan_id}.
type MediaHandler struct {
	Verifier MediaVerifier
	Store    MediaStore
	Logger   zerolog.Logger
	// MaxBodySize caps the upload at 100 MiB by default.
	MaxBodySize int64
	// ML is the optional Phase 4.2 deepfake ML enricher. Nil = C2PA-only.
	ML MediaMLEnricher
	// Citadel is the optional WORM evidence emitter. Nil disables emission.
	Citadel *citadel.Client
	// Tenant tags emitted Citadel events.
	Tenant string
	// RequireTrust flips untrusted/revoked verdicts from a 200 (with
	// status field) to a 422 (operator opt-in for strict mode).
	RequireTrust bool
}

// NewMediaHandler returns a MediaHandler. Both Verifier and Store may be
// nil — when nil the handler degrades gracefully (503 / 404).
func NewMediaHandler(v MediaVerifier, store MediaStore, logger zerolog.Logger) *MediaHandler {
	return &MediaHandler{
		Verifier:    v,
		Store:       store,
		Logger:      logger.With().Str("handler", "media").Logger(),
		MaxBodySize: 100 * 1024 * 1024,
	}
}

// WithML wires the Phase 4.2 ML enricher. Returns h for chaining.
func (h *MediaHandler) WithML(ml MediaMLEnricher) *MediaHandler {
	h.ML = ml
	return h
}

// WithCitadel wires the WORM evidence emitter. Returns h for chaining.
func (h *MediaHandler) WithCitadel(c *citadel.Client, tenant string) *MediaHandler {
	h.Citadel = c
	h.Tenant = tenant
	return h
}

// allowedMediaPrefixes is the deny-by-default content-type allowlist
// for /api/v1/media/verify. C2PA covers images, video, audio, and
// PDFs; anything else is rejected with 415 before we spend a temp
// file or a subprocess on it.
var allowedMediaPrefixes = []string{
	"image/",
	"video/",
	"audio/",
	"application/pdf",
}

func isAllowedMediaType(ct string) bool {
	for _, p := range allowedMediaPrefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// mediaVerifyResponse is the JSON envelope returned by Verify.
type mediaVerifyResponse struct {
	ScanID         string          `json:"scan_id"`
	HasManifest    bool            `json:"has_manifest"`
	SignatureValid bool            `json:"signature_valid"`
	Signer         *string         `json:"signer,omitempty"`
	ClaimsCount    uint32          `json:"claims_count"`
	Format         string          `json:"format,omitempty"`
	FileSize       int64           `json:"file_size"`
	ContentType    string          `json:"content_type,omitempty"`
	Errors         []string        `json:"errors"`
	Warnings       []string        `json:"warnings"`
	ManifestSummary media.ManifestSummary `json:"manifest_summary"`
	DurationMS     float64         `json:"duration_ms"`
	TrustStatus    string          `json:"trust_status"`
	RevocationReason *string       `json:"revocation_reason,omitempty"`
	// ML enrichment fields — populated when ML service is available (Phase 4.2).
	MLConfidence   float64  `json:"ml_confidence,omitempty"`
	MLVerdict      string   `json:"ml_verdict,omitempty"`
	MLModelVersion string   `json:"ml_backend_version,omitempty"`
	MLLatencyMS    float64  `json:"ml_latency_ms,omitempty"`
}

// countingReader wraps an io.Reader and tracks bytes successfully read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Verify handles POST /api/v1/media/verify.
//
// The request body is treated as the raw media file. Callers may set
// X-Filename with the original filename to improve format detection.
// The first 512 bytes are sniffed via http.DetectContentType and
// rejected with 415 if outside allowedMediaPrefixes.
func (h *MediaHandler) Verify(w http.ResponseWriter, r *http.Request) {
	if h.Verifier == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "media_unavailable",
			"C2PA verifier not configured — set VERTGUARD_MEDIA_BINARY_PATH")
		return
	}

	hint := r.Header.Get("X-Filename")
	start := time.Now()

	// Cap the upload stream.
	limited := io.LimitReader(r.Body, h.MaxBodySize+1)

	// Peek the first 512 bytes for magic-byte sniffing. We re-prepend
	// the peeked buffer so the verifier sees the full stream.
	peek := make([]byte, 512)
	pn, perr := io.ReadFull(limited, peek)
	if perr != nil && perr != io.EOF && perr != io.ErrUnexpectedEOF {
		writeJSONError(w, http.StatusBadRequest, "read_failed", "could not read request body")
		return
	}
	peek = peek[:pn]
	sniffedCT := http.DetectContentType(peek)
	if !isAllowedMediaType(sniffedCT) {
		writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			fmt.Sprintf("content type %q is not a supported media format (allowed: image/*, video/*, audio/*, application/pdf)", sniffedCT))
		return
	}

	// Stitch the peek buffer back in front of the remaining stream and
	// wrap with a counting reader so we record the actual bytes
	// consumed by the verifier (file_size column).
	full := io.MultiReader(bytes.NewReader(peek), limited)
	counter := &countingReader{r: full}

	// Tee into SHA-256 hasher so we hash exactly what the verifier reads.
	hasher := sha256.New()
	tee := io.TeeReader(counter, hasher)

	result, err := h.Verifier.Verify(r.Context(), tee, hint)
	durationMS := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		if err == media.ErrFileTooLarge {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "file_too_large",
				fmt.Sprintf("file exceeds limit of %d bytes", h.MaxBodySize))
			return
		}
		h.Logger.Error().Err(err).Str("hint", hint).Msg("c2pa verify failed")
		writeJSONError(w, http.StatusBadGateway, "verify_failed", err.Error())
		return
	}

	scanID := uuid.NewString()
	fileHash := fmt.Sprintf("%x", hasher.Sum(nil))
	fileSize := counter.n

	resp := mediaVerifyResponse{
		ScanID:          scanID,
		HasManifest:     result.HasManifest,
		SignatureValid:  result.SignatureValid,
		Signer:          result.Signer,
		ClaimsCount:     result.ClaimsCount,
		Format:          result.Format,
		FileSize:        fileSize,
		ContentType:     sniffedCT,
		Errors:          result.Errors,
		Warnings:        result.Warnings,
		ManifestSummary: result.ManifestSummary,
		DurationMS:      durationMS,
		TrustStatus:     result.TrustStatus,
		RevocationReason: result.RevocationReason,
	}
	if resp.TrustStatus == "" {
		// Defensive default — a verifier built without trust wiring
		// still emits a stable enum value so clients never see "".
		if result.HasManifest {
			resp.TrustStatus = media.TrustStatusUntrusted
		} else {
			resp.TrustStatus = media.TrustStatusUnsigned
		}
	}
	if resp.Errors == nil {
		resp.Errors = []string{}
	}
	if resp.Warnings == nil {
		resp.Warnings = []string{}
	}

	// Phase 4.2 — ML deepfake enrichment (soft-fail).
	if h.ML != nil {
		if mlResult, err := h.ML.ScoreMedia(r.Context(), fileHash, sniffedCT, fileSize, result.HasManifest, result.SignatureValid, scanID, h.Tenant); err == nil {
			resp.MLConfidence = mlResult.Confidence
			resp.MLVerdict = mlResult.Verdict
			resp.MLModelVersion = mlResult.ModelVersion
			resp.MLLatencyMS = mlResult.LatencyMs
		} else {
			h.Logger.Debug().Err(err).Str("scan_id", scanID).Msg("ml enrichment skipped")
		}
	}

	// Persist scan record (best-effort; never block the response).
	if h.Store != nil {
		rec := &db.MediaScan{
			ScanID:         scanID,
			FileHash:       fileHash,
			FileSize:       fileSize,
			ContentHint:    hint,
			HasManifest:    result.HasManifest,
			SignatureValid: result.SignatureValid,
			Signer:         result.Signer,
			ClaimsCount:    int(result.ClaimsCount),
			Format:         result.Format,
			Errors:         resp.Errors,
			Warnings:       resp.Warnings,
			DurationMS:     durationMS,
		}
		if err := h.Store.SaveMediaScan(r.Context(), rec); err != nil {
			h.Logger.Warn().Err(err).Str("scan_id", scanID).Msg("persist media scan failed")
		}
	}

	// CITADEL WORM emit (fire-and-forget; mirrors prompt handler).
	if h.Citadel != nil {
		signer := ""
		if result.Signer != nil {
			signer = *result.Signer
		}
		manifestID := ""
		if result.ManifestSummary.InstanceID != nil {
			manifestID = *result.ManifestSummary.InstanceID
		}
		verdict := "unsigned"
		if result.HasManifest {
			if result.SignatureValid {
				verdict = "signed_valid"
			} else {
				verdict = "signed_invalid"
			}
		}
		patterns := []string{}
		if signer != "" {
			patterns = append(patterns, "signer:"+signer)
		}
		if manifestID != "" {
			patterns = append(patterns, "manifest:"+manifestID)
		}
		patterns = append(patterns, fmt.Sprintf("file_size:%d", fileSize))
		patterns = append(patterns, "content_type:"+sniffedCT)
		patterns = append(patterns, "trust_status:"+resp.TrustStatus)
		h.Citadel.EmitAsync(r.Context(), citadel.Evidence{
			EventType:     "vertguard.detection.media_authenticity",
			Subject:       fileHash,
			Verdict:       verdict,
			Score:         resp.MLConfidence,
			Categories:    []string{"media_authenticity"},
			Patterns:      patterns,
			Tenant:        h.Tenant,
			Timestamp:     time.Now().UTC(),
			CorrelationID: scanID,
		})
	} else {
		h.Logger.Debug().Str("scan_id", scanID).Msg("citadel emit skipped — client not configured")
	}

	status := http.StatusOK
	if h.RequireTrust && (resp.TrustStatus == media.TrustStatusUntrusted || resp.TrustStatus == media.TrustStatusRevoked) {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, resp)
}

// GetScan handles GET /api/v1/media/scans/{scan_id}.
func (h *MediaHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	scanID := chi.URLParam(r, "scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_scan_id", "scan_id is required")
		return
	}

	scan, err := h.Store.GetMediaScan(r.Context(), scanID)
	if err != nil {
		h.Logger.Warn().Err(err).Str("scan_id", scanID).Msg("get media scan")
		writeJSONError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	writeJSON(w, http.StatusOK, scan)
}
