package handlers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

const (
	maxSpecUploadBytes = 20 * 1024 * 1024 // 20 MiB
)

// Specs handles OpenAPI spec upload so clients can provide spec files to the
// server without needing a publicly reachable URL.
type Specs struct {
	logger  zerolog.Logger
	uploadDir string
}

// NewSpecs creates a new Specs handler.
// uploadDir is the directory where uploaded spec files are written.
// When empty, os.TempDir() is used.
func NewSpecs(logger zerolog.Logger, uploadDir string) *Specs {
	if uploadDir == "" {
		uploadDir = os.TempDir()
	}
	return &Specs{
		logger:    logger.With().Str("handler", "specs").Logger(),
		uploadDir: uploadDir,
	}
}

type uploadResponse struct {
	SpecPath string `json:"spec_path"` // absolute server-side path; pass as spec_path in POST /scans
	SpecHash string `json:"spec_hash"` // SHA-256 hex of uploaded content
	Size     int64  `json:"size"`
}

// Upload handles POST /api/v1/specs/upload.
//
// Accepts either:
//   - multipart/form-data with a "spec" file field, or
//   - application/octet-stream / text/plain body (raw spec content)
//
// Returns {"spec_path": "/tmp/apiguard-spec-<hash>.yaml", "spec_hash": "<sha256>", "size": N}
// The returned spec_path can be passed directly as spec_path in POST /api/v1/scans.
func (s *Specs) Upload(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")

	var content []byte

	if strings.HasPrefix(ct, "multipart/form-data") {
		// Parse multipart upload; limit parse to maxSpecUploadBytes.
		if err := r.ParseMultipartForm(maxSpecUploadBytes); err != nil {
			writeError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error())
			return
		}
		file, _, err := r.FormFile("spec")
		if err != nil {
			writeError(w, http.StatusBadRequest, "missing 'spec' field in multipart form")
			return
		}
		defer file.Close()

		content, err = io.ReadAll(io.LimitReader(file, maxSpecUploadBytes))
		if err != nil {
			s.logger.Error().Err(err).Msg("reading uploaded spec")
			writeError(w, http.StatusInternalServerError, "failed to read uploaded file")
			return
		}
	} else {
		// Treat the body as raw spec content.
		var err error
		content, err = io.ReadAll(io.LimitReader(r.Body, maxSpecUploadBytes))
		if err != nil {
			s.logger.Error().Err(err).Msg("reading spec body")
			writeError(w, http.StatusInternalServerError, "failed to read request body")
			return
		}
	}

	if len(content) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "spec content is empty")
		return
	}

	// Detect file extension from content (check first non-whitespace byte).
	ext := ".yaml"
	if trimmed := strings.TrimSpace(string(content)); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		ext = ".json"
	}

	// Compute SHA-256 for deduplication and filename.
	sum := sha256.Sum256(content)
	hashHex := fmt.Sprintf("%x", sum)

	filename := fmt.Sprintf("apiguard-spec-%s%s", hashHex[:16], ext)
	destPath := filepath.Join(s.uploadDir, filename)

	// Write only if not already present (content-addressed dedup).
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		if err := os.WriteFile(destPath, content, 0600); err != nil {
			s.logger.Error().Err(err).Str("path", destPath).Msg("writing spec file")
			writeError(w, http.StatusInternalServerError, "failed to store spec")
			return
		}
	}

	s.logger.Info().
		Str("path", destPath).
		Str("hash", hashHex[:16]).
		Int("size", len(content)).
		Msg("spec uploaded")

	writeJSON(w, http.StatusCreated, uploadResponse{
		SpecPath: destPath,
		SpecHash: hashHex,
		Size:     int64(len(content)),
	})
}
