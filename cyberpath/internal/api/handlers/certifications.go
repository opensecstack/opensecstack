// Certification issuance, listing, and revocation handlers.
//
// v1.0.0: Ed25519-signed certification issuance backed by CertificationStore.
// v0.8.0: Eligibility check (all lessons completed), TryAutoIssue for
// auto-trigger from LessonsHandler.Complete, CertHandlerDeps struct.
// PDF generation is deferred to a later release; pdf_path stays empty.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/cert"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/db"
)

// ── interfaces ─────────────────────────────────────────────────────────────────

// CertStore is the DB contract CertificationsHandler depends on.
type CertStore interface {
	Issue(ctx context.Context, userID, trackID uuid.UUID, serial string, expiresAt *time.Time) (*db.Certification, error)
	SetSignature(ctx context.Context, certID uuid.UUID, signature, pdfPath string) error
	ListByUser(ctx context.Context, userID uuid.UUID, includeExpired bool) ([]db.Certification, error)
	Revoke(ctx context.Context, certID uuid.UUID) error
	GetByUserTrack(ctx context.Context, userID, trackID uuid.UUID) (*db.Certification, error)
}

// CertTrackReader resolves a track by ID (used for track metadata on issuance).
type CertTrackReader interface {
	Get(ctx context.Context, id uuid.UUID) (*db.Track, error)
}

// CertCompletionChecker verifies that all lessons in a track are complete
// for a given user. Used by Issue() for eligibility gating.
type CertCompletionChecker interface {
	AllLessonsCompletedForTrack(ctx context.Context, userID, trackID uuid.UUID) (bool, error)
}

// ── handler ────────────────────────────────────────────────────────────────────

// CertHandlerDeps bundles all dependencies for CertificationsHandler.
type CertHandlerDeps struct {
	Certs       CertStore
	Tracks      CertTrackReader
	Completions CertCompletionChecker // optional: nil skips eligibility check in Issue()
	Signer      *cert.Signer
	Outbox      citadel.OutboxEnqueuer
	Audit       *db.AuditEventStore
	Logger      *zerolog.Logger
}

// CertificationsHandler serves certification issuance, listing, and revocation.
type CertificationsHandler struct {
	Certs       CertStore
	Tracks      CertTrackReader
	Completions CertCompletionChecker
	Signer      *cert.Signer
	Outbox      citadel.OutboxEnqueuer
	Audit       *db.AuditEventStore
	Logger      *zerolog.Logger
}

// NewCertificationsHandler wires a CertificationsHandler from a deps bundle.
func NewCertificationsHandler(deps CertHandlerDeps) *CertificationsHandler {
	return &CertificationsHandler{
		Certs:       deps.Certs,
		Tracks:      deps.Tracks,
		Completions: deps.Completions,
		Signer:      deps.Signer,
		Outbox:      deps.Outbox,
		Audit:       deps.Audit,
		Logger:      deps.Logger,
	}
}

// Issue handles POST /api/v1/certifications/issue.
//
// Flow:
//  1. Parse track_id from request body.
//  2. Extract userID from JWT context.
//  3. Eligibility check — all lessons in the track must be completed (when
//     Completions dep is wired). Returns 422 if not yet eligible.
//  4. Generate a serial number and insert certification row.
//  5. Build canonical signing payload and sign with Ed25519.
//  6. Persist signature.
//  7. Enqueue CITADEL cyberpath.certification.issued event (best-effort).
//  8. Return 201 with the certification JSON.
func (h *CertificationsHandler) Issue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TrackID string `json:"track_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "request body must be JSON")
		return
	}
	trackID, err := uuid.Parse(body.TrackID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_track_id", "track_id must be a UUID")
		return
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}

	// Eligibility: all lessons must be completed.
	if h.Completions != nil {
		done, err := h.Completions.AllLessonsCompletedForTrack(r.Context(), userID, trackID)
		if err != nil {
			h.log().Error().Err(err).Msg("certifications.issue: eligibility check failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "eligibility check failed")
			return
		}
		if !done {
			writeError(w, http.StatusUnprocessableEntity, "not_eligible",
				"all lessons in the track must be completed before a certificate can be issued")
			return
		}
	}

	serial := fmt.Sprintf("CP-%s-%d", trackID.String()[:8], time.Now().Unix())

	c, err := h.Certs.Issue(r.Context(), userID, trackID, serial, nil)
	if err != nil {
		h.log().Error().Err(err).Msg("certifications.issue: DB insert failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "certification issuance failed")
		return
	}

	// Build the canonical signing payload and sign it.
	payload, err := json.Marshal(map[string]any{
		"cert_id":   c.ID,
		"user_id":   userID,
		"track_id":  trackID,
		"serial":    c.Serial,
		"issued_at": c.IssuedAt,
	})
	if err != nil {
		h.log().Error().Err(err).Msg("certifications.issue: marshal payload failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "signing payload marshal failed")
		return
	}
	hexSig := h.Signer.Sign(payload)

	if err := h.Certs.SetSignature(r.Context(), c.ID, hexSig, ""); err != nil {
		h.log().Error().Err(err).Str("cert_id", c.ID.String()).Msg("certifications.issue: SetSignature failed")
	} else {
		c.Signature = hexSig
	}

	h.enqueueIssuedEvent(r.Context(), c, userID, trackID)
	h.appendAudit(r.Context(), userID, "certification.issue", "certification", c.ID.String())

	writeJSON(w, http.StatusCreated, certificationResponse(c))
}

// TryAutoIssue is called by LessonsHandler after track completion is detected.
// It is idempotent: if the user already has a non-revoked cert for the track,
// it returns immediately. The Completions eligibility check is intentionally
// skipped here — the caller (LessonsHandler.checkTrackCompletion) has already
// verified that all lessons are complete.
func (h *CertificationsHandler) TryAutoIssue(ctx context.Context, userID, trackID uuid.UUID) error {
	// Idempotency: cert already issued for this user+track.
	if _, err := h.Certs.GetByUserTrack(ctx, userID, trackID); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) && !isErrNoRows(err) {
		return fmt.Errorf("TryAutoIssue: GetByUserTrack: %w", err)
	}

	serial := fmt.Sprintf("CP-%s-%d", trackID.String()[:8], time.Now().Unix())
	c, err := h.Certs.Issue(ctx, userID, trackID, serial, nil)
	if err != nil {
		return fmt.Errorf("TryAutoIssue: Issue: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"cert_id":   c.ID,
		"user_id":   userID,
		"track_id":  trackID,
		"serial":    c.Serial,
		"issued_at": c.IssuedAt,
	})
	if err == nil {
		hexSig := h.Signer.Sign(payload)
		if sigErr := h.Certs.SetSignature(ctx, c.ID, hexSig, ""); sigErr != nil {
			h.log().Warn().Err(sigErr).Str("cert_id", c.ID.String()).Msg("TryAutoIssue: SetSignature")
		} else {
			c.Signature = hexSig
		}
	}

	h.enqueueIssuedEvent(ctx, c, userID, trackID)
	h.appendAudit(ctx, userID, "certification.auto_issue", "certification", c.ID.String())
	h.log().Info().
		Str("cert_id", c.ID.String()).
		Str("user_id", userID.String()).
		Str("track_id", trackID.String()).
		Msg("TryAutoIssue: certificate issued")
	return nil
}

// ListMine handles GET /api/v1/me/certifications.
// Returns the authenticated user's active (non-expired, non-revoked) certifications.
func (h *CertificationsHandler) ListMine(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}

	rows, err := h.Certs.ListByUser(r.Context(), userID, false)
	if err != nil {
		h.log().Error().Err(err).Str("user_id", userID.String()).Msg("certifications.list_mine")
		writeError(w, http.StatusInternalServerError, "internal_error", "certifications lookup failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, certificationResponse(&rows[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":        userID.String(),
		"certifications": out,
	})
}

// Revoke handles DELETE /api/v1/admin/certifications/{id}/revoke.
// Admin-only. Marks the certification as revoked.
func (h *CertificationsHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}
	if !auth.HasRole(claims, auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}

	idStr := chi.URLParam(r, "id")
	certID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "certification id must be a UUID")
		return
	}

	if err := h.Certs.Revoke(r.Context(), certID); err != nil {
		h.log().Error().Err(err).Str("cert_id", idStr).Msg("certifications.revoke")
		writeError(w, http.StatusInternalServerError, "internal_error", "revocation failed")
		return
	}

	actorID, _ := userIDFromContext(r.Context())
	h.appendAudit(r.Context(), actorID, "certification.revoke", "certification", certID.String())

	writeJSON(w, http.StatusOK, map[string]any{
		"cert_id": certID.String(),
		"revoked": true,
	})
}

// ── helpers ────────────────────────────────────────────────────────────────────

func (h *CertificationsHandler) enqueueIssuedEvent(ctx context.Context, c *db.Certification, userID, trackID uuid.UUID) {
	if h.Outbox == nil {
		return
	}
	ev := citadel.CertificationIssued{
		CertificateID:      c.ID.String(),
		UserID:             userID.String(),
		TrackID:            trackID.String(),
		CertificationLevel: "track-cert",
		IssuedAt:           c.IssuedAt,
		ExpiresAt:          c.ExpiresAt,
		SignedBy:            "ed25519:" + h.Signer.KeyID(),
		CorrelationID:      uuid.NewString(),
	}
	if _, err := citadel.EnqueueCertificationIssued(ctx, h.Outbox, ev); err != nil {
		h.log().Warn().Err(err).Msg("certifications: CITADEL enqueue failed (non-fatal)")
	}
}

func (h *CertificationsHandler) appendAudit(ctx context.Context, userID uuid.UUID, action, targetType, targetID string) {
	if h.Audit == nil {
		return
	}
	uidCopy := userID
	_ = h.Audit.Append(ctx, &db.AuditEvent{
		ActorUserID: &uidCopy,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Outcome:     "success",
	})
}

func certificationResponse(c *db.Certification) map[string]any {
	resp := map[string]any{
		"id":        c.ID.String(),
		"user_id":   c.UserID.String(),
		"track_id":  c.TrackID.String(),
		"serial":    c.Serial,
		"issued_at": c.IssuedAt.UTC().Format(time.RFC3339),
		"revoked":   c.Revoked,
		"signature": c.Signature,
	}
	if c.ExpiresAt != nil {
		resp["expires_at"] = c.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if c.PDFPath != "" {
		resp["pdf_path"] = c.PDFPath
	}
	return resp
}

func (h *CertificationsHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// isErrNoRows catches wrapped pgx.ErrNoRows from store methods.
func isErrNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
