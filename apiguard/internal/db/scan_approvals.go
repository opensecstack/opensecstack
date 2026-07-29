package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ApprovalStatus represents the state of a two-person scan approval request.
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
)

// ScanApproval represents a row in the scan_approvals table: a record of the
// real Operator (RequestedBy) who asked for a scan and — once decided — the
// real, distinct Verifier (DecidedBy) who approved or rejected it. This is
// the persistence backing for genuine two-person Separation of Duties on scan
// initiation (feeding CITADEL Gate 3 NDS with two real, independently
// sinauth-authenticated identities instead of a fixed placeholder Verifier).
// See internal/api/handlers/scans.go's Approve/Reject handlers.
type ScanApproval struct {
	ID             uuid.UUID      `json:"id"`
	ScanID         uuid.UUID      `json:"scan_id"`
	RequestedBy    string         `json:"requested_by"`
	Status         ApprovalStatus `json:"status"`
	DecidedBy      sql.NullString `json:"decided_by"`
	DecidedAt      sql.NullTime   `json:"decided_at"`
	DecisionReason sql.NullString `json:"decision_reason"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// CreateScanApproval inserts a pending approval record for a scan, recording
// the real sinauth UserID of the Operator who requested it.
func (d *DB) CreateScanApproval(ctx context.Context, scanID uuid.UUID, requestedBy string) (*ScanApproval, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	a := &ScanApproval{ScanID: scanID, RequestedBy: requestedBy, Status: ApprovalStatusPending}
	query := `
		INSERT INTO scan_approvals (scan_id, requested_by, status)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`
	if err := d.Pool.QueryRow(ctx, query, scanID, requestedBy, ApprovalStatusPending).
		Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, fmt.Errorf("creating scan approval: %w", err)
	}
	return a, nil
}

// GetScanApprovalByScanID retrieves the approval record for a scan.
func (d *DB) GetScanApprovalByScanID(ctx context.Context, scanID uuid.UUID) (*ScanApproval, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT id, scan_id, requested_by, status, decided_by, decided_at, decision_reason, created_at, updated_at
		FROM scan_approvals
		WHERE scan_id = $1`

	var a ScanApproval
	err := d.Pool.QueryRow(ctx, query, scanID).Scan(
		&a.ID, &a.ScanID, &a.RequestedBy, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.DecisionReason, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("scan approval not found for scan: %s", scanID)
		}
		return nil, fmt.Errorf("querying scan approval: %w", err)
	}
	return &a, nil
}

// ApproveScanApproval transitions a pending approval to approved, recording
// the real, distinct Verifier's UserID. The UPDATE only affects rows still in
// "pending" status, so it is safe to use as the authoritative guard against a
// double-approve or approve-after-reject race even if the caller already
// checked the status moments earlier. Returns an error (0 rows affected) if
// the approval was not found or was no longer pending.
func (d *DB) ApproveScanApproval(ctx context.Context, scanID uuid.UUID, decidedBy string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		UPDATE scan_approvals
		SET status = $1, decided_by = $2, decided_at = NOW(), updated_at = NOW()
		WHERE scan_id = $3 AND status = $4`
	ct, err := d.Pool.Exec(ctx, query, ApprovalStatusApproved, decidedBy, scanID, ApprovalStatusPending)
	if err != nil {
		return fmt.Errorf("approving scan approval: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan approval race: not pending for scan %s", scanID)
	}
	return nil
}

// RejectScanApproval transitions a pending approval to rejected, recording
// the reviewer's UserID and a reason (e.g. a CITADEL REFUSE/HARD_STOP outcome,
// a manual decline, or the original request expiring before it was decided).
// Same race-safe semantics as ApproveScanApproval.
func (d *DB) RejectScanApproval(ctx context.Context, scanID uuid.UUID, decidedBy, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		UPDATE scan_approvals
		SET status = $1, decided_by = $2, decided_at = NOW(), decision_reason = $3, updated_at = NOW()
		WHERE scan_id = $4 AND status = $5`
	ct, err := d.Pool.Exec(ctx, query, ApprovalStatusRejected, decidedBy, reason, scanID, ApprovalStatusPending)
	if err != nil {
		return fmt.Errorf("rejecting scan approval: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan approval race: not pending for scan %s", scanID)
	}
	return nil
}
