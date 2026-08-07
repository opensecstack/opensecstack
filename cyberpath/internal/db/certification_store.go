// Package db — certification_store manages the `certifications` table.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Certification mirrors a row in `certifications`.
type Certification struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	TrackID    uuid.UUID  `json:"track_id"`
	Serial     string     `json:"serial"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	PDFPath    string     `json:"pdf_path,omitempty"`
	Signature  string     `json:"signature,omitempty"`
	Revoked    bool       `json:"revoked"`
}

// CertificationStore wraps a pgx pool for `certifications`.
type CertificationStore struct {
	Pool *pgxpool.Pool
}

// NewCertificationStore wires a CertificationStore.
func NewCertificationStore(pool *pgxpool.Pool) *CertificationStore {
	return &CertificationStore{Pool: pool}
}

const certificationColumns = `id, user_id, track_id, serial, issued_at, expires_at,
	COALESCE(pdf_path,''), COALESCE(signature,''), revoked`

func scanCertification(row pgx.Row) (*Certification, error) {
	var c Certification
	if err := row.Scan(
		&c.ID, &c.UserID, &c.TrackID, &c.Serial, &c.IssuedAt, &c.ExpiresAt,
		&c.PDFPath, &c.Signature, &c.Revoked,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// Issue inserts a new certification row. The serial is required by the
// schema (unique). expiresAt is optional; pass nil for non-expiring.
func (s *CertificationStore) Issue(ctx context.Context, userID, trackID uuid.UUID, serial string, expiresAt *time.Time) (*Certification, error) {
	const op = "db/certification_store/Issue"
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO certifications (user_id, track_id, serial, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING `+certificationColumns,
		userID, trackID, serial, nullableTime(expiresAt),
	)
	c, err := scanCertification(row)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return c, nil
}

// ListByUser returns certifications for a user. When includeExpired is
// false, expired and revoked rows are filtered out.
func (s *CertificationStore) ListByUser(ctx context.Context, userID uuid.UUID, includeExpired bool) ([]Certification, error) {
	const op = "db/certification_store/ListByUser"
	q := `SELECT ` + certificationColumns + ` FROM certifications WHERE user_id = $1`
	if !includeExpired {
		q += ` AND revoked = FALSE AND (expires_at IS NULL OR expires_at > now())`
	}
	q += ` ORDER BY issued_at DESC`
	rows, err := s.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Certification, 0, 8)
	for rows.Next() {
		c, err := scanCertification(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}

// SetSignature updates the signature and pdf_path columns for a certification
// row after the Ed25519 signing step. pdf_path may be empty for v1.0.0 (no
// PDF generation yet).
func (s *CertificationStore) SetSignature(ctx context.Context, certID uuid.UUID, signature, pdfPath string) error {
	const op = "db/certification_store/SetSignature"
	tag, err := s.Pool.Exec(ctx,
		`UPDATE certifications SET signature = $2, pdf_path = $3 WHERE id = $1`,
		certID, signature, pdfPath,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", op, pgx.ErrNoRows)
	}
	return nil
}

// GetByUserTrack returns the most recent non-revoked certification for a
// user+track pair. Returns pgx.ErrNoRows (wrapped) when none exists.
func (s *CertificationStore) GetByUserTrack(ctx context.Context, userID, trackID uuid.UUID) (*Certification, error) {
	const op = "db/certification_store/GetByUserTrack"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+certificationColumns+` FROM certifications
		WHERE user_id = $1 AND track_id = $2 AND revoked = FALSE
		ORDER BY issued_at DESC LIMIT 1`, userID, trackID)
	c, err := scanCertification(row)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return c, nil
}

// Revoke marks a certification as revoked. Returns pgx.ErrNoRows when the
// id doesn't match a row.
func (s *CertificationStore) Revoke(ctx context.Context, certID uuid.UUID) error {
	const op = "db/certification_store/Revoke"
	tag, err := s.Pool.Exec(ctx, `UPDATE certifications SET revoked = TRUE WHERE id = $1`, certID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", op, pgx.ErrNoRows)
	}
	return nil
}
