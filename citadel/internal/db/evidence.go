package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ComplianceEvidence is a single retrievable, structured evidence record
// submitted by a producer platform (currently only NIS2 Compass — see
// nis2compass/app/citadel_client.py's submit_compliance_evidence).
type ComplianceEvidence struct {
	ID             uuid.UUID
	OrganisationID string
	AssessmentID   string
	SchemaVersion  string
	ReportHash     string
	Report         []byte // raw JSONB bytes, verbatim
	SubmittedBy    string
	WORMEntryID    uuid.UUID
	SubmittedAt    time.Time
	CreatedAt      time.Time
}

// InsertComplianceEvidence stores a compliance evidence record. wormEntryID
// must reference an already-appended worm_entries row (see AppendWORM) —
// this function does not itself write to the WORM chain, matching the
// existing precedent in internal/marshal/marshal.go's gate5 (AppendWORM is
// called first, its returned entry.ID is then used as a foreign key by a
// second, separate write). That means these two writes are not atomic
// across tables: if the WORM append succeeds but this insert then fails
// (e.g. a transient connection drop), the event is still durably and
// immutably recorded in worm_entries (the source of truth for "did this
// happen", per root CLAUDE.md's Governance & Audit section) even though it
// is not yet queryable via GET /api/v1/evidence — the caller sees a 500 and
// can safely retry (WORM is append-only, so a retry adds a new entry rather
// than corrupting the old one; duplicate evidence rows for the same
// organisation/assessment are not a correctness problem — retrieval callers
// treat the latest submitted_at as authoritative).
func (d *DB) InsertComplianceEvidence(
	ctx context.Context,
	organisationID, assessmentID, schemaVersion, reportHash string,
	report []byte,
	submittedBy string,
	wormEntryID uuid.UUID,
) (*ComplianceEvidence, error) {
	id := uuid.New()
	now := time.Now().UTC()

	_, err := d.Pool.Exec(ctx, `
		INSERT INTO compliance_evidence
			(id, organisation_id, assessment_id, schema_version, report_hash,
			 report, submitted_by, worm_entry_id, submitted_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		id, organisationID, assessmentID, schemaVersion, reportHash,
		report, submittedBy, wormEntryID, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("evidence: insert: %w", err)
	}

	return &ComplianceEvidence{
		ID:             id,
		OrganisationID: organisationID,
		AssessmentID:   assessmentID,
		SchemaVersion:  schemaVersion,
		ReportHash:     reportHash,
		Report:         report,
		SubmittedBy:    submittedBy,
		WORMEntryID:    wormEntryID,
		SubmittedAt:    now,
		CreatedAt:      now,
	}, nil
}

// GetComplianceEvidence returns a single compliance evidence record by id.
// exists is false (with a nil error) if no such record exists — callers
// must not conflate "not found" with a real query failure.
func (d *DB) GetComplianceEvidence(ctx context.Context, id uuid.UUID) (entry *ComplianceEvidence, exists bool, err error) {
	var e ComplianceEvidence
	row := d.Pool.QueryRow(ctx, `
		SELECT id, organisation_id, assessment_id, schema_version, report_hash,
		       report, submitted_by, worm_entry_id, submitted_at, created_at
		FROM compliance_evidence
		WHERE id = $1`, id)
	err = row.Scan(
		&e.ID, &e.OrganisationID, &e.AssessmentID, &e.SchemaVersion, &e.ReportHash,
		&e.Report, &e.SubmittedBy, &e.WORMEntryID, &e.SubmittedAt, &e.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("evidence: get: %w", err)
	}
	return &e, true, nil
}

// ListComplianceEvidence returns compliance evidence records matching the
// given filters, newest submitted_at first. Either filter may be empty to
// mean "any" — at least one of organisationID/assessmentID SHOULD be
// supplied by callers (enforced at the HTTP handler level, not here) since
// an unfiltered scan of every organisation's evidence is rarely a
// legitimate query.
func (d *DB) ListComplianceEvidence(ctx context.Context, organisationID, assessmentID string) ([]*ComplianceEvidence, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT id, organisation_id, assessment_id, schema_version, report_hash,
		       report, submitted_by, worm_entry_id, submitted_at, created_at
		FROM compliance_evidence
		WHERE ($1 = '' OR organisation_id = $1)
		  AND ($2 = '' OR assessment_id = $2)
		ORDER BY submitted_at DESC`,
		organisationID, assessmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("evidence: list query: %w", err)
	}
	defer rows.Close()

	var out []*ComplianceEvidence
	for rows.Next() {
		var e ComplianceEvidence
		if err := rows.Scan(
			&e.ID, &e.OrganisationID, &e.AssessmentID, &e.SchemaVersion, &e.ReportHash,
			&e.Report, &e.SubmittedBy, &e.WORMEntryID, &e.SubmittedAt, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("evidence: list scan: %w", err)
		}
		out = append(out, &e)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("evidence: list rows: %w", rows.Err())
	}
	return out, nil
}
