package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// scanFinding scans a single finding row from a pgx.Rows or pgx.Row.
func scanFinding(row pgx.Row) (*Finding, error) {
	var f Finding
	err := row.Scan(
		&f.ID, &f.ScanID, &f.OwaspID, &f.ModuleID,
		&f.Title, &f.Description, &f.Severity,
		&f.CVSSScore, &f.CVSSVector,
		&f.EndpointPath, &f.EndpointMethod,
		&f.EvidenceRequest, &f.EvidenceResponse, &f.EvidenceJSON,
		&f.Remediation,
		&f.Status, &f.TriagedBy, &f.TriagedAt, &f.TriageNote,
		&f.CreatedAt, &f.UpdatedAt,
	)
	return &f, err
}

const findingColumns = `
	id, scan_id, owasp_id, module_id,
	title, description, severity,
	cvss_score, cvss_vector,
	endpoint_path, endpoint_method,
	evidence_request, evidence_response, evidence_json,
	remediation,
	status, triaged_by, triaged_at, triage_note,
	created_at, updated_at`

// CreateFinding inserts a single finding and populates its generated fields.
func (d *DB) CreateFinding(ctx context.Context, finding *Finding) error {
	query := `
		INSERT INTO findings (
			scan_id, owasp_id, module_id,
			title, description, severity,
			cvss_score, cvss_vector,
			endpoint_path, endpoint_method,
			evidence_request, evidence_response, evidence_json,
			remediation
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, status, created_at, updated_at`

	return d.Pool.QueryRow(ctx, query,
		finding.ScanID, finding.OwaspID, finding.ModuleID,
		finding.Title, finding.Description, finding.Severity,
		finding.CVSSScore, finding.CVSSVector,
		finding.EndpointPath, finding.EndpointMethod,
		finding.EvidenceRequest, finding.EvidenceResponse, finding.EvidenceJSON,
		finding.Remediation,
	).Scan(&finding.ID, &finding.Status, &finding.CreatedAt, &finding.UpdatedAt)
}

// CreateFindings inserts multiple findings in a single batch operation.
func (d *DB) CreateFindings(ctx context.Context, findings []Finding) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if len(findings) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	query := `
		INSERT INTO findings (
			scan_id, owasp_id, module_id,
			title, description, severity,
			cvss_score, cvss_vector,
			endpoint_path, endpoint_method,
			evidence_request, evidence_response, evidence_json,
			remediation
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, status, created_at, updated_at`

	for i := range findings {
		f := &findings[i]
		batch.Queue(query,
			f.ScanID, f.OwaspID, f.ModuleID,
			f.Title, f.Description, f.Severity,
			f.CVSSScore, f.CVSSVector,
			f.EndpointPath, f.EndpointMethod,
			f.EvidenceRequest, f.EvidenceResponse, f.EvidenceJSON,
			f.Remediation,
		)
	}

	br := d.Pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := range findings {
		if err := br.QueryRow().Scan(
			&findings[i].ID, &findings[i].Status,
			&findings[i].CreatedAt, &findings[i].UpdatedAt,
		); err != nil {
			return fmt.Errorf("inserting finding %d: %w", i, err)
		}
	}

	return nil
}

// GetFinding retrieves a single finding by ID.
func (d *DB) GetFinding(ctx context.Context, id uuid.UUID) (*Finding, error) {
	query := fmt.Sprintf(`SELECT %s FROM findings WHERE id = $1`, findingColumns)

	f, err := scanFinding(d.Pool.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("finding not found: %s", id)
		}
		return nil, fmt.Errorf("querying finding: %w", err)
	}
	return f, nil
}

// ListFindings returns a filtered, paginated list of findings.
// It returns the findings, the total count matching the filters, and any error.
func (d *DB) ListFindings(ctx context.Context, filters FindingFilters, limit, offset int) ([]Finding, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const maxPageSize = 100
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var conditions []string
	var args []interface{}
	argIdx := 1

	if filters.ScanID != nil {
		conditions = append(conditions, fmt.Sprintf("scan_id = $%d", argIdx))
		args = append(args, *filters.ScanID)
		argIdx++
	}
	if filters.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, *filters.Severity)
		argIdx++
	}
	if filters.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *filters.Status)
		argIdx++
	}
	if filters.OwaspID != nil {
		conditions = append(conditions, fmt.Sprintf("owasp_id = $%d", argIdx))
		args = append(args, *filters.OwaspID)
		argIdx++
	}
	if filters.ModuleID != nil {
		conditions = append(conditions, fmt.Sprintf("module_id = $%d", argIdx))
		args = append(args, *filters.ModuleID)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings %s", whereClause)
	var total int
	if err := d.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting findings: %w", err)
	}

	// Fetch the page.
	dataQuery := fmt.Sprintf(
		"SELECT %s FROM findings %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		findingColumns, whereClause, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := d.Pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.OwaspID, &f.ModuleID,
			&f.Title, &f.Description, &f.Severity,
			&f.CVSSScore, &f.CVSSVector,
			&f.EndpointPath, &f.EndpointMethod,
			&f.EvidenceRequest, &f.EvidenceResponse, &f.EvidenceJSON,
			&f.Remediation,
			&f.Status, &f.TriagedBy, &f.TriagedAt, &f.TriageNote,
			&f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning row: %w", err)
		}
		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating rows: %w", err)
	}

	return findings, total, nil
}

// UpdateFindingStatus updates the triage status, note, and actor on a finding.
func (d *DB) UpdateFindingStatus(ctx context.Context, id uuid.UUID, status FindingStatus, note, actorID string) error {
	query := `
		UPDATE findings
		SET status = $1, triage_note = $2, triaged_by = $3, triaged_at = NOW(), updated_at = NOW()
		WHERE id = $4`

	ct, err := d.Pool.Exec(ctx, query, status, note, actorID, id)
	if err != nil {
		return fmt.Errorf("updating finding status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("finding not found: %s", id)
	}
	return nil
}

// ListFindingsByScan returns a paginated list of findings for a specific scan.
func (d *DB) ListFindingsByScan(ctx context.Context, scanID uuid.UUID, limit, offset int) ([]Finding, int, error) {
	filters := FindingFilters{ScanID: &scanID}
	return d.ListFindings(ctx, filters, limit, offset)
}
