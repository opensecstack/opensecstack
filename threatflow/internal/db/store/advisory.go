package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Advisory mirrors the *current* revision of a row in advisories.
type Advisory struct {
	ID                 uuid.UUID  `json:"id"`
	TrackingID         string     `json:"tracking_id"`
	CSAFVersion        string     `json:"csaf_version"`
	Revision           string     `json:"revision"`
	Category           string     `json:"category"`
	Title              string     `json:"title"`
	Lang               string     `json:"lang"`
	Status             string     `json:"status"`
	TLPLabel           string     `json:"tlp_label"`
	PublisherName      string     `json:"publisher_name"`
	PublisherCategory  string     `json:"publisher_category"`
	PublisherNamespace string     `json:"publisher_namespace,omitempty"`
	InitialReleaseDate time.Time  `json:"initial_release_date"`
	CurrentReleaseDate time.Time  `json:"current_release_date"`
	Source             string     `json:"source"`
	StixBundleID       *uuid.UUID `json:"stix_bundle_id,omitempty"`
	RawDocument        []byte     `json:"-"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// AdvisoryVulnerability mirrors a row in advisory_vulnerabilities.
type AdvisoryVulnerability struct {
	ID            uuid.UUID `json:"id"`
	AdvisoryID    uuid.UUID `json:"advisory_id"`
	CVE           string    `json:"cve,omitempty"`
	Title         string    `json:"title"`
	Notes         []byte    `json:"notes"`
	ProductStatus []byte    `json:"product_status"`
	Scores        []byte    `json:"scores"`
	References    []byte    `json:"references"`
	StixObjectRef string    `json:"stix_object_ref,omitempty"`
	CreatedAt     time.Time `json:"created_at"`

	Remediations []*AdvisoryRemediation `json:"remediations,omitempty"`
}

// AdvisoryRemediation mirrors a row in advisory_remediations.
type AdvisoryRemediation struct {
	ID              uuid.UUID `json:"id"`
	VulnerabilityID uuid.UUID `json:"vulnerability_id"`
	Category        string    `json:"category"`
	Details         string    `json:"details"`
	ProductIDs      []string  `json:"product_ids"`
	URL             string    `json:"url,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// AdvisoryProduct mirrors a row in advisory_products.
type AdvisoryProduct struct {
	ID         uuid.UUID `json:"id"`
	AdvisoryID uuid.UUID `json:"advisory_id"`
	ProductID  string    `json:"product_id"`
	Name       string    `json:"name"`
	CPE        string    `json:"cpe,omitempty"`
	PURL       string    `json:"purl,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// AdvisoryDetail bundles an Advisory with its child rows for GET responses.
type AdvisoryDetail struct {
	Advisory
	Vulnerabilities []*AdvisoryVulnerability `json:"vulnerabilities"`
	Products        []*AdvisoryProduct       `json:"products"`
}

// UpsertAdvisoryInput is the fully-prepared write for one CSAF revision —
// STIX objects referenced by Vulnerabilities[].StixObjectRef must already be
// persisted (via StixStore) before this is called, since advisory_
// vulnerabilities.stix_object_ref is a foreign key into stix_objects.stix_id.
type UpsertAdvisoryInput struct {
	Advisory        *Advisory
	Vulnerabilities []*AdvisoryVulnerability
	Products        []*AdvisoryProduct
	DocumentHash    string
}

// AdvisoryAction describes what UpsertRevision did with a given revision.
type AdvisoryAction string

const (
	// AdvisoryCreated: tracking.id was never seen before.
	AdvisoryCreated AdvisoryAction = "created"
	// AdvisoryUpdated: tracking.id existed and the incoming version is newer
	// — the advisory row and all child rows were replaced with the new
	// revision's data.
	AdvisoryUpdated AdvisoryAction = "updated"
	// AdvisoryDuplicate: this exact (tracking.id, version) was already
	// ingested — a no-op, idempotent re-delivery.
	AdvisoryDuplicate AdvisoryAction = "duplicate"
	// AdvisoryStale: tracking.id existed with a newer version already
	// stored than the one in this request — logged for audit, current
	// state left untouched.
	AdvisoryStale AdvisoryAction = "stale"
)

// UpsertAdvisoryResult is returned by UpsertRevision.
type UpsertAdvisoryResult struct {
	Advisory *Advisory
	Action   AdvisoryAction
}

// AdvisoryStore persists advisories / advisory_revisions /
// advisory_vulnerabilities / advisory_remediations / advisory_products rows.
type AdvisoryStore struct {
	pool *pgxpool.Pool
}

// NewAdvisoryStore binds a store to the pool.
func NewAdvisoryStore(pool *pgxpool.Pool) *AdvisoryStore {
	return &AdvisoryStore{pool: pool}
}

// UpsertRevision applies one CSAF revision under a single transaction — the
// (tracking.id, version) dedup/staleness decision and the row mutation are
// made atomically (SELECT ... FOR UPDATE on the tracking_id row) so
// concurrent pushes of the same advisory can't race past each other into an
// inconsistent state. See AdvisoryAction for the possible outcomes.
func (s *AdvisoryStore) UpsertRevision(ctx context.Context, in *UpsertAdvisoryInput) (*UpsertAdvisoryResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		existingID       uuid.UUID
		existingRevision string
	)
	err = tx.QueryRow(ctx,
		`SELECT id, revision FROM advisories WHERE tracking_id = $1 FOR UPDATE`,
		in.Advisory.TrackingID,
	).Scan(&existingID, &existingRevision)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		res, err := s.insertNew(ctx, tx, in)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}
		return res, nil

	case err != nil:
		return nil, fmt.Errorf("lock advisory: %w", err)
	}

	cmp := compareVersionsExported(in.Advisory.Revision, existingRevision)
	switch {
	case cmp == 0:
		// Duplicate: record the receipt for audit (ON CONFLICT DO NOTHING —
		// the unique constraint on (advisory_id, revision) makes this
		// idempotent), but never touch current state.
		if _, err := tx.Exec(ctx, `
INSERT INTO advisory_revisions (advisory_id, revision, document_hash, raw_document)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (advisory_id, revision) DO NOTHING`,
			existingID, in.Advisory.Revision, in.DocumentHash, in.Advisory.RawDocument,
		); err != nil {
			return nil, fmt.Errorf("record duplicate revision: %w", err)
		}
		a, err := s.getTx(ctx, tx, existingID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}
		return &UpsertAdvisoryResult{Advisory: a, Action: AdvisoryDuplicate}, nil

	case cmp < 0:
		// Stale: incoming revision is older than what's already stored.
		// Still logged to advisory_revisions for the audit trail (this
		// specific revision string has not been seen before, or it would
		// have hit the duplicate case above), current state untouched.
		if _, err := tx.Exec(ctx, `
INSERT INTO advisory_revisions (advisory_id, revision, document_hash, raw_document)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (advisory_id, revision) DO NOTHING`,
			existingID, in.Advisory.Revision, in.DocumentHash, in.Advisory.RawDocument,
		); err != nil {
			return nil, fmt.Errorf("record stale revision: %w", err)
		}
		a, err := s.getTx(ctx, tx, existingID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}
		return &UpsertAdvisoryResult{Advisory: a, Action: AdvisoryStale}, nil
	}

	// cmp > 0: incoming revision is newer — replace current state.
	in.Advisory.ID = existingID
	res, err := s.replace(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

func (s *AdvisoryStore) insertNew(ctx context.Context, tx pgx.Tx, in *UpsertAdvisoryInput) (*UpsertAdvisoryResult, error) {
	a := in.Advisory
	err := tx.QueryRow(ctx, `
INSERT INTO advisories (
    tracking_id, csaf_version, revision, category, title, lang, status,
    tlp_label, publisher_name, publisher_category, publisher_namespace,
    initial_release_date, current_release_date, source, stix_bundle_id, raw_document
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)
RETURNING id, created_at, updated_at`,
		a.TrackingID, a.CSAFVersion, a.Revision, a.Category, a.Title, a.Lang, a.Status,
		a.TLPLabel, a.PublisherName, a.PublisherCategory, nullIfEmpty(a.PublisherNamespace),
		a.InitialReleaseDate, a.CurrentReleaseDate, a.Source, a.StixBundleID, a.RawDocument,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert advisory: %w", err)
	}

	if err := s.insertChildren(ctx, tx, a.ID, in); err != nil {
		return nil, err
	}
	if err := s.insertRevisionLog(ctx, tx, a.ID, a.Revision, in.DocumentHash, a.RawDocument); err != nil {
		return nil, err
	}
	return &UpsertAdvisoryResult{Advisory: a, Action: AdvisoryCreated}, nil
}

func (s *AdvisoryStore) replace(ctx context.Context, tx pgx.Tx, in *UpsertAdvisoryInput) (*UpsertAdvisoryResult, error) {
	a := in.Advisory
	err := tx.QueryRow(ctx, `
UPDATE advisories SET
    csaf_version = $2, revision = $3, category = $4, title = $5, lang = $6,
    status = $7, tlp_label = $8, publisher_name = $9, publisher_category = $10,
    publisher_namespace = $11, initial_release_date = $12, current_release_date = $13,
    source = $14, stix_bundle_id = $15, raw_document = $16::jsonb, updated_at = now()
WHERE id = $1
RETURNING created_at, updated_at`,
		a.ID, a.CSAFVersion, a.Revision, a.Category, a.Title, a.Lang, a.Status,
		a.TLPLabel, a.PublisherName, a.PublisherCategory, nullIfEmpty(a.PublisherNamespace),
		a.InitialReleaseDate, a.CurrentReleaseDate, a.Source, a.StixBundleID, a.RawDocument,
	).Scan(&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update advisory: %w", err)
	}

	// Replace child rows wholesale — a revision supersedes the previous
	// revision's vulnerability/product set entirely rather than merging,
	// matching how CSAF documents are authored (each revision is a
	// complete, self-contained document, not a diff).
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_vulnerabilities WHERE advisory_id = $1`, a.ID); err != nil {
		return nil, fmt.Errorf("clear vulnerabilities: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_products WHERE advisory_id = $1`, a.ID); err != nil {
		return nil, fmt.Errorf("clear products: %w", err)
	}
	if err := s.insertChildren(ctx, tx, a.ID, in); err != nil {
		return nil, err
	}
	if err := s.insertRevisionLog(ctx, tx, a.ID, a.Revision, in.DocumentHash, a.RawDocument); err != nil {
		return nil, err
	}
	return &UpsertAdvisoryResult{Advisory: a, Action: AdvisoryUpdated}, nil
}

func (s *AdvisoryStore) insertChildren(ctx context.Context, tx pgx.Tx, advisoryID uuid.UUID, in *UpsertAdvisoryInput) error {
	for _, v := range in.Vulnerabilities {
		v.AdvisoryID = advisoryID
		if v.Notes == nil {
			v.Notes = []byte(`[]`)
		}
		if v.ProductStatus == nil {
			v.ProductStatus = []byte(`{}`)
		}
		if v.Scores == nil {
			v.Scores = []byte(`[]`)
		}
		if v.References == nil {
			v.References = []byte(`[]`)
		}
		err := tx.QueryRow(ctx, `
INSERT INTO advisory_vulnerabilities (
    advisory_id, cve, title, notes, product_status, scores, references_json, stix_object_ref
) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8)
RETURNING id, created_at`,
			v.AdvisoryID, nullIfEmpty(v.CVE), v.Title, v.Notes, v.ProductStatus, v.Scores, v.References,
			nullIfEmpty(v.StixObjectRef),
		).Scan(&v.ID, &v.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert vulnerability %q: %w", v.Title, err)
		}

		for _, r := range v.Remediations {
			r.VulnerabilityID = v.ID
			if r.ProductIDs == nil {
				r.ProductIDs = []string{}
			}
			err := tx.QueryRow(ctx, `
INSERT INTO advisory_remediations (vulnerability_id, category, details, product_ids, url)
VALUES ($1,$2,$3,$4,$5)
RETURNING id, created_at`,
				r.VulnerabilityID, r.Category, r.Details, r.ProductIDs, nullIfEmpty(r.URL),
			).Scan(&r.ID, &r.CreatedAt)
			if err != nil {
				return fmt.Errorf("insert remediation for %q: %w", v.Title, err)
			}
		}
	}

	for _, p := range in.Products {
		p.AdvisoryID = advisoryID
		err := tx.QueryRow(ctx, `
INSERT INTO advisory_products (advisory_id, product_id, name, cpe, purl)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (advisory_id, product_id) DO UPDATE SET name = EXCLUDED.name
RETURNING id, created_at`,
			p.AdvisoryID, p.ProductID, p.Name, nullIfEmpty(p.CPE), nullIfEmpty(p.PURL),
		).Scan(&p.ID, &p.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert product %q: %w", p.ProductID, err)
		}
	}
	return nil
}

func (s *AdvisoryStore) insertRevisionLog(ctx context.Context, tx pgx.Tx, advisoryID uuid.UUID, revision, documentHash string, rawDoc []byte) error {
	_, err := tx.Exec(ctx, `
INSERT INTO advisory_revisions (advisory_id, revision, document_hash, raw_document)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (advisory_id, revision) DO NOTHING`,
		advisoryID, revision, documentHash, rawDoc,
	)
	if err != nil {
		return fmt.Errorf("insert revision log: %w", err)
	}
	return nil
}

func (s *AdvisoryStore) getTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*Advisory, error) {
	a := &Advisory{}
	var raw []byte
	err := tx.QueryRow(ctx, `
SELECT id, tracking_id, csaf_version, revision, category, title, lang, status,
       tlp_label, publisher_name, publisher_category, coalesce(publisher_namespace, ''),
       initial_release_date, current_release_date, source, stix_bundle_id, raw_document,
       created_at, updated_at
FROM advisories WHERE id = $1`, id).Scan(
		&a.ID, &a.TrackingID, &a.CSAFVersion, &a.Revision, &a.Category, &a.Title, &a.Lang, &a.Status,
		&a.TLPLabel, &a.PublisherName, &a.PublisherCategory, &a.PublisherNamespace,
		&a.InitialReleaseDate, &a.CurrentReleaseDate, &a.Source, &a.StixBundleID, &raw,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get advisory: %w", err)
	}
	a.RawDocument = raw
	return a, nil
}

// GetByTrackingID fetches the current advisory row by its CSAF tracking id.
func (s *AdvisoryStore) GetByTrackingID(ctx context.Context, trackingID string) (*Advisory, error) {
	a := &Advisory{}
	var raw []byte
	err := s.pool.QueryRow(ctx, `
SELECT id, tracking_id, csaf_version, revision, category, title, lang, status,
       tlp_label, publisher_name, publisher_category, coalesce(publisher_namespace, ''),
       initial_release_date, current_release_date, source, stix_bundle_id, raw_document,
       created_at, updated_at
FROM advisories WHERE tracking_id = $1`, trackingID).Scan(
		&a.ID, &a.TrackingID, &a.CSAFVersion, &a.Revision, &a.Category, &a.Title, &a.Lang, &a.Status,
		&a.TLPLabel, &a.PublisherName, &a.PublisherCategory, &a.PublisherNamespace,
		&a.InitialReleaseDate, &a.CurrentReleaseDate, &a.Source, &a.StixBundleID, &raw,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.RawDocument = raw
	return a, nil
}

// Get fetches an advisory by internal UUID, including its vulnerabilities
// (with nested remediations) and products.
func (s *AdvisoryStore) Get(ctx context.Context, id uuid.UUID) (*AdvisoryDetail, error) {
	a, err := s.getByID(ctx, id)
	if err != nil {
		return nil, err
	}
	vulns, err := s.vulnerabilitiesForAdvisory(ctx, id)
	if err != nil {
		return nil, err
	}
	products, err := s.productsForAdvisory(ctx, id)
	if err != nil {
		return nil, err
	}
	return &AdvisoryDetail{Advisory: *a, Vulnerabilities: vulns, Products: products}, nil
}

func (s *AdvisoryStore) getByID(ctx context.Context, id uuid.UUID) (*Advisory, error) {
	a := &Advisory{}
	var raw []byte
	err := s.pool.QueryRow(ctx, `
SELECT id, tracking_id, csaf_version, revision, category, title, lang, status,
       tlp_label, publisher_name, publisher_category, coalesce(publisher_namespace, ''),
       initial_release_date, current_release_date, source, stix_bundle_id, raw_document,
       created_at, updated_at
FROM advisories WHERE id = $1`, id).Scan(
		&a.ID, &a.TrackingID, &a.CSAFVersion, &a.Revision, &a.Category, &a.Title, &a.Lang, &a.Status,
		&a.TLPLabel, &a.PublisherName, &a.PublisherCategory, &a.PublisherNamespace,
		&a.InitialReleaseDate, &a.CurrentReleaseDate, &a.Source, &a.StixBundleID, &raw,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.RawDocument = raw
	return a, nil
}

func (s *AdvisoryStore) vulnerabilitiesForAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]*AdvisoryVulnerability, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, advisory_id, coalesce(cve, ''), title, notes::text, product_status::text,
       scores::text, references_json::text, coalesce(stix_object_ref, ''), created_at
FROM advisory_vulnerabilities WHERE advisory_id = $1 ORDER BY created_at`, advisoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AdvisoryVulnerability
	for rows.Next() {
		var (
			v                                            AdvisoryVulnerability
			notes, productStatus, scores, referencesJSON string
		)
		if err := rows.Scan(&v.ID, &v.AdvisoryID, &v.CVE, &v.Title, &notes, &productStatus,
			&scores, &referencesJSON, &v.StixObjectRef, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.Notes = json.RawMessage(notes)
		v.ProductStatus = json.RawMessage(productStatus)
		v.Scores = json.RawMessage(scores)
		v.References = json.RawMessage(referencesJSON)
		rem, err := s.remediationsForVulnerability(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		v.Remediations = rem
		out = append(out, &v)
	}
	return out, rows.Err()
}

func (s *AdvisoryStore) remediationsForVulnerability(ctx context.Context, vulnID uuid.UUID) ([]*AdvisoryRemediation, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, vulnerability_id, category, details, product_ids, coalesce(url, ''), created_at
FROM advisory_remediations WHERE vulnerability_id = $1 ORDER BY created_at`, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AdvisoryRemediation
	for rows.Next() {
		var r AdvisoryRemediation
		if err := rows.Scan(&r.ID, &r.VulnerabilityID, &r.Category, &r.Details, &r.ProductIDs, &r.URL, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *AdvisoryStore) productsForAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]*AdvisoryProduct, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, advisory_id, product_id, name, coalesce(cpe, ''), coalesce(purl, ''), created_at
FROM advisory_products WHERE advisory_id = $1 ORDER BY created_at`, advisoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AdvisoryProduct
	for rows.Next() {
		var p AdvisoryProduct
		if err := rows.Scan(&p.ID, &p.AdvisoryID, &p.ProductID, &p.Name, &p.CPE, &p.PURL, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// List returns advisories ordered by current_release_date DESC.
func (s *AdvisoryStore) List(ctx context.Context, limit, offset int) ([]*Advisory, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM advisories`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx, `
SELECT id, tracking_id, csaf_version, revision, category, title, lang, status,
       tlp_label, publisher_name, publisher_category, coalesce(publisher_namespace, ''),
       initial_release_date, current_release_date, source, stix_bundle_id,
       created_at, updated_at
FROM advisories
ORDER BY current_release_date DESC
LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*Advisory
	for rows.Next() {
		var a Advisory
		if err := rows.Scan(&a.ID, &a.TrackingID, &a.CSAFVersion, &a.Revision, &a.Category, &a.Title,
			&a.Lang, &a.Status, &a.TLPLabel, &a.PublisherName, &a.PublisherCategory, &a.PublisherNamespace,
			&a.InitialReleaseDate, &a.CurrentReleaseDate, &a.Source, &a.StixBundleID,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, &a)
	}
	return out, total, rows.Err()
}

// compareVersionsExported orders two CSAF tracking.version strings the same
// way internal/csaf.compareVersions does (integer comparison when both
// parse as integers, else exact string match for "same revision" and
// "treat as newer" for anything else — see that function's doc for the
// rationale). It is duplicated here in miniature, rather than imported,
// because internal/csaf imports this package (for the store types it
// builds) and this comparison must run *inside* the UpsertRevision
// transaction, under the row lock, to avoid a check-then-act race between
// two concurrent pushes of the same advisory. Keep the two in sync.
func compareVersionsExported(a, b string) int {
	an, aerr := parseIntSafe(a)
	bn, berr := parseIntSafe(b)
	if aerr == nil && berr == nil {
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	}
	if a == b {
		return 0
	}
	return 1
}

func parseIntSafe(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a digit: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
