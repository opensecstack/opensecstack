package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UpsertAPISpec inserts a new api_spec row or returns the existing one if a
// spec with the same hash is already stored. The entry's ID is populated on
// successful insert; on conflict the existing ID is returned via GetAPISpecByHash.
func (d *DB) UpsertAPISpec(ctx context.Context, spec *APISpec) error {
	authSchemes := spec.AuthSchemes
	if authSchemes == nil {
		authSchemes = []byte("[]")
	}
	parsedIR := spec.ParsedIR
	if parsedIR == nil {
		parsedIR = []byte("{}")
	}

	format := spec.SpecFormat
	if format == "" {
		format = "openapi3"
	}

	err := d.Pool.QueryRow(ctx, `
		INSERT INTO api_specs (
			id, spec_hash, spec_url, spec_format, title, version,
			base_url, endpoint_count, auth_schemes, raw_spec, parsed_ir
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)
		ON CONFLICT (spec_hash) DO UPDATE SET
			spec_url    = COALESCE(EXCLUDED.spec_url, api_specs.spec_url),
			updated_at  = NOW()
		RETURNING id, created_at, updated_at`,
		spec.SpecHash,
		spec.SpecURL,
		format,
		spec.Title,
		spec.Version,
		spec.BaseURL,
		spec.EndpointCount,
		authSchemes,
		spec.RawSpec,
		parsedIR,
	).Scan(&spec.ID, &spec.CreatedAt, &spec.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upserting api_spec: %w", err)
	}
	return nil
}

// GetAPISpecByHash retrieves an api_spec by its content hash.
func (d *DB) GetAPISpecByHash(ctx context.Context, hash string) (*APISpec, error) {
	var s APISpec
	err := d.Pool.QueryRow(ctx, `
		SELECT id, spec_hash, spec_url, spec_format, title, version,
		       base_url, endpoint_count, auth_schemes, parsed_ir,
		       created_at, updated_at
		FROM api_specs
		WHERE spec_hash = $1`,
		hash,
	).Scan(
		&s.ID, &s.SpecHash, &s.SpecURL, &s.SpecFormat, &s.Title, &s.Version,
		&s.BaseURL, &s.EndpointCount, &s.AuthSchemes, &s.ParsedIR,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("api_spec not found: %s", hash)
		}
		return nil, fmt.Errorf("querying api_spec: %w", err)
	}
	return &s, nil
}

// LinkScanAPISpec sets the api_spec_id foreign key on a scan row.
func (d *DB) LinkScanAPISpec(ctx context.Context, scanID, specID uuid.UUID) error {
	ct, err := d.Pool.Exec(ctx,
		`UPDATE scans SET api_spec_id = $1, updated_at = NOW() WHERE id = $2`,
		specID, scanID,
	)
	if err != nil {
		return fmt.Errorf("linking api_spec to scan: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan not found: %s", scanID)
	}
	return nil
}
