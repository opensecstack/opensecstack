package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Correlation is a row in ioc_correlations.
type Correlation struct {
	ID            uuid.UUID       `json:"id"`
	SourceIOCID   uuid.UUID       `json:"source_ioc_id"`
	TargetIOCID   uuid.UUID       `json:"target_ioc_id"`
	Relationship  string          `json:"relationship"`
	Confidence    int             `json:"confidence"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// CorrelationNeighbor is a correlation combined with the value of the other IOC
// — convenient for the `/iocs/{id}/correlations` response.
type CorrelationNeighbor struct {
	Correlation
	OtherIOCID   uuid.UUID `json:"other_ioc_id"`
	OtherType    string    `json:"other_type"`
	OtherValue   string    `json:"other_value"`
	Direction    string    `json:"direction"` // "outbound" = the queried IOC is source
}

// CorrelationStore persists ioc_correlations rows.
type CorrelationStore struct {
	pool *pgxpool.Pool
}

// NewCorrelationStore binds a store to the pool.
func NewCorrelationStore(pool *pgxpool.Pool) *CorrelationStore {
	return &CorrelationStore{pool: pool}
}

// Upsert inserts a correlation or updates the confidence + evidence if the
// same triple already exists.
func (s *CorrelationStore) Upsert(ctx context.Context, c *Correlation) error {
	if c.SourceIOCID == c.TargetIOCID {
		return fmt.Errorf("correlation source and target are identical")
	}
	if len(c.Evidence) == 0 {
		c.Evidence = json.RawMessage(`{}`)
	}
	const q = `
INSERT INTO ioc_correlations (source_ioc_id, target_ioc_id, relationship, confidence, evidence)
VALUES ($1, $2, $3, $4, $5::jsonb)
ON CONFLICT (source_ioc_id, target_ioc_id, relationship) DO UPDATE SET
    confidence = GREATEST(ioc_correlations.confidence, EXCLUDED.confidence),
    evidence   = EXCLUDED.evidence
RETURNING id, created_at`
	return s.pool.QueryRow(ctx, q,
		c.SourceIOCID, c.TargetIOCID, c.Relationship, c.Confidence, c.Evidence,
	).Scan(&c.ID, &c.CreatedAt)
}

// ForIOC returns every correlation that touches iocID, along with the other
// IOC's type/value for rendering.
func (s *CorrelationStore) ForIOC(ctx context.Context, iocID uuid.UUID) ([]*CorrelationNeighbor, error) {
	const q = `
SELECT c.id, c.source_ioc_id, c.target_ioc_id, c.relationship, c.confidence,
       c.evidence::text, c.created_at,
       CASE WHEN c.source_ioc_id = $1 THEN c.target_ioc_id ELSE c.source_ioc_id END AS other_id,
       o.type, o.value,
       CASE WHEN c.source_ioc_id = $1 THEN 'outbound' ELSE 'inbound' END AS direction
FROM ioc_correlations c
JOIN iocs o ON o.id = CASE WHEN c.source_ioc_id = $1 THEN c.target_ioc_id ELSE c.source_ioc_id END
WHERE c.source_ioc_id = $1 OR c.target_ioc_id = $1
ORDER BY c.confidence DESC, c.relationship`

	rows, err := s.pool.Query(ctx, q, iocID)
	if err != nil {
		return nil, fmt.Errorf("query correlations: %w", err)
	}
	defer rows.Close()

	var out []*CorrelationNeighbor
	for rows.Next() {
		var (
			n       CorrelationNeighbor
			evidenceText string
		)
		if err := rows.Scan(
			&n.ID, &n.SourceIOCID, &n.TargetIOCID, &n.Relationship,
			&n.Confidence, &evidenceText, &n.CreatedAt,
			&n.OtherIOCID, &n.OtherType, &n.OtherValue, &n.Direction,
		); err != nil {
			return nil, err
		}
		n.Evidence = json.RawMessage(evidenceText)
		out = append(out, &n)
	}
	return out, rows.Err()
}

// SummaryRow is one technique/relationship aggregation row.
type SummaryRow struct {
	Relationship string `json:"relationship"`
	Count        int    `json:"count"`
}

// Summary returns the count of correlations per relationship kind.
func (s *CorrelationStore) Summary(ctx context.Context) ([]SummaryRow, error) {
	rows, err := s.pool.Query(ctx, `
SELECT relationship, count(*)::int FROM ioc_correlations
GROUP BY relationship ORDER BY count(*) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SummaryRow
	for rows.Next() {
		var r SummaryRow
		if err := rows.Scan(&r.Relationship, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
