package db

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/zeebo/blake3"
)

// WORMEntry is a single append-only log record in the WORM chain.
type WORMEntry struct {
	ID          uuid.UUID
	SequenceNum int64
	TsUTC       time.Time
	Source      string
	EventType   string
	ProjectID   string
	Payload     []byte // raw JSON
	TripleHash  string // hex(SHA-256||SHA-512||BLAKE3) = 256 hex chars
	ChainHash   string // hex(SHA-256(prev_hash || payload_bytes))
	PrevHash    string
	CreatedAt   time.Time
}

// TripleHash computes the 128-byte composite digest of payload.
// Layout: bytes 0-32 SHA-256, bytes 32-96 SHA-512, bytes 96-128 BLAKE3.
// Returns the result as a 256-character hex string.
func TripleHash(payload []byte) string {
	h256 := sha256.Sum256(payload) // 32 bytes
	h512 := sha512.Sum512(payload) // 64 bytes
	hB3 := blake3.Sum256(payload)  // 32 bytes

	composite := make([]byte, 0, 128)
	composite = append(composite, h256[:]...)
	composite = append(composite, h512[:]...)
	composite = append(composite, hB3[:]...)

	return hex.EncodeToString(composite)
}

// chainHash computes SHA-256(prevHash || payloadBytes).
func chainHash(prevHashHex string, payloadBytes []byte) string {
	prev, err := hex.DecodeString(prevHashHex)
	if err != nil {
		// prevHash was not valid hex — use raw bytes
		prev = []byte(prevHashHex)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(payloadBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendWORM inserts a new entry into the WORM chain.
// It reads the last chain_hash, computes the new chain_hash and triple_hash,
// then inserts atomically. Returns the completed WORMEntry.
func (d *DB) AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte) (*WORMEntry, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("worm: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Lock to prevent concurrent appends breaking the chain.
	if _, err := tx.Exec(ctx, "LOCK TABLE worm_entries IN EXCLUSIVE MODE"); err != nil {
		return nil, fmt.Errorf("worm: lock table: %w", err)
	}

	// Get last sequence_num and chain_hash.
	var prevHash string
	var prevSeq int64
	row := tx.QueryRow(ctx,
		`SELECT sequence_num, chain_hash FROM worm_entries ORDER BY sequence_num DESC LIMIT 1`)
	err = row.Scan(&prevSeq, &prevHash)
	if err != nil {
		// No rows — genesis entry
		prevSeq = 0
		prevHash = genesisHash()
	}

	seqNum := prevSeq + 1
	th := TripleHash(payload)
	ch := chainHash(prevHash, payload)
	id := uuid.New()
	now := time.Now().UTC()

	_, err = tx.Exec(ctx, `
		INSERT INTO worm_entries
			(id, sequence_num, ts_utc, source, event_type, project_id,
			 payload, triple_hash, chain_hash, prev_hash, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, seqNum, now, source, eventType, projectID,
		payload, th, ch, prevHash, now,
	)
	if err != nil {
		return nil, fmt.Errorf("worm: insert entry: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("worm: commit: %w", err)
	}

	return &WORMEntry{
		ID:          id,
		SequenceNum: seqNum,
		TsUTC:       now,
		Source:      source,
		EventType:   eventType,
		ProjectID:   projectID,
		Payload:     payload,
		TripleHash:  th,
		ChainHash:   ch,
		PrevHash:    prevHash,
		CreatedAt:   now,
	}, nil
}

// VerifyResult is the outcome of a chain integrity check.
type VerifyResult struct {
	Valid           bool   `json:"valid"`
	EntriesVerified int    `json:"entries_verified"`
	BreakAt         string `json:"break_at,omitempty"`
	AnchorVerified  bool   `json:"anchor_verified"`
}

// VerifyChain performs linear chain verification for entries in [from, to].
// Returns a VerifyResult with the first break point if tampering is detected.
func (d *DB) VerifyChain(ctx context.Context, from, to time.Time) (*VerifyResult, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT sequence_num, payload, triple_hash, chain_hash, prev_hash
		 FROM worm_entries
		 WHERE ts_utc BETWEEN $1 AND $2
		 ORDER BY sequence_num ASC`,
		from, to,
	)
	if err != nil {
		return nil, fmt.Errorf("worm: verify query: %w", err)
	}
	defer rows.Close()

	type row struct {
		SeqNum     int64
		Payload    []byte
		TripleHash string
		ChainHash  string
		PrevHash   string
	}

	var entries []row
	for rows.Next() {
		var e row
		if err := rows.Scan(&e.SeqNum, &e.Payload, &e.TripleHash, &e.ChainHash, &e.PrevHash); err != nil {
			return nil, fmt.Errorf("worm: verify scan: %w", err)
		}
		entries = append(entries, e)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("worm: verify rows: %w", rows.Err())
	}

	if len(entries) == 0 {
		return &VerifyResult{Valid: true, EntriesVerified: 0}, nil
	}

	// Verify each entry.
	for i, e := range entries {
		// 1. Recompute triple_hash
		expected := TripleHash(e.Payload)
		if expected != e.TripleHash {
			return &VerifyResult{
				Valid:           false,
				EntriesVerified: i,
				BreakAt:         fmt.Sprintf("sequence_num=%d: triple_hash mismatch", e.SeqNum),
			}, nil
		}

		// 2. Recompute chain_hash
		expectedChain := chainHash(e.PrevHash, e.Payload)
		if expectedChain != e.ChainHash {
			return &VerifyResult{
				Valid:           false,
				EntriesVerified: i,
				BreakAt:         fmt.Sprintf("sequence_num=%d: chain_hash mismatch", e.SeqNum),
			}, nil
		}

		// 3. Check chain continuity (prev_hash of entry[i] == chain_hash of entry[i-1])
		if i > 0 && e.PrevHash != entries[i-1].ChainHash {
			return &VerifyResult{
				Valid:           false,
				EntriesVerified: i,
				BreakAt:         fmt.Sprintf("sequence_num=%d: prev_hash does not match prior chain_hash", e.SeqNum),
			}, nil
		}
	}

	return &VerifyResult{
		Valid:           true,
		EntriesVerified: len(entries),
		AnchorVerified:  false, // Ed25519 anchor verification added in Session 4
	}, nil
}

// GetLastChainHash returns the chain_hash of the most recent WORM entry.
// Returns the genesis hash if no entries exist.
func (d *DB) GetLastChainHash(ctx context.Context) (string, error) {
	var ch string
	err := d.Pool.QueryRow(ctx,
		`SELECT chain_hash FROM worm_entries ORDER BY sequence_num DESC LIMIT 1`,
	).Scan(&ch)
	if err != nil {
		return genesisHash(), nil
	}
	return ch, nil
}

// genesisHash returns SHA-256("CITADEL-GENESIS-SIN-v1") as hex.
func genesisHash() string {
	h := sha256.Sum256([]byte("CITADEL-GENESIS-SIN-v1"))
	return hex.EncodeToString(h[:])
}
