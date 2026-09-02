package db

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/zeebo/blake3"

	"github.com/opensecstack/citadel/internal/marshal"
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
	SigOperator string // hex-encoded Ed25519 signature by the Kerkese Operator, empty if unsigned
	SigVerifier string // hex-encoded Ed25519 signature by the Kerkese Verifier, empty if unsigned
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

// ConfigureAnchoring wires the Ed25519 master key and anchor interval into
// d, enabling AppendWORM to produce anchors and VerifyChain to check them.
// masterKeyHex is the hex-encoded Ed25519 private key (CITADEL_MASTER_KEY,
// see internal/config); an empty string leaves anchor signing disabled
// (matches config.WarnIfInsecure's warning) while still recording
// interval so AppendWORM can log a clear warning every time an anchor
// boundary is crossed without a key configured, rather than silently
// producing no anchors. interval <= 0 falls back to the documented default
// of 100 WORM entries between anchors.
//
// Call this once after db.New, before serving traffic — see
// cmd/citadel/main.go. Not calling it at all (as most existing tests and
// benchmarks do) leaves anchoring completely unconfigured: AppendWORM skips
// the anchor step silently and VerifyChain treats "no anchors found" as
// AnchorVerified: true, identical to pre-anchor behavior.
func (d *DB) ConfigureAnchoring(masterKeyHex string, interval int) error {
	if interval <= 0 {
		interval = 100
	}
	d.anchorInterval = interval

	if masterKeyHex == "" {
		d.anchorKey = nil
		return nil
	}

	keyBytes, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return fmt.Errorf("db: ConfigureAnchoring: master key is not valid hex: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("db: ConfigureAnchoring: master key must be %d bytes (got %d) — expected an Ed25519 private key as produced by `citadel keygen`", ed25519.PrivateKeySize, len(keyBytes))
	}
	d.anchorKey = ed25519.PrivateKey(keyBytes)
	return nil
}

// AppendWORM inserts a new entry into the WORM chain.
// It reads the last chain_hash, computes the new chain_hash and triple_hash,
// then inserts atomically. Returns the completed WORMEntry.
func (d *DB) AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte, sigOperator, sigVerifier string) (*WORMEntry, error) {
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
			 payload, triple_hash, chain_hash, prev_hash, sig_operator, sig_verifier, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id, seqNum, now, source, eventType, projectID,
		payload, th, ch, prevHash, nullIfEmpty(sigOperator), nullIfEmpty(sigVerifier), now,
	)
	if err != nil {
		return nil, fmt.Errorf("worm: insert entry: %w", err)
	}

	// Anchor production: every AnchorInterval-th entry, sign chain_hash with
	// the Ed25519 master key and record it in `anchors`, in the same
	// transaction as the append — an anchor must never exist for an entry
	// that didn't actually commit, and vice versa. See ConfigureAnchoring.
	if d.anchorInterval > 0 && seqNum%int64(d.anchorInterval) == 0 {
		if d.anchorKey == nil {
			// Anchoring is configured (interval known) but no master key is
			// present — this must be loud, not silent: an auditor walking
			// the chain later needs to know this boundary has no
			// cryptographic anchor coverage by policy, not by bug.
			log.Printf("WARNING: worm: sequence_num=%d crossed the anchor interval boundary (every %d entries) but CITADEL_MASTER_KEY is not configured — no anchor was produced for this boundary", seqNum, d.anchorInterval)
		} else {
			sig := ed25519.Sign(d.anchorKey, []byte(ch))
			sigHex := hex.EncodeToString(sig)
			_, err = tx.Exec(ctx,
				`INSERT INTO anchors (sequence_num, chain_hash, ed25519_sig) VALUES ($1,$2,$3)`,
				seqNum, ch, sigHex,
			)
			if err != nil {
				return nil, fmt.Errorf("worm: insert anchor: %w", err)
			}
		}
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
		SigOperator: sigOperator,
		SigVerifier: sigVerifier,
		CreatedAt:   now,
	}, nil
}

// nullIfEmpty converts an empty string to nil so it is stored as SQL NULL
// rather than an empty-string TEXT value, keeping "unsigned" distinguishable
// from "signed with an empty signature" (which should never happen, but NULL
// is the correct representation of "not present").
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
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
		// No entries in range means no anchors can fall in range either —
		// nothing contradicts the (empty) chain, so AnchorVerified is true,
		// not a false negative.
		return &VerifyResult{Valid: true, EntriesVerified: 0, AnchorVerified: true}, nil
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

	// The linear chain walk above passed for every entry in range. Now
	// cross-check any Ed25519 anchors that fall within [minSeq, maxSeq] —
	// this is what catches a DB-level attacker who rewrites chain_hashes
	// consistently enough to fool the linear walk but cannot also forge the
	// anchor signatures.
	anchorResult, err := d.verifyAnchors(ctx, entries[0].SeqNum, entries[len(entries)-1].SeqNum)
	if err != nil {
		return nil, err
	}
	if !anchorResult.ok {
		return &VerifyResult{
			Valid:           false,
			EntriesVerified: len(entries),
			BreakAt:         anchorResult.breakAt,
			AnchorVerified:  false,
		}, nil
	}

	return &VerifyResult{
		Valid:           true,
		EntriesVerified: len(entries),
		AnchorVerified:  true,
	}, nil
}

// anchorVerifyOutcome is the internal result of verifyAnchors.
type anchorVerifyOutcome struct {
	ok      bool
	breakAt string
}

// verifyAnchors checks every `anchors` row whose sequence_num falls in
// [minSeq, maxSeq] against two independent things: (1) the Ed25519
// signature is valid over the anchor's claimed chain_hash, using the
// public half of the configured master key, and (2) the anchor's claimed
// chain_hash actually matches the real, current chain_hash of that
// sequence_num in worm_entries — a stale or mismatched anchor is itself a
// tamper signal even if its own signature checks out (e.g. an attacker who
// rewrote worm_entries but left an old, validly-signed anchor in place).
//
// A range with zero anchors is not a failure: ok=true, matching "nothing
// contradicts the chain" rather than a false negative.
func (d *DB) verifyAnchors(ctx context.Context, minSeq, maxSeq int64) (anchorVerifyOutcome, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT a.sequence_num, a.chain_hash, a.ed25519_sig, w.chain_hash
		FROM anchors a
		JOIN worm_entries w ON w.sequence_num = a.sequence_num
		WHERE a.sequence_num BETWEEN $1 AND $2
		ORDER BY a.sequence_num ASC`,
		minSeq, maxSeq,
	)
	if err != nil {
		return anchorVerifyOutcome{}, fmt.Errorf("worm: verify anchors query: %w", err)
	}
	defer rows.Close()

	var pub ed25519.PublicKey
	if d.anchorKey != nil {
		pub = d.anchorKey.Public().(ed25519.PublicKey) //nolint:errcheck // ed25519.PrivateKey.Public() always returns ed25519.PublicKey; check-type-assertions is what flags this, not forcetypeassert
	}

	for rows.Next() {
		var seq int64
		var claimedHash, sigHex, realHash string
		if err := rows.Scan(&seq, &claimedHash, &sigHex, &realHash); err != nil {
			return anchorVerifyOutcome{}, fmt.Errorf("worm: verify anchors scan: %w", err)
		}

		if pub == nil {
			// Anchors exist in range but this instance has no master key
			// configured to check them against — fail closed rather than
			// silently reporting "verified" for something that was never
			// actually checked.
			return anchorVerifyOutcome{
				ok:      false,
				breakAt: fmt.Sprintf("sequence_num=%d: anchor present but no CITADEL_MASTER_KEY configured to verify it", seq),
			}, nil
		}

		if !marshal.VerifySignature(pub, claimedHash, sigHex) {
			return anchorVerifyOutcome{
				ok:      false,
				breakAt: fmt.Sprintf("sequence_num=%d: anchor ed25519_sig does not verify against its chain_hash", seq),
			}, nil
		}

		if claimedHash != realHash {
			return anchorVerifyOutcome{
				ok:      false,
				breakAt: fmt.Sprintf("sequence_num=%d: anchor chain_hash does not match worm_entries chain_hash", seq),
			}, nil
		}
	}
	if rows.Err() != nil {
		return anchorVerifyOutcome{}, fmt.Errorf("worm: verify anchors rows: %w", rows.Err())
	}

	return anchorVerifyOutcome{ok: true}, nil
}

// GetLastChainHash returns the chain_hash of the most recent WORM entry.
// Returns the genesis hash if no entries exist.
func (d *DB) GetLastChainHash(ctx context.Context) (string, error) {
	var ch string
	err := d.Pool.QueryRow(ctx,
		`SELECT chain_hash FROM worm_entries ORDER BY sequence_num DESC LIMIT 1`,
	).Scan(&ch)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return genesisHash(), nil
		}
		// A real query/connection failure must not be silently reported as
		// "empty chain, use genesis" — a caller anchoring a new entry off a
		// fabricated genesis hash during a DB outage would corrupt chain
		// continuity instead of failing loudly.
		return "", fmt.Errorf("db: GetLastChainHash: query: %w", err)
	}
	return ch, nil
}

// genesisHash returns SHA-256("CITADEL-GENESIS-SIN-v1") as hex.
func genesisHash() string {
	h := sha256.Sum256([]byte("CITADEL-GENESIS-SIN-v1"))
	return hex.EncodeToString(h[:])
}
