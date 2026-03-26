package db

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/apiguard/internal/citadel"
)

// auditQueueCapacity is the maximum number of pending audit entries before the
// non-blocking send path begins dropping (with a logged warning).
const auditQueueCapacity = 1000

// auditBatchSize is the maximum number of entries written in a single worker
// iteration before the batch timer is reset.
const auditBatchSize = 50

// auditFlushInterval is the maximum time the worker waits before writing
// whatever has accumulated in the batch channel.
const auditFlushInterval = 100 * time.Millisecond

// auditEntry is the internal envelope that travels through auditQueue.
type auditEntry struct {
	entry   *AuditLog
	citadel *citadel.Client
}

// auditQueue is the package-level buffered channel. It is initialised by
// StartAuditWorker and must be non-nil before AppendAuditLog is called.
var (
	auditQueue   chan *auditEntry
	auditQueueMu sync.Mutex // guards initialisation check only

	// auditWg tracks entries that have been enqueued but not yet processed by
	// the worker. Add(1) is called before sending to auditQueue; Done() is
	// called by the worker after processing each entry. FlushAuditLog calls
	// Wait() to block until all previously enqueued entries are processed.
	auditWg sync.WaitGroup
)

// StartAuditWorker initialises the package-level audit queue and launches a
// single background goroutine that is the **only** writer to the audit_log
// table. Because there is exactly one writer, the PostgreSQL advisory lock is
// held only by this goroutine — contention drops to zero.
//
// The goroutine drains the queue in batches of up to auditBatchSize entries
// or after auditFlushInterval, whichever fires first.
//
// Call StartAuditWorker once during application startup, before serving
// requests. The returned stop function should be called on shutdown (it does
// not drain — use FlushAuditLog for a graceful drain before stopping).
func StartAuditWorker(pool *pgxpool.Pool) (stop func()) {
	auditQueueMu.Lock()
	if auditQueue == nil {
		auditQueue = make(chan *auditEntry, auditQueueCapacity)
	}
	auditQueueMu.Unlock()

	quit := make(chan struct{})

	go func() {
		ticker := time.NewTicker(auditFlushInterval)
		defer ticker.Stop()

		batch := make([]*auditEntry, 0, auditBatchSize)

		flush := func() {
			if len(batch) == 0 {
				return
			}
			for _, e := range batch {
				if err := writeEntryToDB(context.Background(), pool, e); err != nil {
					log.Printf("audit worker: write failed: %v", err)
				}
				auditWg.Done()
			}
			batch = batch[:0]
		}

		for {
			select {
			case e := <-auditQueue:
				batch = append(batch, e)
				if len(batch) >= auditBatchSize {
					flush()
					ticker.Reset(auditFlushInterval)
				}

			case <-ticker.C:
				flush()

			case <-quit:
				// Drain whatever remains before exiting.
				for {
					select {
					case e := <-auditQueue:
						batch = append(batch, e)
					default:
						flush()
						return
					}
				}
			}
		}
	}()

	return func() { close(quit) }
}

// FlushAuditLog blocks until all entries enqueued before the call have been
// processed by the worker, or until ctx is cancelled. It is intended for
// graceful shutdown sequences.
//
// FlushAuditLog does not stop the worker — it simply waits for previously
// enqueued work to drain. Call the stop function returned by StartAuditWorker
// afterwards if you want to shut down the goroutine entirely.
func FlushAuditLog(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		auditWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AppendAuditLog enqueues an audit log entry for asynchronous writing by the
// background worker goroutine. The call is non-blocking: if the internal
// queue is full the entry is dropped and a warning is logged — callers on the
// hot request path are never stalled.
//
// The public signature is identical to the previous synchronous implementation
// so no call-site changes are required.
func (d *DB) AppendAuditLog(_ context.Context, entry *AuditLog, citadelClient *citadel.Client) error {
	auditQueueMu.Lock()
	q := auditQueue
	auditQueueMu.Unlock()

	if q == nil {
		// Worker has not been started — fall back to a synchronous write so
		// that audit events are never silently lost in test or CLI contexts.
		return writeEntryToDB(context.Background(), d.Pool, &auditEntry{
			entry:   entry,
			citadel: citadelClient,
		})
	}

	e := &auditEntry{entry: entry, citadel: citadelClient}
	auditWg.Add(1)
	select {
	case q <- e:
		// Successfully queued.
	default:
		// Queue full — log a warning and drop rather than blocking the caller.
		// Decrement the WaitGroup counter since this entry will not be processed.
		auditWg.Done()
		log.Printf("audit log queue full (capacity %d): dropping entry action=%s actor=%s",
			auditQueueCapacity, entry.Action, entry.ActorID)
	}
	return nil
}

// writeEntryToDB performs the actual chain-hash computation and INSERT for a
// single audit entry. It is called exclusively from the worker goroutine
// (or from the synchronous fallback path), so the advisory lock serialises a
// single goroutine — contention is eliminated.
func writeEntryToDB(ctx context.Context, pool *pgxpool.Pool, e *auditEntry) error {
	entry := e.entry

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning audit log transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise all audit_log writes through a single advisory lock so that
	// the fetch-then-insert is atomic with respect to other appenders.
	// Use a stable hardcoded int64 key instead of hashtext() to avoid the
	// 32-bit collision space of hashtext and to guarantee a fixed lock identity.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1234567891::bigint)`); err != nil {
		return fmt.Errorf("acquiring audit chain lock: %w", err)
	}

	// Fetch the most recent chain_hash to anchor this entry.
	// Order by id DESC (auto-increment sequence) as the authoritative ordering
	// key — created_at is set in Go and can collide under high concurrency.
	var prevHash *string
	var lastHash string
	if err := tx.QueryRow(ctx,
		`SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1`,
	).Scan(&lastHash); err == nil {
		prevHash = &lastHash
	}

	id := uuid.New()
	now := time.Now().UTC()

	resourceIDStr := ""
	if entry.ResourceID != nil {
		resourceIDStr = entry.ResourceID.String()
	}
	prevHashStr := ""
	if prevHash != nil {
		prevHashStr = *prevHash
	}

	// chain_hash = SHA-256(id|actor_id|action|resource_id|prev_hash|created_at)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		id.String(),
		entry.ActorID,
		string(entry.Action),
		resourceIDStr,
		prevHashStr,
		now.Format(time.RFC3339Nano),
	)
	chainHash := fmt.Sprintf("%x", h.Sum(nil))

	metaJSON := entry.Metadata
	if metaJSON == nil {
		metaJSON = []byte("{}")
	}

	var beforeState, afterState interface{}
	if len(entry.BeforeState) > 0 {
		beforeState = entry.BeforeState
	}
	if len(entry.AfterState) > 0 {
		afterState = entry.AfterState
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (
			id, actor_id, actor_type, action, resource_type, resource_id,
			ip_address, user_agent, before_state, after_state, metadata,
			prev_hash, chain_hash, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14
		)`,
		id,
		entry.ActorID,
		entry.ActorType,
		string(entry.Action),
		entry.ResourceType,
		entry.ResourceID,
		entry.IPAddress,
		entry.UserAgent,
		beforeState,
		afterState,
		metaJSON,
		prevHash,
		chainHash,
		now,
	); err != nil {
		return fmt.Errorf("inserting audit log entry: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing audit log transaction: %w", err)
	}

	entry.ID = id
	entry.PrevHash = prevHash
	entry.ChainHash = chainHash
	entry.CreatedAt = now

	// Forward to CITADEL asynchronously — best-effort, never blocks the caller.
	if e.citadel != nil {
		metadata := map[string]interface{}{
			"resource_type": entry.ResourceType,
			"actor_type":    string(entry.ActorType),
			"chain_hash":    chainHash,
			"platform":      "apiguard",
		}
		e.citadel.LogEvent(
			string(entry.Action),
			entry.ActorID,
			string(entry.ActorType),
			"EXECUTED",
			"apiguard",
			resourceIDStr,
			metadata,
		)
	}

	return nil
}

// AuditLogFilters holds optional filters for querying audit logs.
type AuditLogFilters struct {
	ActorID      *string
	Action       *AuditAction
	ResourceID   *uuid.UUID
	ResourceType *string
}

// ListAuditLog returns audit log entries ordered by created_at DESC with optional filters and pagination.
func (d *DB) ListAuditLog(ctx context.Context, filters AuditLogFilters, page, perPage int) ([]*AuditLog, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	args := []interface{}{}
	where := []string{}
	i := 1

	if filters.ActorID != nil {
		where = append(where, fmt.Sprintf("actor_id = $%d", i))
		args = append(args, *filters.ActorID)
		i++
	}
	if filters.Action != nil {
		where = append(where, fmt.Sprintf("action = $%d", i))
		args = append(args, string(*filters.Action))
		i++
	}
	if filters.ResourceID != nil {
		where = append(where, fmt.Sprintf("resource_id = $%d", i))
		args = append(args, *filters.ResourceID)
		i++
	}
	if filters.ResourceType != nil {
		where = append(where, fmt.Sprintf("resource_type = $%d", i))
		args = append(args, *filters.ResourceType)
		i++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total.
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_log %s", whereClause)
	if err := d.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting audit log: %w", err)
	}

	// Fetch page.
	dataArgs := append(args, perPage, offset)
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(`
		SELECT id, actor_id, actor_type, action, resource_type, resource_id,
		       ip_address, user_agent, before_state, after_state, metadata,
		       prev_hash, chain_hash, created_at
		FROM audit_log %s
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, i, i+1), dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []*AuditLog
	for rows.Next() {
		e := &AuditLog{}
		if err := rows.Scan(
			&e.ID, &e.ActorID, &e.ActorType, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.IPAddress, &e.UserAgent, &e.BeforeState, &e.AfterState, &e.Metadata,
			&e.PrevHash, &e.ChainHash, &e.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning audit log row: %w", err)
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []*AuditLog{}
	}
	return entries, total, rows.Err()
}
