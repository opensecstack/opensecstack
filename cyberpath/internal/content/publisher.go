// Package content — publisher.go materialises a validated, hashed
// TrackYAML into the runtime tables (tracks, modules, lessons,
// quizzes, quiz_questions, lab_definitions) plus the append-only
// content_versions table, all inside a single transaction.
//
// The publisher is store-interface agnostic — it consumes any types
// that satisfy the small interfaces declared at the bottom of this
// file. Sibling agents writing internal/db/{quiz,lab,…}_store.go can
// supply concrete types that implement these interfaces, or the
// publisher can drive raw SQL via the pgx pool when a store is not
// yet wired.
package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publisher writes validated tracks into the database. Sibling stores
// are referenced via narrow interfaces so this package compiles
// independently while siblings finalise their store APIs.
type Publisher struct {
	Pool   *pgxpool.Pool
	Audit  AuditLogger
	Outbox OutboxEnqueuer // optional
	// Strict, when true, refuses to publish a track that has any
	// "error" severity validation diagnostics. Default true.
	Strict bool
}

// NewPublisher constructs a Publisher with strict mode on by default.
func NewPublisher(pool *pgxpool.Pool, audit AuditLogger, outbox OutboxEnqueuer) *Publisher {
	return &Publisher{Pool: pool, Audit: audit, Outbox: outbox, Strict: true}
}

// Publish materialises t into the runtime + content_versions tables.
//
// Steps:
//  1. Validate; refuse on any "error" severity (when Strict).
//  2. Compute content_hash for track / lab / quiz / lesson.
//  3. Open a transaction.
//  4. INSERT content_versions for the track + every nested entity.
//  5. UPSERT into tracks / modules / lessons / quizzes /
//     quiz_questions / lab_definitions.
//  6. Commit, then emit audit_event("track.published") and enqueue the
//     `cyberpath.track_published` outbox event (best-effort).
func (p *Publisher) Publish(ctx context.Context, t *TrackYAML, publishedBy uuid.UUID) error {
	const op = "publisher.Publish"
	if t == nil {
		return fmt.Errorf("content/%s: track is nil", op)
	}
	if p.Pool == nil {
		return fmt.Errorf("content/%s: pool is nil", op)
	}

	diags := ValidateTrack(t)
	if p.Strict {
		for _, d := range diags {
			if d.Severity == "error" {
				return fmt.Errorf("content/%s: validation failed: %s", op, summariseErrors(diags))
			}
		}
	}

	t.ContentHash = HashTrack(t)
	for i := range t.Modules {
		if t.Modules[i].Lab != nil && t.Modules[i].Lab.Lab != nil {
			t.Modules[i].Lab.Lab.ContentHash = HashLab(t.Modules[i].Lab.Lab)
		}
	}

	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("content/%s: begin tx: %w", op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	trackUUID, err := upsertTrack(ctx, tx, t)
	if err != nil {
		return fmt.Errorf("content/%s: %w", op, err)
	}
	versionInt := parseVersionMajor(t.Version)
	trackPayload, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("content/%s: marshal track: %w", op, err)
	}
	if err := insertContentVersion(ctx, tx, "track", t.ID, versionInt, t.ContentHash, trackPayload, publishedBy); err != nil {
		return fmt.Errorf("content/%s: %w", op, err)
	}

	for i := range t.Modules {
		m := &t.Modules[i]
		modUUID, err := upsertModule(ctx, tx, trackUUID, m)
		if err != nil {
			return fmt.Errorf("content/%s: module %q: %w", op, m.ID, err)
		}
		modPayload, _ := json.Marshal(m)
		modHash := HashLesson(string(modPayload)) // module hash = sha256 of its own payload
		if err := insertContentVersion(ctx, tx, "module", m.ID, 1, modHash, modPayload, publishedBy); err != nil {
			return fmt.Errorf("content/%s: module %q version: %w", op, m.ID, err)
		}

		for j := range m.Lessons {
			l := &m.Lessons[j]
			body := l.BodySQ
			if body == "" {
				body = l.BodyEN
			}
			hash := HashLesson(body)
			lessonUUID, err := upsertLesson(ctx, tx, modUUID, l)
			if err != nil {
				return fmt.Errorf("content/%s: lesson %q: %w", op, l.ID, err)
			}
			lessonPayload, _ := json.Marshal(l)
			if err := insertContentVersion(ctx, tx, "lesson", l.ID, 1, hash, lessonPayload, publishedBy); err != nil {
				return fmt.Errorf("content/%s: lesson %q version: %w", op, l.ID, err)
			}
			_ = lessonUUID // future: link lesson UUID into outbox payload
		}

		if m.Quiz != nil {
			quizHash := HashQuiz(m.Quiz)
			quizPayload, _ := json.Marshal(m.Quiz)
			quizUUID, err := upsertQuiz(ctx, tx, trackUUID, m.Quiz, quizHash)
			if err != nil {
				return fmt.Errorf("content/%s: quiz %q: %w", op, m.Quiz.ID, err)
			}
			if err := upsertQuizQuestions(ctx, tx, quizUUID, m.Quiz.Questions); err != nil {
				return fmt.Errorf("content/%s: quiz %q questions: %w", op, m.Quiz.ID, err)
			}
			if err := insertContentVersion(ctx, tx, "quiz", m.Quiz.ID, 1, quizHash, quizPayload, publishedBy); err != nil {
				return fmt.Errorf("content/%s: quiz %q version: %w", op, m.Quiz.ID, err)
			}
		}

		if m.Lab != nil && m.Lab.Lab != nil {
			lab := m.Lab.Lab
			labHash := HashLab(lab)
			labPayload, _ := json.Marshal(lab)
			if err := upsertLabDefinition(ctx, tx, trackUUID, lab, labHash); err != nil {
				return fmt.Errorf("content/%s: lab %q: %w", op, lab.ID, err)
			}
			if err := insertContentVersion(ctx, tx, "lab", lab.ID, parseVersionMajor(lab.Version), labHash, labPayload, publishedBy); err != nil {
				return fmt.Errorf("content/%s: lab %q version: %w", op, lab.ID, err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("content/%s: commit: %w", op, err)
	}

	// Audit + outbox are best-effort post-commit.
	if p.Audit != nil {
		_ = p.Audit.Log(ctx, AuditEvent{
			Action:     "track.published",
			ActorID:    publishedBy,
			TargetType: "track",
			TargetID:   t.ID,
			Outcome:    "success",
			Metadata: map[string]any{
				"version":      t.Version,
				"content_hash": t.ContentHash,
			},
		})
	}
	if p.Outbox != nil {
		_ = p.Outbox.Enqueue(ctx, OutboxEvent{
			EventType: "cyberpath.track_published",
			Payload: map[string]any{
				"track_id":     t.ID,
				"version":      t.Version,
				"content_hash": t.ContentHash,
				"published_by": publishedBy.String(),
			},
		})
	}

	return nil
}

// PublishAll scans dir and publishes each track found. Returns the
// count of successful publishes.
func (p *Publisher) PublishAll(ctx context.Context, dir string, byUser uuid.UUID) (int, error) {
	const op = "publisher.PublishAll"
	tracks, err := LoadAllTracks(dir)
	if err != nil {
		return 0, fmt.Errorf("content/%s: %w", op, err)
	}
	count := 0
	for _, t := range tracks {
		if err := p.Publish(ctx, t, byUser); err != nil {
			return count, fmt.Errorf("content/%s: track %q: %w", op, t.ID, err)
		}
		count++
	}
	return count, nil
}

// ── SQL helpers ───────────────────────────────────────────────────────

// insertContentVersion appends an immutable snapshot row.
//
// The unique constraint on (entity_type, entity_id, version) means
// re-publishing an unchanged version is a no-op (ON CONFLICT DO
// NOTHING); a content change MUST bump the version field for a new
// row to land. This is the audit-immutability guarantee from
// migration 0004.
func insertContentVersion(ctx context.Context, tx pgx.Tx, entityType, entityID string, version int, hash string, payload []byte, publishedBy uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO content_versions (entity_type, entity_id, version, content_hash, payload, published_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (entity_type, entity_id, version) DO NOTHING`,
		entityType, entityID, version, hash, payload, nullableUUID(publishedBy))
	if err != nil {
		return fmt.Errorf("insert content_versions(%s/%s@%d): %w", entityType, entityID, version, err)
	}
	return nil
}

// upsertTrack inserts/updates the runtime tracks row keyed by slug
// and returns its uuid.
func upsertTrack(ctx context.Context, tx pgx.Tx, t *TrackYAML) (uuid.UUID, error) {
	var id uuid.UUID
	row := tx.QueryRow(ctx, `
		INSERT INTO tracks (slug, title, description, locale, tags, nis2_refs, published, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, TRUE, now())
		ON CONFLICT (slug) DO UPDATE SET
			title       = EXCLUDED.title,
			description = EXCLUDED.description,
			locale      = EXCLUDED.locale,
			tags        = EXCLUDED.tags,
			nis2_refs   = EXCLUDED.nis2_refs,
			published   = TRUE,
			updated_at  = now()
		RETURNING id`,
		t.ID,
		nonEmpty(t.TitleSQ, t.TitleEN),
		nonEmpty(t.DescriptionSQ, t.DescriptionEN),
		"sq",
		t.Audience,
		t.NIS2Mappings,
	)
	if err := row.Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("upsert tracks: %w", err)
	}
	return id, nil
}

func upsertModule(ctx context.Context, tx pgx.Tx, trackID uuid.UUID, m *ModuleYAML) (uuid.UUID, error) {
	var id uuid.UUID
	row := tx.QueryRow(ctx, `
		INSERT INTO modules (track_id, slug, title, ord)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (track_id, slug) DO UPDATE SET
			title = EXCLUDED.title,
			ord   = EXCLUDED.ord
		RETURNING id`,
		trackID, m.ID, nonEmpty(m.TitleSQ, m.TitleEN), m.Order,
	)
	if err := row.Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("upsert modules: %w", err)
	}
	return id, nil
}

func upsertLesson(ctx context.Context, tx pgx.Tx, moduleID uuid.UUID, l *LessonYAML) (uuid.UUID, error) {
	var id uuid.UUID
	body := l.BodySQ
	if body == "" {
		body = l.BodyEN
	}
	locale := "sq"
	if l.BodySQ == "" {
		locale = "en"
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO lessons (module_id, slug, title, locale, body_md, ord, duration_min)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (module_id, slug, locale) DO UPDATE SET
			title        = EXCLUDED.title,
			body_md      = EXCLUDED.body_md,
			ord          = EXCLUDED.ord,
			duration_min = EXCLUDED.duration_min
		RETURNING id`,
		moduleID, l.ID, nonEmpty(l.TitleSQ, l.TitleEN), locale, body, l.Order, maxInt(1, l.EstimatedMinutes),
	)
	if err := row.Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("upsert lessons: %w", err)
	}
	return id, nil
}

func upsertQuiz(ctx context.Context, tx pgx.Tx, trackID uuid.UUID, q *QuizYAML, hash string) (uuid.UUID, error) {
	// We anchor quizzes at track-level here; lesson-level anchoring
	// happens when the quiz YAML carries a lesson reference (future
	// work — schema already supports it).
	var id uuid.UUID
	var timeLimit any
	if q.TimeLimitSeconds != nil {
		timeLimit = *q.TimeLimitSeconds
	}
	// Match-by (track_id, title_en) for upsert, since the quiz table
	// has no slug column.
	row := tx.QueryRow(ctx, `
		WITH upsert AS (
			SELECT id FROM quizzes
			WHERE track_id = $1 AND title_en = $3
			LIMIT 1
		),
		ins AS (
			INSERT INTO quizzes (track_id, title_sq, title_en, pass_threshold, time_limit_seconds, content_hash, updated_at)
			SELECT $1, $2, $3, $4, $5, $6, now()
			WHERE NOT EXISTS (SELECT 1 FROM upsert)
			RETURNING id
		),
		upd AS (
			UPDATE quizzes SET
				title_sq           = $2,
				title_en           = $3,
				pass_threshold     = $4,
				time_limit_seconds = $5,
				content_hash       = $6,
				updated_at         = now()
			WHERE id IN (SELECT id FROM upsert)
			RETURNING id
		)
		SELECT id FROM ins
		UNION ALL
		SELECT id FROM upd`,
		trackID, q.TitleSQ, q.TitleEN, q.PassThreshold, timeLimit, hash,
	)
	if err := row.Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("upsert quizzes: %w", err)
	}
	return id, nil
}

func upsertQuizQuestions(ctx context.Context, tx pgx.Tx, quizID uuid.UUID, qs []QuestionYAML) error {
	// Replace-all semantics: clear then insert. quiz_questions has no
	// natural slug-key, so we rebuild on every publish.
	if _, err := tx.Exec(ctx, `DELETE FROM quiz_questions WHERE quiz_id = $1`, quizID); err != nil {
		return fmt.Errorf("clear quiz_questions: %w", err)
	}
	for i, q := range qs {
		choices, _ := json.Marshal(q.Choices)
		correct := q.Correct
		if len(correct) == 0 {
			correct = json.RawMessage("null")
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO quiz_questions (
				quiz_id, position, kind, prompt_sq, prompt_en,
				choices, correct, explanation_sq, explanation_en, points
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			quizID, i+1, q.Kind, q.PromptSQ, q.PromptEN,
			choices, []byte(correct), q.ExplanationSQ, q.ExplanationEN, maxInt(1, q.Points),
		)
		if err != nil {
			return fmt.Errorf("insert question %q: %w", q.ID, err)
		}
	}
	return nil
}

func upsertLabDefinition(ctx context.Context, tx pgx.Tx, trackID uuid.UUID, lab *LabYAML, hash string) error {
	runtime := normaliseLabRuntime(lab.Runtime)
	assets, _ := json.Marshal(lab.Assets)
	validation, _ := json.Marshal(lab.Validation)
	egress, _ := json.Marshal(lab.EgressWhitelist)
	hints, _ := json.Marshal(lab.Hints)
	successJSON, _ := json.Marshal(lab.SuccessCriteria)
	_, err := tx.Exec(ctx, `
		INSERT INTO lab_definitions (
			id, track_id, runtime, image, entry_command, assets,
			validation, time_limit_seconds, egress_whitelist,
			success_criteria, hints, version, content_hash, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
		ON CONFLICT (id) DO UPDATE SET
			track_id           = EXCLUDED.track_id,
			runtime            = EXCLUDED.runtime,
			image              = EXCLUDED.image,
			entry_command      = EXCLUDED.entry_command,
			assets             = EXCLUDED.assets,
			validation         = EXCLUDED.validation,
			time_limit_seconds = EXCLUDED.time_limit_seconds,
			egress_whitelist   = EXCLUDED.egress_whitelist,
			success_criteria   = EXCLUDED.success_criteria,
			hints              = EXCLUDED.hints,
			version            = EXCLUDED.version,
			content_hash       = EXCLUDED.content_hash,
			updated_at         = now()`,
		lab.ID, trackID, runtime, lab.Image, lab.EntryCommand, assets,
		validation, maxInt(1, lab.TimeLimitSeconds), egress,
		string(successJSON), hints, parseVersionMajor(lab.Version), hash,
	)
	if err != nil {
		return fmt.Errorf("upsert lab_definitions: %w", err)
	}
	return nil
}

// normaliseLabRuntime collapses the wasm-* sub-runtimes onto the DB
// enum value `wasmtime` (see migration 0003).
func normaliseLabRuntime(r string) string {
	switch r {
	case "docker":
		return "docker"
	case "wasmtime", "wasm-shell", "wasm-python", "wasm-kubectl":
		return "wasmtime"
	default:
		return r
	}
}

// parseVersionMajor extracts the leading integer from "1.4.0" → 1.
// Migration 0004's content_versions.version is INT, so we collapse
// semver to its major component for the row key. The full string is
// retained inside payload.
func parseVersionMajor(v string) int {
	if v == "" {
		return 1
	}
	parts := strings.SplitN(v, ".", 2)
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 1
	}
	if n < 1 {
		// Pre-1.0 tracks (e.g. 1.0.0) still need a positive version
		// row; we encode them as version=1 in content_versions and
		// distinguish via the payload's full semver string.
		return 1
	}
	return n
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// nullableUUID returns nil for the zero uuid (so SQL records NULL).
func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func summariseErrors(diags []ValidationError) string {
	parts := make([]string, 0, len(diags))
	for _, d := range diags {
		if d.Severity == "error" {
			parts = append(parts, d.Error())
		}
	}
	if len(parts) == 0 {
		return "no errors"
	}
	return strings.Join(parts, "; ")
}

// ── store interfaces (sibling-friendly) ───────────────────────────────

// AuditEvent is the subset of audit_events fields the publisher emits.
type AuditEvent struct {
	Action     string
	ActorID    uuid.UUID
	TargetType string
	TargetID   string
	Outcome    string
	Metadata   map[string]any
}

// AuditLogger is satisfied by the (sibling-owned) audit store.
type AuditLogger interface {
	Log(ctx context.Context, e AuditEvent) error
}

// OutboxEvent is the subset of outbox fields the publisher emits.
type OutboxEvent struct {
	EventType string
	Payload   map[string]any
}

// OutboxEnqueuer is satisfied by the (sibling-owned) outbox store.
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, e OutboxEvent) error
}

// Sentinel returned by Publisher.Publish when validation refuses.
var ErrValidationFailed = errors.New("content validation failed")
