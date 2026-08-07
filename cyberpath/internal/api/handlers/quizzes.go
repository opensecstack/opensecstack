// Quiz submission handler. v1.0.0 scores answers against the stored answer
// key; v0.0.1 stub (SubmitQuiz) is retained at the bottom as a fallback.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── Interfaces ────────────────────────────────────────────────────────────────

// QuizGetter is the read slice of QuizStore the handler depends on.
type QuizGetter interface {
	Get(ctx context.Context, id uuid.UUID) (*db.Quiz, []db.QuizQuestion, error)
}

// ── Handler struct ────────────────────────────────────────────────────────────

// QuizHandler serves /quizzes routes from the DB.
type QuizHandler struct {
	Quizzes  QuizGetter
	Progress ProgressUpserter // defined in lessons.go
	Audit    *db.AuditEventStore
	Logger   *zerolog.Logger
}

// NewQuizHandler wires a QuizHandler.
func NewQuizHandler(quizzes QuizGetter, progress ProgressUpserter, audit *db.AuditEventStore, logger *zerolog.Logger) *QuizHandler {
	return &QuizHandler{Quizzes: quizzes, Progress: progress, Audit: audit, Logger: logger}
}

// ── Get handler ───────────────────────────────────────────────────────────────

// quizResponse is the response body for GET /quizzes/{id}.
// The correct answer is intentionally omitted — clients must not receive it.
type quizResponse struct {
	ID               string             `json:"id"`
	LessonID         *string            `json:"lesson_id,omitempty"`
	TrackID          *string            `json:"track_id,omitempty"`
	TitleEN          string             `json:"title_en"`
	TitleSQ          string             `json:"title_sq"`
	PassThreshold    int                `json:"pass_threshold"`
	TimeLimitSeconds *int               `json:"time_limit_seconds,omitempty"`
	Questions        []questionResponse `json:"questions"`
}

// questionResponse is a single question in the GET /quizzes/{id} response.
// The correct answer is NOT included — it is server-side only.
type questionResponse struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	PromptEN  string          `json:"prompt_en"`
	PromptSQ  string          `json:"prompt_sq"`
	Choices   json.RawMessage `json:"choices,omitempty"`
	Points    int             `json:"points"`
}

// Get handles GET /quizzes/{id}.
// Questions are shuffled on every request so that repeated attempts see a
// different ordering. Answer scoring in Submit() uses question ID + answer
// key — not position — so shuffling does not affect correctness checking.
func (h *QuizHandler) Get(w http.ResponseWriter, r *http.Request) {
	rawID := chi.URLParam(r, "id")
	qid, err := uuid.Parse(rawID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "quiz id must be a UUID")
		return
	}

	quiz, questions, err := h.Quizzes.Get(r.Context(), qid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "quiz_not_found", "no quiz with id "+rawID)
			return
		}
		h.log().Error().Err(err).Str("quiz_id", rawID).Msg("quizzes.get: get quiz")
		writeError(w, http.StatusInternalServerError, "internal_error", "quiz lookup failed")
		return
	}

	// Shuffle questions for each request so repeated attempts see a different
	// order. Scoring is by question ID, so position changes are safe.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(questions), func(i, j int) {
		questions[i], questions[j] = questions[j], questions[i]
	})

	// Build the response, omitting the correct answer field.
	qrs := make([]questionResponse, len(questions))
	for i, q := range questions {
		qrs[i] = questionResponse{
			ID:       q.ID.String(),
			Kind:     q.Kind,
			PromptEN: q.PromptEN,
			PromptSQ: q.PromptSQ,
			Choices:  q.Choices,
			Points:   q.Points,
		}
	}

	resp := quizResponse{
		ID:               quiz.ID.String(),
		TitleEN:          quiz.TitleEN,
		TitleSQ:          quiz.TitleSQ,
		PassThreshold:    quiz.PassThreshold,
		TimeLimitSeconds: quiz.TimeLimitSeconds,
		Questions:        qrs,
	}
	if quiz.LessonID != nil {
		s := quiz.LessonID.String()
		resp.LessonID = &s
	}
	if quiz.TrackID != nil {
		s := quiz.TrackID.String()
		resp.TrackID = &s
	}

	writeJSON(w, http.StatusOK, resp)
}

// ── Request / response types ──────────────────────────────────────────────────

// submitRequest is the decoded POST /quizzes/{id}/submit body.
// Each value is either a JSON string (mcq) or a JSON array of strings
// (multi_select), so we keep it as raw JSON until scoring time.
type submitRequest struct {
	Answers map[string]json.RawMessage `json:"answers"`
}

// submitResponse is the scored result returned to the caller.
type submitResponse struct {
	QuizID        string `json:"quiz_id"`
	SubmissionID  string `json:"submission_id"`
	Score         int    `json:"score"`
	Passed        bool   `json:"passed"`
	Correct       int    `json:"correct"`
	Total         int    `json:"total"`
	PassThreshold int    `json:"pass_threshold"`
}

// ── Submit handler ────────────────────────────────────────────────────────────

// Submit handles POST /quizzes/{id}/submit.
func (h *QuizHandler) Submit(w http.ResponseWriter, r *http.Request) {
	rawID := chi.URLParam(r, "id")
	qid, err := uuid.Parse(rawID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "quiz id must be a UUID")
		return
	}

	// Decode answer payload.
	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	if req.Answers == nil {
		req.Answers = map[string]json.RawMessage{}
	}

	// Load quiz + questions.
	quiz, questions, err := h.Quizzes.Get(r.Context(), qid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "quiz_not_found", "no quiz with id "+rawID)
			return
		}
		h.log().Error().Err(err).Str("quiz_id", rawID).Msg("quizzes.submit: get quiz")
		writeError(w, http.StatusInternalServerError, "internal_error", "quiz lookup failed")
		return
	}

	// ── Score ─────────────────────────────────────────────────────────────────
	var (
		earnedPoints int
		totalPoints  int
		correctCount int
	)

	for _, q := range questions {
		totalPoints += q.Points

		submitted, hasAnswer := req.Answers[q.ID.String()]
		if !hasAnswer {
			continue // no answer → no points
		}

		var correct bool
		switch q.Kind {
		case "mcq":
			correct = scoreMCQ(q.Correct, submitted)
		case "multi_select":
			correct = scoreMultiSelect(q.Correct, submitted)
		default:
			// Unknown question kind: skip silently (no points awarded).
			h.log().Warn().
				Str("quiz_id", rawID).
				Str("question_id", q.ID.String()).
				Str("kind", q.Kind).
				Msg("quizzes.submit: unknown question kind, skipping")
		}

		if correct {
			earnedPoints += q.Points
			correctCount++
		}
	}

	score := 0
	if totalPoints > 0 {
		// Round to nearest integer.
		score = (earnedPoints*100 + totalPoints/2) / totalPoints
	}
	passed := score >= quiz.PassThreshold

	// ── Record progress (best-effort) ─────────────────────────────────────────
	if quiz.LessonID != nil {
		uid, ok := userIDFromContext(r.Context())
		if ok {
			if _, err := h.Progress.Upsert(r.Context(), uid, *quiz.LessonID, "completed", &score); err != nil {
				h.log().Error().Err(err).
					Str("quiz_id", rawID).
					Str("user_id", uid.String()).
					Msg("quizzes.submit: progress upsert failed (non-fatal)")
			}
		} else {
			h.log().Warn().Str("quiz_id", rawID).Msg("quizzes.submit: no user in context, skipping progress upsert")
		}
	}

	// ── Audit (best-effort) ───────────────────────────────────────────────────
	if h.Audit != nil {
		uid, ok := userIDFromContext(r.Context())
		if ok {
			uidCopy := uid
			_ = h.Audit.Append(r.Context(), &db.AuditEvent{
				ActorUserID: &uidCopy,
				Action:      "quiz.submit",
				TargetType:  "quiz",
				TargetID:    quiz.ID.String(),
				Outcome:     map[bool]string{true: "passed", false: "failed"}[passed],
			})
		}
	}

	writeJSON(w, http.StatusOK, submitResponse{
		QuizID:        quiz.ID.String(),
		SubmissionID:  uuid.New().String(),
		Score:         score,
		Passed:        passed,
		Correct:       correctCount,
		Total:         len(questions),
		PassThreshold: quiz.PassThreshold,
	})
}

// ── Scoring helpers ───────────────────────────────────────────────────────────

// scoreMCQ compares a single-string correct answer to the submitted raw JSON.
// Correct is stored as a JSON string: `"answer"`.
// Submitted is the raw JSON value from the request, also expected to be a
// JSON string. Returns false on any parse error.
func scoreMCQ(correct json.RawMessage, submitted json.RawMessage) bool {
	var correctStr string
	if err := json.Unmarshal(correct, &correctStr); err != nil {
		return false
	}
	var submittedStr string
	if err := json.Unmarshal(submitted, &submittedStr); err != nil {
		return false
	}
	return correctStr == submittedStr
}

// scoreMultiSelect compares two sets of strings (order-insensitive).
// Correct is stored as a JSON array: `["a","b"]`.
// Submitted is the raw JSON value from the request, expected to be a JSON
// array of strings. Returns false on any parse error or set mismatch.
func scoreMultiSelect(correct json.RawMessage, submitted json.RawMessage) bool {
	var correctSlice []string
	if err := json.Unmarshal(correct, &correctSlice); err != nil {
		return false
	}
	var submittedSlice []string
	if err := json.Unmarshal(submitted, &submittedSlice); err != nil {
		return false
	}
	if len(correctSlice) != len(submittedSlice) {
		return false
	}
	sort.Strings(correctSlice)
	sort.Strings(submittedSlice)
	for i := range correctSlice {
		if correctSlice[i] != submittedSlice[i] {
			return false
		}
	}
	return true
}

// log returns the handler's logger, falling back to a no-op logger.
func (h *QuizHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// ── v0.0.1 stub fallback ──────────────────────────────────────────────────────

// SubmitQuiz accepts answers and returns a stub passing score.
// Retained for backwards-compat; prefer QuizHandler.Submit for real scoring.
func SubmitQuiz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "quizzes.submit").Str("id", id).Msg("submit quiz")
		writeJSON(w, http.StatusOK, map[string]any{
			"quiz_id":       id,
			"score":         100,
			"passed":        true,
			"correct":       0,
			"total":         0,
			"submission_id": "sub_stub_" + id,
		})
	}
}
