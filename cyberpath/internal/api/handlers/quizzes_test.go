// Integration tests for QuizHandler (Get + Submit).
// Uses in-memory fakes — no real DB or network calls.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/db"
)

// ── context helpers ───────────────────────────────────────────────────────────

// ── context helpers ───────────────────────────────────────────────────────────

// withUserCtx returns r with auth.Claims{Sub: userID.String(), Role: "learner"} in context.
// withAdminCtx is defined in certifications_test.go (same package).
func withUserCtx(r *http.Request, userID uuid.UUID) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{Sub: userID.String(), Role: "learner"}))
}

// ── fake stores ───────────────────────────────────────────────────────────────

// fakeQuizGetter implements QuizGetter using in-memory state.
type fakeQuizGetter struct {
	quiz      *db.Quiz
	questions []db.QuizQuestion
	err       error
}

func (f *fakeQuizGetter) Get(_ context.Context, _ uuid.UUID) (*db.Quiz, []db.QuizQuestion, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.quiz, f.questions, nil
}

// fakeProgressForQuiz implements ProgressUpserter for quiz tests.
// The real ProgressUpserter interface is declared in lessons.go.
type fakeProgressForQuiz struct {
	err error
}

func (f *fakeProgressForQuiz) Upsert(_ context.Context, _, _ uuid.UUID, _ string, _ *int) (*db.Progress, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &db.Progress{ID: uuid.New()}, nil
}

// ── test data helpers ─────────────────────────────────────────────────────────

func testQuiz(passThreshold int, questions []db.QuizQuestion) (*db.Quiz, []db.QuizQuestion) {
	lessonID := uuid.New()
	return &db.Quiz{
		ID:            uuid.New(),
		LessonID:      &lessonID,
		TitleEN:       "Test Quiz",
		PassThreshold: passThreshold,
	}, questions
}

func mcqQuestion(prompt, correct string, points int) db.QuizQuestion {
	choicesJSON, _ := json.Marshal([]map[string]string{
		{"key": "a", "text": "Option A"},
		{"key": "b", "text": "Option B"},
	})
	correctJSON, _ := json.Marshal(correct)
	return db.QuizQuestion{
		ID:       uuid.New(),
		Kind:     "mcq",
		PromptEN: prompt,
		Choices:  choicesJSON,
		Correct:  correctJSON,
		Points:   points,
	}
}

// ── router helper ─────────────────────────────────────────────────────────────

func newQuizRouter(h *QuizHandler) http.Handler {
	r := chi.NewRouter()
	r.Get("/quizzes/{id}", h.Get)
	r.Post("/quizzes/{id}/submit", h.Submit)
	return r
}

func doRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func doRequestWithAuth(handler http.Handler, method, path string, body any, userID uuid.UUID) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = withUserCtx(req, userID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// ── Get tests ─────────────────────────────────────────────────────────────────

func TestQuizGet_Success(t *testing.T) {
	q, qs := testQuiz(80, []db.QuizQuestion{
		mcqQuestion("Q1", "a", 1),
		mcqQuestion("Q2", "b", 1),
		mcqQuestion("Q3", "a", 1),
	})
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	w := doRequest(router, http.MethodGet, "/quizzes/"+q.ID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	questions, ok := resp["questions"].([]any)
	if !ok {
		t.Fatalf("expected 'questions' array in response")
	}
	if len(questions) != 3 {
		t.Fatalf("questions length = %d, want 3", len(questions))
	}
}

func TestQuizGet_NotFound(t *testing.T) {
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{err: pgx.ErrNoRows},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	w := doRequest(router, http.MethodGet, "/quizzes/"+uuid.New().String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestQuizGet_InvalidID(t *testing.T) {
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	w := doRequest(router, http.MethodGet, "/quizzes/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestQuizGet_AnswerKeyStripped(t *testing.T) {
	q, qs := testQuiz(80, []db.QuizQuestion{
		mcqQuestion("Q1", "secret_answer", 1),
	})
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	w := doRequest(router, http.MethodGet, "/quizzes/"+q.ID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// The raw JSON body must not contain the "correct" key anywhere.
	bodyStr := w.Body.String()
	// Parse as generic structure to check for "correct" field in questions.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	questions, _ := resp["questions"].([]any)
	for i, q := range questions {
		qMap, ok := q.(map[string]any)
		if !ok {
			continue
		}
		if _, has := qMap["correct"]; has {
			t.Errorf("question[%d] contains 'correct' field — answer key leaked; body: %s", i, bodyStr)
		}
	}
}

// ── Submit tests ──────────────────────────────────────────────────────────────

func TestQuizSubmit_AllCorrect(t *testing.T) {
	q1 := mcqQuestion("Q1", "a", 1)
	q2 := mcqQuestion("Q2", "b", 1)
	q3 := mcqQuestion("Q3", "a", 1)
	q, qs := testQuiz(60, []db.QuizQuestion{q1, q2, q3})

	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)
	userID := uuid.New()

	answers := map[string]any{
		q1.ID.String(): "a",
		q2.ID.String(): "b",
		q3.ID.String(): "a",
	}
	body := map[string]any{"answers": answers}

	var req *http.Request
	b, _ := json.Marshal(body)
	req = httptest.NewRequest(http.MethodPost, "/quizzes/"+q.ID.String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp submitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Passed {
		t.Errorf("passed = false, want true")
	}
	if resp.Score != 100 {
		t.Errorf("score = %d, want 100", resp.Score)
	}
	if resp.Correct != 3 {
		t.Errorf("correct = %d, want 3", resp.Correct)
	}
}

func TestQuizSubmit_SomeWrong(t *testing.T) {
	q1 := mcqQuestion("Q1", "a", 1)
	q2 := mcqQuestion("Q2", "b", 1)
	// passThreshold=80 → submitting 1/2 correct = 50% → not passed
	q, qs := testQuiz(80, []db.QuizQuestion{q1, q2})

	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)
	userID := uuid.New()

	// Correct answer for q1 only; wrong for q2.
	answers := map[string]any{
		q1.ID.String(): "a",  // correct
		q2.ID.String(): "a",  // wrong (correct is "b")
	}
	body := map[string]any{"answers": answers}

	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/"+q.ID.String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp submitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Correct != 1 {
		t.Errorf("correct = %d, want 1", resp.Correct)
	}
	if resp.Total != 2 {
		t.Errorf("total = %d, want 2", resp.Total)
	}
	// 50% < 80% threshold → not passed
	if resp.Passed {
		t.Errorf("passed = true, want false (score %d < threshold %d)", resp.Score, resp.PassThreshold)
	}
}

func TestQuizSubmit_NoAnswers(t *testing.T) {
	q1 := mcqQuestion("Q1", "a", 1)
	q, qs := testQuiz(60, []db.QuizQuestion{q1})

	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	body := map[string]any{"answers": map[string]any{}}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/"+q.ID.String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp submitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Score != 0 {
		t.Errorf("score = %d, want 0", resp.Score)
	}
	if resp.Passed {
		t.Errorf("passed = true, want false")
	}
}

func TestQuizSubmit_MultiSelect_Correct(t *testing.T) {
	correctJSON, _ := json.Marshal([]string{"a", "b"})
	q1 := db.QuizQuestion{
		ID:      uuid.New(),
		Kind:    "multi_select",
		PromptEN: "Choose all correct",
		Correct: correctJSON,
		Points:  2,
	}
	q, qs := testQuiz(60, []db.QuizQuestion{q1})

	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	// Submit ["b","a"] — order-independent should still be correct.
	submittedJSON, _ := json.Marshal([]string{"b", "a"})
	answers := map[string]json.RawMessage{
		q1.ID.String(): submittedJSON,
	}
	body := map[string]any{"answers": answers}

	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/"+q.ID.String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp submitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Correct != 1 {
		t.Errorf("correct = %d, want 1 (multi_select order-independent match)", resp.Correct)
	}
}

func TestQuizSubmit_MultiSelect_Wrong(t *testing.T) {
	correctJSON, _ := json.Marshal([]string{"a", "b"})
	q1 := db.QuizQuestion{
		ID:      uuid.New(),
		Kind:    "multi_select",
		PromptEN: "Choose all correct",
		Correct: correctJSON,
		Points:  2,
	}
	q, qs := testQuiz(60, []db.QuizQuestion{q1})

	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{quiz: q, questions: qs},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	// Submit only ["a"] — missing "b" → wrong.
	submittedJSON, _ := json.Marshal([]string{"a"})
	answers := map[string]json.RawMessage{
		q1.ID.String(): submittedJSON,
	}
	body := map[string]any{"answers": answers}

	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/"+q.ID.String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp submitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Correct != 0 {
		t.Errorf("correct = %d, want 0", resp.Correct)
	}
}

func TestQuizSubmit_NotFound(t *testing.T) {
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{err: pgx.ErrNoRows},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	body := map[string]any{"answers": map[string]any{}}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/"+uuid.New().String()+"/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestQuizSubmit_InvalidID(t *testing.T) {
	h := &QuizHandler{
		Quizzes:  &fakeQuizGetter{},
		Progress: &fakeProgressForQuiz{},
	}
	router := newQuizRouter(h)

	body := map[string]any{"answers": map[string]any{}}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/quizzes/not-a-uuid/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
