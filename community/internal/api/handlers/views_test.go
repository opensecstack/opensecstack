package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestRecordView_Success_IncrementsViewsAndDailyCount(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "published")
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM post_views_daily WHERE post_id=$1`, id)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+id+"/view", nil)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()

	handlers.RecordView(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var views int64
	_ = d.Pool.QueryRow(context.Background(), `SELECT views FROM posts WHERE id=$1`, id).Scan(&views)
	if views != 1 {
		t.Errorf("expected posts.views=1 after one view, got %d", views)
	}

	// post_views_daily is written from a background goroutine — poll instead
	// of a fixed sleep to keep this test fast on an idle DB while still
	// tolerating real-world latency spikes on a busy shared test database.
	deadline := time.Now().Add(15 * time.Second)
	var count int64
	for time.Now().Before(deadline) {
		_ = d.Pool.QueryRow(context.Background(),
			`SELECT count FROM post_views_daily WHERE post_id=$1 AND day=CURRENT_DATE`, id).Scan(&count)
		if count == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if count != 1 {
		t.Errorf("expected post_views_daily count=1 after one view, got %d", count)
	}
}

// TestRecordView_DBError_StillReturns204 verifies RecordView is
// best-effort: both Exec calls discard their errors, so even against an
// unreachable DB the handler always answers 204.
func TestRecordView_DBError_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/view", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	handlers.RecordView(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 regardless of db error, got %d — body: %s", w.Code, w.Body.String())
	}
}
