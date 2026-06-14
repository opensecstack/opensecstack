package handlers

import (
	"context"
	"net/http"
)

func RecordView(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, _ = d.Pool.Exec(r.Context(), `UPDATE posts SET views = views + 1 WHERE id = $1`, id)
		go func() {
			_, _ = d.Pool.Exec(context.Background(),
				`INSERT INTO post_views_daily (post_id, day, count)
				 VALUES ($1, CURRENT_DATE, 1)
				 ON CONFLICT (post_id, day) DO UPDATE SET count = post_views_daily.count + 1`,
				id,
			)
		}()
		w.WriteHeader(http.StatusNoContent)
	}
}
