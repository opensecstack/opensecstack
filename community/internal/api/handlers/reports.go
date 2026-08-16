package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

var validReasons = map[string]bool{
	"spam":           true,
	"harassment":     true,
	"off_topic":      true,
	"misinformation": true,
	"other":          true,
}

// ReportPost handles POST /api/v1/posts/{id}/report
func ReportPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			Reason string `json:"reason"`
			Note   string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if !validReasons[req.Reason] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid reason"})
			return
		}

		postID := r.PathValue("id")

		var reporterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&reporterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var existingPostID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM posts WHERE id=$1`, postID).Scan(&existingPostID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}

		var dupID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM reports WHERE reporter_id=$1 AND post_id=$2`, reporterID, postID,
		).Scan(&dupID); err == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already reported"})
			return
		}

		var id string
		if err := d.Pool.QueryRow(r.Context(),
			`INSERT INTO reports (reporter_id, post_id, reason, note) VALUES ($1,$2,$3,$4) RETURNING id`,
			reporterID, postID, req.Reason, req.Note,
		).Scan(&id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// ReportComment handles POST /api/v1/comments/{id}/report
func ReportComment(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			Reason string `json:"reason"`
			Note   string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if !validReasons[req.Reason] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid reason"})
			return
		}

		commentID := r.PathValue("id")

		var reporterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&reporterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var existingCommentID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM comments WHERE id=$1`, commentID).Scan(&existingCommentID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "comment not found"})
			return
		}

		var dupID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM reports WHERE reporter_id=$1 AND comment_id=$2`, reporterID, commentID,
		).Scan(&dupID); err == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already reported"})
			return
		}

		var id string
		if err := d.Pool.QueryRow(r.Context(),
			`INSERT INTO reports (reporter_id, comment_id, reason, note) VALUES ($1,$2,$3,$4) RETURNING id`,
			reporterID, commentID, req.Reason, req.Note,
		).Scan(&id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

type reportRow struct {
	ID                    string  `json:"id"`
	Reason                string  `json:"reason"`
	Note                  string  `json:"note"`
	Status                string  `json:"status"`
	CreatedAt             string  `json:"created_at"`
	ReporterUsername      string  `json:"reporter_username"`
	PostID                *string `json:"post_id"`
	PostTitle             *string `json:"post_title"`
	PostSlug              *string `json:"post_slug"`
	CommentID             *string `json:"comment_id"`
	CommentBody           *string `json:"comment_body"`
	PostAuthorUsername    *string `json:"post_author_username"`
	CommentAuthorUsername *string `json:"comment_author_username"`
}

// ListReports handles GET /api/v1/mod/reports
func ListReports(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		status := r.URL.Query().Get("status")
		if status == "" {
			status = "pending"
		}
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
SELECT r.id, r.reason, r.note, r.status, r.created_at::text,
       ru.username AS reporter_username,
       p.id AS post_id, p.title AS post_title, p.slug AS post_slug,
       c.id AS comment_id, LEFT(c.body, 200) AS comment_body,
       pu.username AS post_author_username,
       cu.username AS comment_author_username
FROM reports r
JOIN users ru ON ru.id = r.reporter_id
LEFT JOIN posts p ON p.id = r.post_id
LEFT JOIN users pu ON pu.id = p.author_id
LEFT JOIN comments c ON c.id = r.comment_id
LEFT JOIN users cu ON cu.id = c.author_id
WHERE r.status = $1
ORDER BY r.created_at DESC
LIMIT $2 OFFSET $3`, status, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var reports []reportRow
		for rows.Next() {
			var rep reportRow
			if err := rows.Scan(
				&rep.ID, &rep.Reason, &rep.Note, &rep.Status, &rep.CreatedAt,
				&rep.ReporterUsername,
				&rep.PostID, &rep.PostTitle, &rep.PostSlug,
				&rep.CommentID, &rep.CommentBody,
				&rep.PostAuthorUsername, &rep.CommentAuthorUsername,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			reports = append(reports, rep)
		}
		if reports == nil {
			reports = []reportRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"reports": reports, "count": len(reports)})
	}
}

// ResolveReport handles POST /api/v1/mod/reports/{id}/resolve
func ResolveReport(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		var req struct {
			Action string  `json:"action"`
			Note   *string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var newStatus string
		switch req.Action {
		case "resolve":
			newStatus = "resolved"
		case "dismiss":
			newStatus = "dismissed"
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be resolve or dismiss"})
			return
		}

		claims := middleware.ClaimsFrom(r.Context())

		var modID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&modID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		reportID := r.PathValue("id")
		_, err := d.Pool.Exec(r.Context(),
			`UPDATE reports SET status=$1, resolved_by=$2, moderator_note=$3, resolved_at=now() WHERE id=$4`,
			newStatus, modID, req.Note, reportID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		recordAudit(r.Context(), d.Pool, modID, "resolve_report", "report", reportID, "")
		w.WriteHeader(http.StatusNoContent)
	}
}
