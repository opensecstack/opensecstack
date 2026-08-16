package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

type auditLogRow struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	Note          string `json:"note"`
	CreatedAt     string `json:"created_at"`
	ActorUsername string `json:"actor_username"`
}

func ListAuditLog(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		limit := queryInt(r, "limit", 50)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
SELECT al.id, al.action, al.target_type, COALESCE(al.target_id,'') AS target_id,
       al.note, al.created_at::text,
       COALESCE(u.username,'[deleted]') AS actor_username
FROM audit_log al
LEFT JOIN users u ON u.id = al.actor_id
ORDER BY al.created_at DESC
LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var entries []auditLogRow
		for rows.Next() {
			var e auditLogRow
			if err := rows.Scan(&e.ID, &e.Action, &e.TargetType, &e.TargetID, &e.Note, &e.CreatedAt, &e.ActorUsername); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			entries = append(entries, e)
		}
		if entries == nil {
			entries = []auditLogRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
	}
}

func recordAudit(ctx context.Context, pool *pgxpool.Pool, actorID, action, targetType, targetID, note string) {
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_log (actor_id, action, target_type, target_id, note) VALUES ($1,$2,$3,$4,$5)`,
		actorID, action, targetType, targetID, note,
	); err != nil {
		slog.Error("recordAudit: insert failed", "action", action, "target_type", targetType, "target_id", targetID, "err", err)
	}
}
