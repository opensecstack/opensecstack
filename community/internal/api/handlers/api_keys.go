package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func generateAPIKey() (raw, prefix, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = "sin_" + base64.RawURLEncoding.EncodeToString(b)
	prefix = raw[:12]
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return
}

func ListAPIKeys(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		rows, err := d.Pool.Query(r.Context(),
			`SELECT ak.id, ak.name, ak.key_prefix, ak.last_used_at::text, ak.created_at::text
			 FROM api_keys ak JOIN users u ON u.id = ak.user_id
			 WHERE u.username = $1 ORDER BY ak.created_at DESC`, claims.Sub)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		type keyItem struct {
			ID         string  `json:"id"`
			Name       string  `json:"name"`
			KeyPrefix  string  `json:"key_prefix"`
			LastUsedAt *string `json:"last_used_at"`
			CreatedAt  string  `json:"created_at"`
		}
		var keys []keyItem
		for rows.Next() {
			var k keyItem
			if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.LastUsedAt, &k.CreatedAt); err != nil {
				continue
			}
			keys = append(keys, k)
		}
		if keys == nil {
			keys = []keyItem{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
	}
}

func CreateAPIKey(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}

		var keyCount int
		err := d.Pool.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE u.username = $1`,
			claims.Sub,
		).Scan(&keyCount)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		if keyCount >= 10 {
			http.Error(w, `{"error":"API key limit reached (max 10)"}`, http.StatusTooManyRequests)
			return
		}

		raw, prefix, hash, err := generateAPIKey()
		if err != nil {
			http.Error(w, "key generation failed", http.StatusInternalServerError)
			return
		}

		var keyID string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO api_keys (user_id, name, key_prefix, key_hash)
			 SELECT id, $1, $2, $3 FROM users WHERE username = $4
			 RETURNING id`, req.Name, prefix, hash, claims.Sub).Scan(&keyID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{
			"id":  keyID,
			"key": raw, // shown ONCE
		})
	}
}

func DeleteAPIKey(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("id")
		res, err := d.Pool.Exec(r.Context(),
			`DELETE FROM api_keys ak USING users u
			 WHERE ak.user_id = u.id AND u.username = $1 AND ak.id = $2`,
			claims.Sub, id)
		if err != nil || res.RowsAffected() == 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
