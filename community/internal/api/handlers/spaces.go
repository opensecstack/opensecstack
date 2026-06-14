// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensecstack/community/internal/api/middleware"
)

var spaceSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func spaceSlugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = spaceSlugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func getUID(r *http.Request, d Deps, username string) string {
	var id string
	_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, username).Scan(&id)
	return id
}

func spaceRole(r *http.Request, d Deps, spaceID, userID string) string {
	var role string
	_ = d.Pool.QueryRow(r.Context(),
		`SELECT role FROM space_members WHERE space_id=$1 AND user_id=$2`, spaceID, userID).Scan(&role)
	return role
}

// ---- types ----

type spaceRow struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Description string  `json:"description"`
	IconEmoji   string  `json:"icon_emoji"`
	IsPrivate   bool    `json:"is_private"`
	CreatedBy   string  `json:"created_by"`
	CreatedAt   string  `json:"created_at"`
	MemberCount int64   `json:"member_count"`
	IsMember    bool    `json:"is_member"`
	ViewerRole  *string `json:"viewer_role"`
}

type channelRow struct {
	ID          string `json:"id"`
	SpaceID     string `json:"space_id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Position    int    `json:"position"`
}

// ---- ListSpaces ----

func ListSpaces(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		limit := queryInt(r, "limit", 24)
		offset := queryInt(r, "offset", 0)

		var userID string
		if claims != nil {
			userID = getUID(r, d, claims.Sub)
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT s.id, s.name, s.slug, s.description, s.icon_emoji, s.is_private,
			       s.created_by::text, s.created_at::text,
			       COUNT(DISTINCT sm.user_id) AS member_count,
			       CASE WHEN $3 = '' THEN false
			            ELSE EXISTS(SELECT 1 FROM space_members WHERE space_id=s.id AND user_id=$3::uuid)
			       END AS is_member,
			       (SELECT role FROM space_members WHERE space_id=s.id AND user_id=CASE WHEN $3='' THEN NULL ELSE $3::uuid END LIMIT 1) AS viewer_role
			FROM spaces s
			LEFT JOIN space_members sm ON sm.space_id = s.id
			WHERE s.is_private = false
			   OR ($3 != '' AND EXISTS(SELECT 1 FROM space_members WHERE space_id=s.id AND user_id=$3::uuid))
			GROUP BY s.id
			ORDER BY member_count DESC, s.created_at DESC
			LIMIT $1 OFFSET $2`, limit, offset, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer rows.Close()

		spaces := []spaceRow{}
		for rows.Next() {
			var s spaceRow
			if err := rows.Scan(&s.ID, &s.Name, &s.Slug, &s.Description, &s.IconEmoji,
				&s.IsPrivate, &s.CreatedBy, &s.CreatedAt, &s.MemberCount, &s.IsMember, &s.ViewerRole); err != nil {
				continue
			}
			spaces = append(spaces, s)
		}
		writeJSON(w, http.StatusOK, map[string]any{"spaces": spaces, "count": len(spaces)})
	}
}

// ---- CreateSpace ----

func CreateSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			IconEmoji   string `json:"icon_emoji"`
			IsPrivate   bool   `json:"is_private"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}
		if req.IconEmoji == "" {
			req.IconEmoji = "🔷"
		}
		slug := spaceSlugify(req.Name)

		userID := getUID(r, d, claims.Sub)
		if userID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}

		tx, err := d.Pool.Begin(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		var space spaceRow
		err = tx.QueryRow(r.Context(), `
			INSERT INTO spaces (name, slug, description, icon_emoji, is_private, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, name, slug, description, icon_emoji, is_private, created_by::text, created_at::text`,
			req.Name, slug, req.Description, req.IconEmoji, req.IsPrivate, userID).
			Scan(&space.ID, &space.Name, &space.Slug, &space.Description, &space.IconEmoji,
				&space.IsPrivate, &space.CreatedBy, &space.CreatedAt)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "slug already exists"})
			return
		}

		// add creator as owner
		if _, err = tx.Exec(r.Context(),
			`INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, 'owner')`,
			space.ID, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		// auto-create #general channel
		if _, err = tx.Exec(r.Context(), `
			INSERT INTO channels (space_id, name, slug, description, type, position)
			VALUES ($1, 'general', 'general', 'General discussion', 'text', 0)`, space.ID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		if err = tx.Commit(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		space.MemberCount = 1
		space.IsMember = true
		role := "owner"
		space.ViewerRole = &role
		writeJSON(w, http.StatusCreated, space)
	}
}

// ---- GetSpace ----

func GetSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		claims := middleware.ClaimsFrom(r.Context())

		var userID string
		if claims != nil {
			userID = getUID(r, d, claims.Sub)
		}

		var space spaceRow
		err := d.Pool.QueryRow(r.Context(), `
			SELECT s.id, s.name, s.slug, s.description, s.icon_emoji, s.is_private,
			       s.created_by::text, s.created_at::text,
			       COUNT(DISTINCT sm.user_id) AS member_count,
			       CASE WHEN $2='' THEN false
			            ELSE EXISTS(SELECT 1 FROM space_members WHERE space_id=s.id AND user_id=$2::uuid)
			       END AS is_member,
			       (SELECT role FROM space_members WHERE space_id=s.id AND user_id=CASE WHEN $2='' THEN NULL ELSE $2::uuid END LIMIT 1) AS viewer_role
			FROM spaces s
			LEFT JOIN space_members sm ON sm.space_id = s.id
			WHERE s.slug = $1
			GROUP BY s.id`, slug, userID).
			Scan(&space.ID, &space.Name, &space.Slug, &space.Description, &space.IconEmoji,
				&space.IsPrivate, &space.CreatedBy, &space.CreatedAt, &space.MemberCount,
				&space.IsMember, &space.ViewerRole)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}

		if space.IsPrivate && !space.IsMember {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "private space"})
			return
		}

		// get channels
		chRows, err := d.Pool.Query(r.Context(), `
			SELECT id, space_id::text, name, slug, description, type, position
			FROM channels WHERE space_id=$1 ORDER BY position, name`, space.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer chRows.Close()

		channels := []channelRow{}
		for chRows.Next() {
			var ch channelRow
			if err := chRows.Scan(&ch.ID, &ch.SpaceID, &ch.Name, &ch.Slug, &ch.Description, &ch.Type, &ch.Position); err != nil {
				continue
			}
			channels = append(channels, ch)
		}

		writeJSON(w, http.StatusOK, map[string]any{"space": space, "channels": channels})
	}
}

// ---- UpdateSpace ----

func UpdateSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, slug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if spaceRole(r, d, spaceID, userID) != "owner" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner only"})
			return
		}

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			IconEmoji   string `json:"icon_emoji"`
			IsPrivate   bool   `json:"is_private"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		if req.IconEmoji == "" {
			req.IconEmoji = "🔷"
		}

		if _, err := d.Pool.Exec(r.Context(), `
			UPDATE spaces SET name=$1, description=$2, icon_emoji=$3, is_private=$4, updated_at=now()
			WHERE id=$5`, req.Name, req.Description, req.IconEmoji, req.IsPrivate, spaceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ---- DeleteSpace ----

func DeleteSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, slug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if spaceRole(r, d, spaceID, userID) != "owner" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner only"})
			return
		}

		if _, err := d.Pool.Exec(r.Context(), `DELETE FROM spaces WHERE id=$1`, spaceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- JoinSpace ----

func JoinSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		var isPrivate bool
		err := d.Pool.QueryRow(r.Context(), `SELECT id, is_private FROM spaces WHERE slug=$1`, slug).
			Scan(&spaceID, &isPrivate)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if isPrivate {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "use invite code to join private space"})
			return
		}

		if _, err = d.Pool.Exec(r.Context(),
			`INSERT INTO space_members (space_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			spaceID, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		// Notify the joining user (confirmation) and the space owner.
		createSystemNotification(r.Context(), d.Pool, userID, "space_joined", &spaceID)
		var ownerID string
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT user_id FROM space_members WHERE space_id=$1 AND role='owner'`, spaceID,
		).Scan(&ownerID)
		if ownerID != "" {
			createSpaceNotification(r.Context(), d.Pool, d.Cfg, ownerID, userID, "space_member_joined", spaceID)
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "joined"})
	}
}

// ---- LeaveSpace ----

func LeaveSpace(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, slug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if spaceRole(r, d, spaceID, userID) == "owner" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "owner cannot leave; delete the space instead"})
			return
		}

		d.Pool.Exec(r.Context(), `DELETE FROM space_members WHERE space_id=$1 AND user_id=$2`, spaceID, userID) //nolint:errcheck
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- CreateChannel ----

func CreateChannel(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, slug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}
		role := spaceRole(r, d, spaceID, userID)
		if role != "owner" && role != "moderator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner or moderator required"})
			return
		}

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Type        string `json:"type"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		if req.Type == "" {
			req.Type = "text"
		}
		chSlug := spaceSlugify(req.Name)

		var pos int
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT COALESCE(MAX(position)+1, 0) FROM channels WHERE space_id=$1`, spaceID).Scan(&pos)

		var ch channelRow
		err := d.Pool.QueryRow(r.Context(), `
			INSERT INTO channels (space_id, name, slug, description, type, position)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, space_id::text, name, slug, description, type, position`,
			spaceID, req.Name, chSlug, req.Description, req.Type, pos).
			Scan(&ch.ID, &ch.SpaceID, &ch.Name, &ch.Slug, &ch.Description, &ch.Type, &ch.Position)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "channel slug already exists"})
			return
		}
		writeJSON(w, http.StatusCreated, ch)
	}
}

// ---- DeleteChannel ----

func DeleteChannel(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel_slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, spaceSlug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}
		role := spaceRole(r, d, spaceID, userID)
		if role != "owner" && role != "moderator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner or moderator required"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`DELETE FROM channels WHERE space_id=$1 AND slug=$2`, spaceID, channelSlug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- GetChannelPosts ----

func GetChannelPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel_slug")
		claims := middleware.ClaimsFrom(r.Context())
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		var userID string
		if claims != nil {
			userID = getUID(r, d, claims.Sub)
		}

		// resolve space and check access
		var spaceID string
		var isPrivate bool
		err := d.Pool.QueryRow(r.Context(), `SELECT id, is_private FROM spaces WHERE slug=$1`, spaceSlug).
			Scan(&spaceID, &isPrivate)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}
		if isPrivate && (userID == "" || spaceRole(r, d, spaceID, userID) == "") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "private space"})
			return
		}

		var channelID string
		err = d.Pool.QueryRow(r.Context(),
			`SELECT id FROM channels WHERE space_id=$1 AND slug=$2`, spaceID, channelSlug).Scan(&channelID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
			       p.title, p.slug, p.cover_image_url, p.state,
			       p.published_at::text, p.created_at::text, p.updated_at::text,
			       p.edited_at::text,
			       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
			       (SELECT count(*) FROM reactions r2 WHERE r2.post_id = p.id) AS reaction_count,
			       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
			       p.views, p.locked, p.pinned, p.sensitive
			FROM posts p
			JOIN users u ON u.id = p.author_id
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			WHERE p.channel_id = $1 AND p.state = 'published'
			GROUP BY p.id, u.id
			ORDER BY p.published_at DESC
			LIMIT $2 OFFSET $3`, channelID, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer rows.Close()

		posts := []postRow{}
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(scanPost(&p, &tags)...); err != nil {
				continue
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		writeJSON(w, http.StatusOK, map[string]any{"posts": posts, "count": len(posts)})
	}
}

// ---- CreateChannelPost ----

func CreateChannelPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel_slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		var isPrivate bool
		err := d.Pool.QueryRow(r.Context(), `SELECT id, is_private FROM spaces WHERE slug=$1`, spaceSlug).
			Scan(&spaceID, &isPrivate)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}
		memberRole := spaceRole(r, d, spaceID, userID)
		if memberRole == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "join the space first"})
			return
		}

		var channelID string
		var channelType string
		err = d.Pool.QueryRow(r.Context(),
			`SELECT id, type FROM channels WHERE space_id=$1 AND slug=$2`, spaceID, channelSlug).
			Scan(&channelID, &channelType)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}
		if channelType == "announcement" && memberRole == "member" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "only owner/moderator can post in announcement channels"})
			return
		}

		var req struct {
			Title string   `json:"title"`
			Body  string   `json:"body"`
			Tags  []string `json:"tags"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Title = strings.TrimSpace(req.Title)
		if req.Title == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title required"})
			return
		}

		postSlug := spaceSlugify(req.Title) + "-" + channelID[:8]

		tx, err := d.Pool.Begin(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		var postID, returnedSlug string
		err = tx.QueryRow(r.Context(), `
			INSERT INTO posts (author_id, title, slug, body, state, published_at, channel_id)
			VALUES ($1, $2, $3, $4, 'published', now(), $5)
			RETURNING id, slug`,
			userID, req.Title, postSlug, req.Body, channelID).Scan(&postID, &returnedSlug)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "slug conflict, try a different title"})
			return
		}

		for _, tagName := range req.Tags {
			tagName = strings.TrimSpace(tagName)
			if tagName == "" {
				continue
			}
			tagSlug := spaceSlugify(tagName)
			var tagID string
			_ = tx.QueryRow(r.Context(),
				`INSERT INTO tags (name, slug) VALUES ($1, $2) ON CONFLICT (slug) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
				tagName, tagSlug).Scan(&tagID)
			if tagID != "" {
				tx.Exec(r.Context(), `INSERT INTO post_tags (post_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, postID, tagID) //nolint:errcheck
			}
		}

		if err = tx.Commit(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": postID, "slug": returnedSlug})
	}
}

// ---- CreateSpaceInvite ----

func CreateSpaceInvite(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM spaces WHERE slug=$1`, slug).Scan(&spaceID)
		if spaceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		role := spaceRole(r, d, spaceID, userID)
		if role != "owner" && role != "moderator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner or moderator required"})
			return
		}

		var code, expiresAt string
		err := d.Pool.QueryRow(r.Context(), `
			INSERT INTO space_invites (space_id, created_by)
			VALUES ($1, $2)
			RETURNING code, expires_at::text`, spaceID, userID).Scan(&code, &expiresAt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"code": code, "expires_at": expiresAt})
	}
}

// ---- JoinByInvite ----

func JoinSpaceByInvite(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		code := r.PathValue("code")
		userID := getUID(r, d, claims.Sub)

		var inviteID, spaceID string
		err := d.Pool.QueryRow(r.Context(), `
			SELECT id, space_id FROM space_invites
			WHERE code=$1 AND used_at IS NULL AND expires_at > now()`, code).
			Scan(&inviteID, &spaceID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid or expired invite"})
			return
		}

		tx, err := d.Pool.Begin(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		tx.Exec(r.Context(), //nolint:errcheck
			`INSERT INTO space_members (space_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, spaceID, userID)
		tx.Exec(r.Context(), //nolint:errcheck
			`UPDATE space_invites SET used_by=$1, used_at=now() WHERE id=$2`, userID, inviteID)

		if err = tx.Commit(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		// Notify the joining user and space owner.
		createSystemNotification(r.Context(), d.Pool, userID, "space_joined", &spaceID)
		var ownerID string
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT user_id FROM space_members WHERE space_id=$1 AND role='owner'`, spaceID,
		).Scan(&ownerID)
		if ownerID != "" {
			createSpaceNotification(r.Context(), d.Pool, d.Cfg, ownerID, userID, "space_member_joined", spaceID)
		}

		// return space slug so frontend can redirect
		var spaceSlug string
		_ = d.Pool.QueryRow(r.Context(), `SELECT slug FROM spaces WHERE id=$1`, spaceID).Scan(&spaceSlug)
		writeJSON(w, http.StatusOK, map[string]string{"status": "joined", "space_slug": spaceSlug})
	}
}
