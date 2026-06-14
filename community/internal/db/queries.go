package db

// Query constants used by handlers and services.
const (
	QueryListPosts = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		WHERE p.state = 'published'
		GROUP BY p.id, u.id
		ORDER BY p.pinned DESC, p.published_at DESC
		LIMIT $1 OFFSET $2`

	QueryGetPostBySlug = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.body, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.canonical_url, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		WHERE p.slug = $1
		GROUP BY p.id, u.id`

	QueryListTags = `
		SELECT t.id, t.name, t.slug, t.description, t.color,
		       COUNT(DISTINCT pt.post_id) FILTER (WHERE p.state = 'published') AS post_count,
		       COUNT(DISTINCT tf.user_id) AS follower_count
		FROM tags t
		LEFT JOIN post_tags pt ON pt.tag_id = t.id
		LEFT JOIN posts p ON p.id = pt.post_id
		LEFT JOIN tag_follows tf ON tf.tag_id = t.id
		GROUP BY t.id
		ORDER BY post_count DESC
		LIMIT $1 OFFSET $2`

	QueryGetTag = `
		SELECT t.id, t.name, t.slug, t.description, t.color,
		       COUNT(DISTINCT pt.post_id) FILTER (WHERE p.state = 'published') AS post_count,
		       COUNT(DISTINCT tf.user_id) AS follower_count
		FROM tags t
		LEFT JOIN post_tags pt ON pt.tag_id = t.id
		LEFT JOIN posts p ON p.id = pt.post_id
		LEFT JOIN tag_follows tf ON tf.tag_id = t.id
		WHERE t.slug = $1
		GROUP BY t.id`

	QuerySearchPosts = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		WHERE p.state = 'published' AND p.search_vector @@ plainto_tsquery('english', $1)
		GROUP BY p.id, u.id
		ORDER BY ts_rank(p.search_vector, plainto_tsquery('english', $1)) DESC
		LIMIT $2 OFFSET $3`

	QueryListPostsByIDs = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		WHERE p.state = 'published' AND p.id = ANY($1)
		GROUP BY p.id, u.id`
)

// SortedListPostsQuery returns a feed query ordered by sort. Params: $1=limit $2=offset.
func SortedListPostsQuery(sort string) string {
	const base = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		WHERE p.state = 'published'
		GROUP BY p.id, u.id`

	return base + sortSuffix(sort, "$1", "$2")
}

// SortedListPostsQueryWithBlocks is like SortedListPostsQuery but filters out posts
// from users blocked by the caller. Params: $1=limit $2=offset $3=blocker_uuid (nullable).
// When $3 is NULL the block filter is a no-op.
func SortedListPostsQueryWithBlocks(sort string) string {
	const base = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		LEFT JOIN blocks bl ON bl.blocker_id = $3::uuid AND bl.blocked_id = p.author_id
		WHERE p.state = 'published' AND bl.blocked_id IS NULL
		GROUP BY p.id, u.id`

	return base + sortSuffix(sort, "$1", "$2")
}

// SortedListPostsQueryWithBlocksAndSuppressions is like SortedListPostsQueryWithBlocks but also
// filters out posts whose tags have been suppressed by the caller.
// Params: $1=limit $2=offset $3=blocker_uuid (nullable) $4=suppressor_uuid (nullable).
// When $3 or $4 is NULL the respective filter is a no-op.
func SortedListPostsQueryWithBlocksAndSuppressions(sort string) string {
	const base = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state,
		       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id
		LEFT JOIN blocks bl ON bl.blocker_id = $3::uuid AND bl.blocked_id = p.author_id
		WHERE p.state = 'published' AND bl.blocked_id IS NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM tag_suppressions ts2
		      JOIN post_tags pt2 ON pt2.post_id = p.id
		      WHERE ts2.tag_id = pt2.tag_id AND ts2.user_id = $4::uuid
		  )
		GROUP BY p.id, u.id`

	return base + sortSuffix(sort, "$1", "$2")
}

// SortedListPostsByTagQuery returns a tag-filtered feed query. Params: $1=tag_slug $2=limit $3=offset.
func SortedListPostsByTagQuery(sort string) string {
	const base = `
		SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
		       p.title, p.slug, p.cover_image_url, p.state, p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
		       p.edited_at::text,
		       COALESCE(array_agg(t2.name) FILTER (WHERE t2.name IS NOT NULL), '{}') AS tags,
		       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
		       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
		       p.views, p.locked, p.pinned, p.sensitive
		FROM posts p
		JOIN users u ON u.id = p.author_id
		JOIN post_tags pt_filter ON pt_filter.post_id = p.id
		JOIN tags t_filter ON t_filter.id = pt_filter.tag_id AND t_filter.slug = $1
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t2 ON t2.id = pt.tag_id
		WHERE p.state = 'published'
		GROUP BY p.id, u.id`

	return base + sortSuffix(sort, "$2", "$3")
}

func sortSuffix(sort, limitParam, offsetParam string) string {
	switch sort {
	case "top_week":
		return `
		ORDER BY (SELECT count(*) FROM reactions r2 WHERE r2.post_id = p.id AND r2.created_at >= now() - interval '7 days') DESC, p.published_at DESC
		LIMIT ` + limitParam + ` OFFSET ` + offsetParam
	case "top_month":
		return `
		ORDER BY (SELECT count(*) FROM reactions r2 WHERE r2.post_id = p.id AND r2.created_at >= now() - interval '30 days') DESC, p.published_at DESC
		LIMIT ` + limitParam + ` OFFSET ` + offsetParam
	case "top_all":
		return `
		ORDER BY reaction_count DESC, p.published_at DESC
		LIMIT ` + limitParam + ` OFFSET ` + offsetParam
	case "rising":
		return `
		ORDER BY (SELECT count(*) FROM reactions r2 WHERE r2.post_id = p.id AND r2.created_at >= now() - interval '24 hours') DESC, p.published_at DESC
		LIMIT ` + limitParam + ` OFFSET ` + offsetParam
	default:
		return `
		ORDER BY p.pinned DESC, p.published_at DESC
		LIMIT ` + limitParam + ` OFFSET ` + offsetParam
	}
}
