package handlers

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
)

// ogPost holds the metadata fetched from the database for a single published post.
type ogPost struct {
	Title          string
	Body           string
	CoverImageURL  *string
	AuthorUsername string
}

// mdStripper removes common Markdown syntax so the body can be used as plain-text description.
var mdStripper = regexp.MustCompile(
	`(#{1,6}\s+)` + // headings
		`|(\*{1,3}|_{1,3})` + // bold/italic
		"|(`{1,3}[^`]*`{1,3})" + // inline code / fenced code
		`|(\[([^\]]*)\]\([^)]*\))`, // links — keep display text, drop URL
)

// stripMarkdown returns a plain-text approximation of the markdown string, truncated to maxLen.
func stripMarkdown(md string, maxLen int) string {
	s := mdStripper.ReplaceAllStringFunc(md, func(m string) string {
		// For link matches, keep the display text captured in group 5.
		if strings.HasPrefix(m, "[") {
			inner := regexp.MustCompile(`\[([^\]]*)\]`).FindStringSubmatch(m)
			if len(inner) > 1 {
				return inner[1]
			}
		}
		return ""
	})
	// Collapse extra whitespace.
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// fetchOGPost queries the database for a published post by slug.
// Returns nil, nil when the post does not exist.
func fetchOGPost(ctx context.Context, d Deps, slug string) (*ogPost, error) {
	const q = `
		SELECT p.title, COALESCE(p.body, ''), p.cover_image_url, u.username
		FROM   posts p
		JOIN   users u ON u.id = p.user_id
		WHERE  p.slug = $1
		AND    p.published = true
		LIMIT  1`

	row := d.Pool.QueryRow(ctx, q, slug)

	var p ogPost
	if err := row.Scan(&p.Title, &p.Body, &p.CoverImageURL, &p.AuthorUsername); err != nil {
		return nil, nil //nolint:nilerr // post not found — serve default OG tags
	}
	return &p, nil
}

// injectOGTags replaces the default OG title/description/image meta values inside
// the index.html bytes with post-specific values.
func injectOGTags(html []byte, title, description, image string) []byte {
	html = bytes.Replace(html,
		[]byte(`content="SIN — Community Knowledge Hub"`),
		[]byte(`content="`+htmlEscape(title)+`"`),
		1,
	)
	html = bytes.Replace(html,
		[]byte(`content="A community platform for security and IT professionals."`),
		[]byte(`content="`+htmlEscape(description)+`"`),
		1,
	)
	html = bytes.Replace(html,
		[]byte(`content="/icons/icon.svg"`),
		[]byte(`content="`+htmlEscape(image)+`"`),
		1,
	)
	return html
}

// htmlEscape escapes the minimal set of characters that are significant inside an
// HTML attribute value (double-quoted).
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ServeWithOG serves index.html with post-specific OG tags injected for /posts/:slug
// URLs. For all other paths, or when the post cannot be found, the original
// indexHTML bytes are served unchanged.
//
// indexHTML should be read once at startup (e.g. os.ReadFile("web/dist/index.html"))
// and passed in via closure so the file is not re-read on every request.
//
// Usage in server.go (catch-all, registered after all /api/ routes):
//
//	indexHTML, _ := os.ReadFile("web/dist/index.html")
//	mux.Handle("/", handlers.ServeWithOG(d, indexHTML))
func ServeWithOG(d Deps, indexHTML []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Only enrich /posts/<slug> paths.
		if strings.HasPrefix(path, "/posts/") {
			slug := strings.TrimPrefix(path, "/posts/")
			// Strip any trailing slash or sub-path (e.g. /posts/my-post/comments).
			if idx := strings.IndexByte(slug, '/'); idx != -1 {
				slug = slug[:idx]
			}

			if slug != "" {
				post, err := fetchOGPost(r.Context(), d, slug)
				if err == nil && post != nil {
					description := stripMarkdown(post.Body, 160)
					if description == "" {
						description = "A community platform for security and IT professionals."
					}

					image := "/icons/icon.svg"
					if post.CoverImageURL != nil && *post.CoverImageURL != "" {
						image = *post.CoverImageURL
					}

					enriched := injectOGTags(indexHTML, post.Title, description, image)
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write(enriched)
					return
				}
			}
		}

		// Default: serve the original index.html for all other SPA routes.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	}
}
