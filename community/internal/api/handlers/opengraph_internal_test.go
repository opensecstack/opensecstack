package handlers

// White-box tests for the pure markdown-stripping / HTML-escaping / tag
// injection helpers behind ServeWithOG. These matter for XSS safety: any
// user-controlled post title/body/cover-image-url is written verbatim into
// server-rendered HTML meta tags for social-media crawlers, so htmlEscape
// and injectOGTags must correctly neutralise HTML metacharacters.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
)

func TestStripMarkdown_RemovesHeadingsAndEmphasis(t *testing.T) {
	got := stripMarkdown("# Heading\n\nSome **bold** and _italic_ text.", 500)
	if strings.Contains(got, "#") || strings.Contains(got, "*") || strings.Contains(got, "_") {
		t.Errorf("expected markdown syntax stripped, got %q", got)
	}
	if !strings.Contains(got, "Heading") || !strings.Contains(got, "bold") {
		t.Errorf("expected text content preserved, got %q", got)
	}
}

func TestStripMarkdown_LinksKeepDisplayTextDropURL(t *testing.T) {
	got := stripMarkdown("Check out [my post](https://example.com/secret-path) today", 500)
	if strings.Contains(got, "example.com") {
		t.Errorf("expected URL to be dropped, got %q", got)
	}
	if !strings.Contains(got, "my post") {
		t.Errorf("expected link display text preserved, got %q", got)
	}
}

func TestStripMarkdown_TruncatesToMaxLen(t *testing.T) {
	long := strings.Repeat("word ", 100)
	got := stripMarkdown(long, 20)
	if len(got) > 20 {
		t.Errorf("expected result truncated to <= 20 chars, got %d: %q", len(got), got)
	}
}

func TestStripMarkdown_CollapsesWhitespace(t *testing.T) {
	got := stripMarkdown("line one\n\n\nline   two", 500)
	if strings.Contains(got, "\n") {
		t.Errorf("expected newlines collapsed, got %q", got)
	}
	if got != "line one line two" {
		t.Errorf("expected collapsed whitespace, got %q", got)
	}
}

func TestHTMLEscape_EscapesAllFiveMetacharacters(t *testing.T) {
	got := htmlEscape(`<script>alert("x")</script> & "quoted" <b>`)
	if strings.ContainsAny(got, `<>"`) {
		t.Errorf("expected all of < > \" escaped, got %q", got)
	}
	want := `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; &#34;quoted&#34; &lt;b&gt;`
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestHTMLEscape_PlainTextUnchanged(t *testing.T) {
	got := htmlEscape("A perfectly normal title")
	if got != "A perfectly normal title" {
		t.Errorf("expected plain text unchanged, got %q", got)
	}
}

func TestInjectOGTags_ReplacesAllThreeDefaults(t *testing.T) {
	html := []byte(`<html><head>
<meta property="og:title" content="SIN — Community Knowledge Hub">
<meta property="og:description" content="A community platform for security and IT professionals.">
<meta property="og:image" content="/icons/icon.svg">
</head></html>`)

	out := injectOGTags(html, "My Post Title", "My description", "/covers/my-post.png")
	s := string(out)

	if !strings.Contains(s, `content="My Post Title"`) {
		t.Errorf("expected title injected, got %s", s)
	}
	if !strings.Contains(s, `content="My description"`) {
		t.Errorf("expected description injected, got %s", s)
	}
	if !strings.Contains(s, `content="/covers/my-post.png"`) {
		t.Errorf("expected image injected, got %s", s)
	}
	if strings.Contains(s, "SIN — Community Knowledge Hub") {
		t.Error("expected default title to be replaced")
	}
}

func TestInjectOGTags_EscapesUserSuppliedTitle(t *testing.T) {
	html := []byte(`<meta property="og:title" content="SIN — Community Knowledge Hub">`)
	out := injectOGTags(html, `"><script>alert(1)</script>`, "desc", "/img.png")
	s := string(out)

	if strings.Contains(s, "<script>") {
		t.Fatalf("expected title to be HTML-escaped before injection (XSS risk), got %s", s)
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag in output, got %s", s)
	}
}

func TestServeWithOG_NonPostsPath_ServesIndexUnchanged(t *testing.T) {
	index := []byte(`<html>original index</html>`)
	// Deps.Pool is left nil: a /posts/ request would panic when fetchOGPost
	// dereferences it, so reaching a correct response here proves the
	// handler never attempted a DB lookup for this path.
	d := Deps{}
	handler := ServeWithOG(d, index)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != string(index) {
		t.Errorf("expected original index.html served unchanged, got %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html content type, got %q", ct)
	}
}

const liveTestDBURLOG = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

// TestServeWithOG_PublishedPost_InjectsOGTags_LiveDB exercises fetchOGPost
// against the real schema (posts JOIN users), proving the query's column
// list and JOIN actually match the live database, then verifies the OG tags
// served for a real published post reflect that post's title/body.
func TestServeWithOG_PublishedPost_InjectsOGTags_LiveDB(t *testing.T) {
	pool, err := db.Connect(liveTestDBURLOG, 5)
	if err != nil {
		t.Skipf("live test DB not reachable: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(pool); err != nil {
		t.Skipf("could not migrate live test DB: %v", err)
	}
	ctx := context.Background()

	username := "og_" + uuid.New().String()[:8]
	var userID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (id, username, display_name, bio, role, created_at, updated_at, email_verified, totp_enabled, banned, website, github_username, twitter_username, location, certifications, specialization)
		 VALUES (gen_random_uuid(), $1, $1, '', 'author', now(), now(), false, false, false, '', '', '', '', '', '')
		 RETURNING id`, username).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID) }()

	slug := "og-post-" + uuid.New().String()[:8]
	var postID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO posts (id, author_id, title, slug, body, state, created_at, updated_at, views, sensitive, locked, pinned, published_at)
		 VALUES (gen_random_uuid(), $1, 'My **Great** Post', $2, 'Some body content here.', 'published', now(), now(), 0, false, false, false, now())
		 RETURNING id`, userID, slug).Scan(&postID); err != nil {
		t.Fatalf("create post: %v", err)
	}
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM posts WHERE id=$1`, postID) }()

	d := Deps{Pool: pool, Cfg: &config.Config{}}
	index := []byte(`<html><head>
<meta property="og:title" content="SIN — Community Knowledge Hub">
<meta property="og:description" content="A community platform for security and IT professionals.">
<meta property="og:image" content="/icons/icon.svg">
</head></html>`)
	handler := ServeWithOG(d, index)

	req := httptest.NewRequest(http.MethodGet, "/posts/"+slug, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `content="My **Great** Post"`) {
		t.Errorf("expected injected post title in OG tag, got %s", body)
	}
	if strings.Contains(body, "SIN — Community Knowledge Hub") {
		t.Errorf("expected default OG title replaced")
	}

	// A non-existent slug falls back to the default index unchanged.
	missingReq := httptest.NewRequest(http.MethodGet, "/posts/does-not-exist-"+uuid.New().String(), nil)
	missingW := httptest.NewRecorder()
	handler(missingW, missingReq)
	if missingW.Body.String() != string(index) {
		t.Errorf("expected default index served unchanged for unknown slug")
	}
}

func TestServeWithOG_PostsPathWithEmptySlug_ServesIndexUnchanged(t *testing.T) {
	index := []byte(`<html>original index</html>`)
	d := Deps{}
	handler := ServeWithOG(d, index)

	// "/posts/" with nothing after it — slug is empty, so fetchOGPost must
	// never be reached (which would panic on the nil pool).
	req := httptest.NewRequest(http.MethodGet, "/posts/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != string(index) {
		t.Errorf("expected original index.html served unchanged, got %q", w.Body.String())
	}
}
