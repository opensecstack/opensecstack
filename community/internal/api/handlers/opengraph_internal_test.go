package handlers

// White-box tests for the pure markdown-stripping / HTML-escaping / tag
// injection helpers behind ServeWithOG. These matter for XSS safety: any
// user-controlled post title/body/cover-image-url is written verbatim into
// server-rendered HTML meta tags for social-media crawlers, so htmlEscape
// and injectOGTags must correctly neutralise HTML metacharacters.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
