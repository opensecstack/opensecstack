package handlers_test

// Tests for sitemap.go — GetSitemap and GetRobotsTxt had zero coverage
// prior to this file.

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

// TestGetSitemap_IncludesStaticPagesAndPublishedPost proves GetSitemap
// returns well-formed XML containing both the hardcoded static URLs and a
// real published post's URL, but not a draft post — against a real DB.
func TestGetSitemap_IncludesStaticPagesAndPublishedPost(t *testing.T) {
	d := dbDeps(t)
	d.Cfg = &config.Config{SiteURL: "https://sin.to"}
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, publishedSlug := createTestPost(t, d.Pool, authorID, "published")
	_, draftSlug := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	w := httptest.NewRecorder()

	handlers.GetSitemap(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("expected XML content type, got %q", ct)
	}

	var sm struct {
		XMLName xml.Name `xml:"urlset"`
		URLs    []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.NewDecoder(w.Body).Decode(&sm); err != nil {
		t.Fatalf("response is not valid sitemap XML: %v", err)
	}

	var locs []string
	for _, u := range sm.URLs {
		locs = append(locs, u.Loc)
	}
	joined := strings.Join(locs, "\n")

	for _, want := range []string{
		"https://sin.to/",
		"https://sin.to/trending",
		"https://sin.to/users",
		"https://sin.to/leaderboard",
		"https://sin.to/posts/" + publishedSlug,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected sitemap to contain %q, it did not.\nfull list:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "https://sin.to/posts/"+draftSlug) {
		t.Errorf("expected sitemap to NOT contain the draft post %q", draftSlug)
	}
}

// TestGetSitemap_DBUnavailable_StillReturnsStaticPages proves the handler
// degrades gracefully (per its `if err == nil` guards around each query)
// rather than erroring out entirely when the DB queries fail.
func TestGetSitemap_DBUnavailable_StillReturnsStaticPages(t *testing.T) {
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{SiteURL: "https://sin.to"}

	req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	w := httptest.NewRecorder()

	handlers.GetSitemap(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even with DB queries failing, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "https://sin.to/trending") {
		t.Errorf("expected static pages to still be present when DB queries fail, got body: %s", w.Body.String())
	}
}

func TestGetRobotsTxt_ReturnsSitemapReferenceForConfiguredSite(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{SiteURL: "https://sin.to"}}

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	w := httptest.NewRecorder()

	handlers.GetRobotsTxt(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Allow: /") {
		t.Errorf("expected robots.txt to allow crawling, got: %s", body)
	}
	if !strings.Contains(body, "Sitemap: https://sin.to/sitemap.xml") {
		t.Errorf("expected robots.txt to reference the configured site's sitemap, got: %s", body)
	}
}
