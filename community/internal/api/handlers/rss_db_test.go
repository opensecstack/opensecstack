package handlers_test

// Live-DB tests for the RSS feed handlers (rss.go): GetFeedRSS,
// GetUserFeedRSS, GetTagFeedRSS. These require a real Postgres to exercise
// the query + XML-encoding path; the pure helpers (parsePubDate, truncate)
// are already covered by rss_internal_test.go.

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

type rssFeedDoc struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Title string `xml:"title"`
		Items []struct {
			Title string `xml:"title"`
			Link  string `xml:"link"`
		} `xml:"item"`
	} `xml:"channel"`
}

func TestGetFeedRSS_Success_IncludesPublishedExcludesDraft(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, pubSlug := createTestPost(t, d.Pool, authorID, "published")
	_, draftSlug := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodGet, "/feed.rss", nil)
	w := httptest.NewRecorder()

	handlers.GetFeedRSS(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Error("expected a Content-Type header for the RSS response")
	}

	var feed rssFeedDoc
	if err := xml.Unmarshal(w.Body.Bytes(), &feed); err != nil {
		t.Fatalf("failed to parse RSS XML: %v — body: %s", err, w.Body.String())
	}

	foundPub, foundDraft := false, false
	for _, item := range feed.Channel.Items {
		if item.Link == "https://sin.to/posts/"+pubSlug {
			foundPub = true
		}
		if item.Link == "https://sin.to/posts/"+draftSlug {
			foundDraft = true
		}
	}
	if !foundPub {
		t.Errorf("expected published post %q in RSS feed", pubSlug)
	}
	if foundDraft {
		t.Errorf("draft post %q must not appear in RSS feed", draftSlug)
	}
}

func TestGetUserFeedRSS_Success_FiltersByAuthor(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	_, ownSlug := createTestPost(t, d.Pool, authorID, "published")

	otherID, _ := createTestUser(t, d.Pool, "author")
	_, otherSlug := createTestPost(t, d.Pool, otherID, "published")

	req := httptest.NewRequest(http.MethodGet, "/users/"+authorUsername+"/feed.rss", nil)
	req.SetPathValue("username", authorUsername)
	w := httptest.NewRecorder()

	handlers.GetUserFeedRSS(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var feed rssFeedDoc
	if err := xml.Unmarshal(w.Body.Bytes(), &feed); err != nil {
		t.Fatalf("failed to parse RSS XML: %v", err)
	}

	foundOwn, foundOther := false, false
	for _, item := range feed.Channel.Items {
		if item.Link == "https://sin.to/posts/"+ownSlug {
			foundOwn = true
		}
		if item.Link == "https://sin.to/posts/"+otherSlug {
			foundOther = true
		}
	}
	if !foundOwn {
		t.Errorf("expected the user's own post %q in per-user RSS feed", ownSlug)
	}
	if foundOther {
		t.Errorf("expected another user's post %q to be excluded from per-user RSS feed", otherSlug)
	}
}

func TestGetUserFeedRSS_UnknownUser_ReturnsEmptyFeed(t *testing.T) {
	d := dbDeps(t)

	username := "nosuchuser_" + handlers.RandomSuffix()
	req := httptest.NewRequest(http.MethodGet, "/users/"+username+"/feed.rss", nil)
	req.SetPathValue("username", username)
	w := httptest.NewRecorder()

	handlers.GetUserFeedRSS(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even for an unknown user (empty feed), got %d", w.Code)
	}
	var feed rssFeedDoc
	if err := xml.Unmarshal(w.Body.Bytes(), &feed); err != nil {
		t.Fatalf("failed to parse RSS XML: %v", err)
	}
	if len(feed.Channel.Items) != 0 {
		t.Errorf("expected no items for an unknown user, got %d", len(feed.Channel.Items))
	}
}

func TestGetTagFeedRSS_Success_FiltersByTag(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, taggedSlug := createTestPost(t, d.Pool, authorID, "published")
	_, untaggedSlug := createTestPost(t, d.Pool, authorID, "published")

	tagSlug := "rsstag-" + handlers.RandomSuffix()
	var tagID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$1) RETURNING id`, tagSlug,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, postID, tagID); err != nil {
		t.Fatalf("insert post_tags: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM tags WHERE id=$1`, tagID)
	})

	req := httptest.NewRequest(http.MethodGet, "/tags/"+tagSlug+"/feed.rss", nil)
	req.SetPathValue("slug", tagSlug)
	w := httptest.NewRecorder()

	handlers.GetTagFeedRSS(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var feed rssFeedDoc
	if err := xml.Unmarshal(w.Body.Bytes(), &feed); err != nil {
		t.Fatalf("failed to parse RSS XML: %v", err)
	}
	foundTagged, foundUntagged := false, false
	for _, item := range feed.Channel.Items {
		if item.Link == "https://sin.to/posts/"+taggedSlug {
			foundTagged = true
		}
		if item.Link == "https://sin.to/posts/"+untaggedSlug {
			foundUntagged = true
		}
	}
	if !foundTagged {
		t.Errorf("expected tagged post %q in tag RSS feed", taggedSlug)
	}
	if foundUntagged {
		t.Errorf("expected untagged post %q to be excluded from tag RSS feed", untaggedSlug)
	}
}
