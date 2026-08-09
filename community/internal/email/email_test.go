package email_test

import (
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/email"
)

// devMailer returns a Mailer with no SMTP host configured, so every Send*
// method takes the dev-mode "log instead of send" branch and returns nil
// without touching the network.
func devMailer() *email.Mailer {
	return email.New(email.Config{SiteURL: "https://sin.to"})
}

func TestSendPasswordReset_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendPasswordReset("alice@example.com", "tok123", "Alice"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendNewComment_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendNewComment("alice@example.com", "alice", "bob", "My Post", "my-post"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendNewReaction_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendNewReaction("alice@example.com", "alice", "bob", "heart", "My Post", "my-post"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendNewFollower_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendNewFollower("alice@example.com", "alice", "bob"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendMention_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendMention("alice@example.com", "alice", "bob", "My Post", "my-post"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendEmailVerification_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendEmailVerification("alice@example.com", "alice", "tok123"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendHTML_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	if err := m.SendHTML("alice@example.com", "Subject", "<p>body</p>"); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

func TestSendWeeklyDigest_DevMode_ReturnsNil(t *testing.T) {
	m := devMailer()
	posts := []email.DigestPost{{Title: "Post 1", Slug: "post-1", AuthorUsername: "alice", ReactionCount: 3, ViewCount: 10}}
	if err := m.SendWeeklyDigest("alice@example.com", "alice", "https://sin.to", posts); err != nil {
		t.Fatalf("expected nil error in dev mode, got %v", err)
	}
}

// TestSendHTML_ConfiguredHost_AttemptsRealSend verifies the code path taken
// when an SMTP host IS configured: it must attempt to dial out (and fail,
// since there's no real server), rather than silently no-op like dev mode.
func TestSendHTML_ConfiguredHost_AttemptsRealSend(t *testing.T) {
	m := email.New(email.Config{
		Host:    "127.0.0.1",
		Port:    1, // nothing listens here
		From:    "noreply@sin.to",
		SiteURL: "https://sin.to",
	})
	err := m.SendHTML("alice@example.com", "Subject", "<p>body</p>")
	if err == nil {
		t.Fatal("expected an error dialing an unreachable SMTP server, got nil")
	}
}

func TestSendPasswordReset_ConfiguredHost_AttemptsRealSend(t *testing.T) {
	m := email.New(email.Config{
		Host:    "127.0.0.1",
		Port:    1,
		From:    "noreply@sin.to",
		SiteURL: "https://sin.to",
	})
	err := m.SendPasswordReset("alice@example.com", "tok123", "Alice")
	if err == nil {
		t.Fatal("expected an error dialing an unreachable SMTP server, got nil")
	}
}

func TestRenderFollowEmail(t *testing.T) {
	subject, html := email.RenderFollowEmail("bob", "alice", "https://sin.to")
	if !strings.Contains(subject, "bob") {
		t.Errorf("expected subject to mention actor 'bob', got %q", subject)
	}
	if !strings.Contains(html, "bob") {
		t.Error("expected rendered HTML to contain actor name")
	}
	if !strings.Contains(html, "https://sin.to/users/bob") {
		t.Error("expected rendered HTML to contain profile URL")
	}
}

func TestRenderFollowEmail_EmptyActorName_UsesFallbackInitial(t *testing.T) {
	_, html := email.RenderFollowEmail("", "alice", "https://sin.to")
	if !strings.Contains(html, ">?<") {
		t.Errorf("expected fallback '?' initial for empty actor name, got: %s", html)
	}
}

func TestRenderCommentEmail(t *testing.T) {
	subject, html := email.RenderCommentEmail("bob", "My Great Post", "my-great-post", "Nice post!", "alice", "https://sin.to")
	if !strings.Contains(subject, "My Great Post") {
		t.Errorf("expected subject to mention post title, got %q", subject)
	}
	if !strings.Contains(html, "Nice post!") {
		t.Error("expected rendered HTML to contain comment snippet")
	}
	if !strings.Contains(html, "https://sin.to/posts/my-great-post") {
		t.Error("expected rendered HTML to contain post URL")
	}
}

func TestRenderCommentEmail_LongSnippet_Truncated(t *testing.T) {
	longSnippet := strings.Repeat("a", 300)
	_, html := email.RenderCommentEmail("bob", "Title", "slug", longSnippet, "alice", "https://sin.to")
	if strings.Contains(html, strings.Repeat("a", 250)) {
		t.Error("expected long comment snippet to be truncated to ~200 chars")
	}
	if !strings.Contains(html, "...") {
		t.Error("expected truncated snippet to end with ellipsis")
	}
}

func TestRenderReactionEmail_KnownKind_UsesEmoji(t *testing.T) {
	_, html := email.RenderReactionEmail("bob", "heart", "My Post", "my-post", "alice", "https://sin.to")
	if !strings.Contains(html, "❤️") {
		t.Error("expected rendered HTML to contain heart emoji for known reaction kind")
	}
}

func TestRenderReactionEmail_UnknownKind_FallsBackToRawKind(t *testing.T) {
	_, html := email.RenderReactionEmail("bob", "custom-kind", "My Post", "my-post", "alice", "https://sin.to")
	if !strings.Contains(html, "custom-kind") {
		t.Error("expected unknown reaction kind to appear verbatim in output")
	}
}

func TestRenderPasswordResetEmail(t *testing.T) {
	subject, html := email.RenderPasswordResetEmail("https://sin.to/reset-password?token=abc", "Alice", "https://sin.to")
	if subject != "Reset your SIN password" {
		t.Errorf("unexpected subject: %q", subject)
	}
	if !strings.Contains(html, "https://sin.to/reset-password?token=abc") {
		t.Error("expected rendered HTML to contain the reset URL")
	}
	if !strings.Contains(html, "Alice") {
		t.Error("expected rendered HTML to greet the recipient by name")
	}
}

func TestRenderPasswordResetEmail_EmptyRecipientName_UsesThere(t *testing.T) {
	_, html := email.RenderPasswordResetEmail("https://sin.to/reset", "", "https://sin.to")
	if !strings.Contains(html, "Hi there,") {
		t.Errorf("expected fallback greeting 'Hi there,' for empty recipient name, got: %s", html)
	}
}

func TestRenderVerificationEmail(t *testing.T) {
	subject, html := email.RenderVerificationEmail("https://sin.to/verify-email?token=abc", "Alice", "https://sin.to")
	if subject != "Verify your SIN email address" {
		t.Errorf("unexpected subject: %q", subject)
	}
	if !strings.Contains(html, "https://sin.to/verify-email?token=abc") {
		t.Error("expected rendered HTML to contain the verify URL")
	}
}

func TestRenderDigestEmail_WithPosts(t *testing.T) {
	posts := []email.DigestPost{
		{Title: "First Post", Slug: "first-post", AuthorUsername: "alice", ReactionCount: 5, ViewCount: 42},
		{Title: "Second Post", Slug: "second-post", AuthorUsername: "bob", ReactionCount: 2, ViewCount: 10},
	}
	subject, html := email.RenderDigestEmail(posts, "Carol", "https://sin.to")
	if subject != "Your weekly SIN digest" {
		t.Errorf("unexpected subject: %q", subject)
	}
	if !strings.Contains(html, "First Post") || !strings.Contains(html, "Second Post") {
		t.Error("expected rendered HTML to list both post titles")
	}
	if !strings.Contains(html, "@alice") || !strings.Contains(html, "@bob") {
		t.Error("expected rendered HTML to list both author usernames")
	}
	if !strings.Contains(html, "https://sin.to/posts/first-post") {
		t.Error("expected rendered HTML to link to the first post")
	}
}

func TestRenderDigestEmail_NoPosts_StillRenders(t *testing.T) {
	subject, html := email.RenderDigestEmail(nil, "", "https://sin.to")
	if subject == "" {
		t.Error("expected non-empty subject even with no posts")
	}
	if !strings.Contains(html, "Hi there,") {
		t.Error("expected fallback greeting for empty recipient name")
	}
}
