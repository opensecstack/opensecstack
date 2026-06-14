package email

import (
	"bytes"
	"fmt"
	"html/template"
)

// reactionEmoji maps reaction kind names to their emoji representations.
var reactionEmoji = map[string]string{
	"heart":    "❤️",
	"unicorn":  "🦄",
	"fire":     "🔥",
	"bookmark": "🔖",
}

// baseData holds the fields injected into the base layout template.
type baseData struct {
	Subject string
	Body    template.HTML
	SiteURL string
}

// baseLayout is the shared outer shell for every HTML email.
var baseLayout = template.Must(template.New("base").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Subject}}</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;max-width:600px">
        <tr><td style="background:#6366f1;padding:24px 32px">
          <span style="color:#ffffff;font-size:24px;font-weight:700;letter-spacing:-0.5px">SIN</span>
          <span style="color:#c7d2fe;font-size:14px;margin-left:8px">Community</span>
        </td></tr>
        <tr><td style="padding:32px">{{.Body}}</td></tr>
        <tr><td style="background:#f9fafb;padding:20px 32px;border-top:1px solid #e5e7eb">
          <p style="margin:0;color:#9ca3af;font-size:12px">
            You received this email from SIN Community.<br>
            <a href="{{.SiteURL}}/settings" style="color:#6366f1">Manage email preferences</a> &middot;
            <a href="{{.SiteURL}}" style="color:#6366f1">Visit SIN</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`))

// renderBase wraps a pre-built body snippet in the base layout and returns the
// full HTML string. subject is used for both the <title> and the email subject.
func renderBase(subject, siteURL string, body template.HTML) (string, error) {
	var buf bytes.Buffer
	err := baseLayout.Execute(&buf, baseData{
		Subject: subject,
		Body:    body,
		SiteURL: siteURL,
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// bodyTmpl compiles a body-level template that produces a template.HTML value.
// The outer base layout is applied afterwards via renderBase.
func bodyTmpl(src string) *template.Template {
	funcs := template.FuncMap{"inc": func(i int) int { return i + 1 }}
	return template.Must(template.New("body").Funcs(funcs).Parse(src))
}

// execBodyTmpl executes t with data and returns the rendered HTML.
func execBodyTmpl(t *template.Template, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil //nolint:gosec // template already escapes user data
}

// --- Follow email ---

var followBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<table cellpadding="0" cellspacing="0" style="margin:0 0 20px">
  <tr>
    <td style="width:40px;height:40px;background:#6366f1;border-radius:50%;text-align:center;vertical-align:middle">
      <span style="color:#ffffff;font-size:18px;font-weight:700;line-height:40px">{{.ActorInitial}}</span>
    </td>
    <td style="padding-left:12px;font-size:15px;color:#374151;line-height:1.6">
      <strong>{{.ActorName}}</strong> is now following you on SIN.
    </td>
  </tr>
</table>
<p style="margin:0 0 16px">
  <a href="{{.ProfileURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">View their profile &rarr;</a>
</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0">You&rsquo;ll see their posts in your Following feed.</p>`)

// RenderFollowEmail returns the subject and full HTML body for a "new follower" email.
func RenderFollowEmail(actorName, recipientName, siteURL string) (subject, html string) {
	subject = fmt.Sprintf("%s started following you on SIN", actorName)

	initial := "?"
	if len(actorName) > 0 {
		r := []rune(actorName)
		initial = string(r[0])
	}

	data := struct {
		RecipientName string
		ActorName     string
		ActorInitial  string
		ProfileURL    string
	}{
		RecipientName: recipientName,
		ActorName:     actorName,
		ActorInitial:  initial,
		ProfileURL:    fmt.Sprintf("%s/users/%s", siteURL, actorName),
	}

	body, err := execBodyTmpl(followBodyTmpl, data)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// --- Comment email ---

var commentBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">
  <strong>{{.ActorName}}</strong> commented on your post &ldquo;<em>{{.PostTitle}}</em>&rdquo;:
</p>
<blockquote style="background:#f9fafb;border-left:4px solid #6366f1;margin:0 0 20px;padding:12px 16px;border-radius:0 4px 4px 0">
  <p style="font-size:15px;color:#374151;line-height:1.6;margin:0">&ldquo;{{.CommentSnippet}}&rdquo;</p>
</blockquote>
<p style="margin:0">
  <a href="{{.PostURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">View comment &rarr;</a>
</p>`)

// RenderCommentEmail returns the subject and full HTML body for a "new comment" email.
func RenderCommentEmail(actorName, postTitle, postSlug, commentSnippet, recipientName, siteURL string) (subject, html string) {
	subject = fmt.Sprintf("%s commented on your post \"%s\"", actorName, postTitle)

	snippet := commentSnippet
	if len([]rune(snippet)) > 200 {
		runes := []rune(snippet)
		snippet = string(runes[:197]) + "..."
	}

	data := struct {
		RecipientName  string
		ActorName      string
		PostTitle      string
		CommentSnippet string
		PostURL        string
	}{
		RecipientName:  recipientName,
		ActorName:      actorName,
		PostTitle:      postTitle,
		CommentSnippet: snippet,
		PostURL:        fmt.Sprintf("%s/posts/%s", siteURL, postSlug),
	}

	body, err := execBodyTmpl(commentBodyTmpl, data)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// --- Reaction email ---

var reactionBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 20px">
  <strong>{{.ActorName}}</strong> reacted {{.Emoji}} to your post &ldquo;<em>{{.PostTitle}}</em>&rdquo;.
</p>
<p style="margin:0">
  <a href="{{.PostURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">View post &rarr;</a>
</p>`)

// RenderReactionEmail returns the subject and full HTML body for a "new reaction" email.
func RenderReactionEmail(actorName, reactionKind, postTitle, postSlug, recipientName, siteURL string) (subject, html string) {
	subject = fmt.Sprintf("%s reacted to your post \"%s\"", actorName, postTitle)

	emoji := reactionEmoji[reactionKind]
	if emoji == "" {
		emoji = reactionKind
	}

	data := struct {
		RecipientName string
		ActorName     string
		Emoji         string
		PostTitle     string
		PostURL       string
	}{
		RecipientName: recipientName,
		ActorName:     actorName,
		Emoji:         emoji,
		PostTitle:     postTitle,
		PostURL:       fmt.Sprintf("%s/posts/%s", siteURL, postSlug),
	}

	body, err := execBodyTmpl(reactionBodyTmpl, data)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// --- Password reset email ---

var passwordResetBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 20px">
  We received a request to reset your SIN password.
</p>
<p style="margin:0 0 20px">
  <a href="{{.ResetURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">Reset password &rarr;</a>
</p>
<p style="font-size:13px;color:#6b7280;margin:0 0 16px">This link expires in 1 hour.</p>
<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">
<p style="font-size:13px;color:#9ca3af;margin:0">If you didn&rsquo;t request this, you can safely ignore this email.</p>`)

// RenderPasswordResetEmail returns the subject and full HTML body for a password reset email.
func RenderPasswordResetEmail(resetURL, recipientName, siteURL string) (subject, html string) {
	subject = "Reset your SIN password"

	name := recipientName
	if name == "" {
		name = "there"
	}

	data := struct {
		RecipientName string
		ResetURL      string
	}{
		RecipientName: name,
		ResetURL:      resetURL,
	}

	body, err := execBodyTmpl(passwordResetBodyTmpl, data)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// --- Verification email ---

var verificationBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 20px">
  Welcome to SIN! Please verify your email address to get started.
</p>
<p style="margin:0 0 20px">
  <a href="{{.VerifyURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">Verify email address &rarr;</a>
</p>
<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">
<p style="font-size:13px;color:#9ca3af;margin:0">If you didn&rsquo;t create a SIN account, you can safely ignore this email.</p>`)

// RenderVerificationEmail returns the subject and full HTML body for an email verification email.
func RenderVerificationEmail(verifyURL, recipientName, siteURL string) (subject, html string) {
	subject = "Verify your SIN email address"

	name := recipientName
	if name == "" {
		name = "there"
	}

	data := struct {
		RecipientName string
		VerifyURL     string
	}{
		RecipientName: name,
		VerifyURL:     verifyURL,
	}

	body, err := execBodyTmpl(verificationBodyTmpl, data)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// --- Digest email ---

// digestBodyTmpl renders the weekly digest post list.
var digestBodyTmpl = bodyTmpl(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 20px">
  Here are this week&rsquo;s top posts on SIN:
</p>
{{range $i, $p := .Posts}}<table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:16px">
  <tr>
    <td style="width:32px;vertical-align:top;padding-top:2px">
      <span style="display:inline-block;width:24px;height:24px;background:#6366f1;border-radius:50%;color:#ffffff;font-size:12px;font-weight:700;text-align:center;line-height:24px">{{inc $i}}</span>
    </td>
    <td style="padding-left:10px">
      <a href="{{$.SiteURL}}/posts/{{$p.Slug}}" style="font-size:15px;font-weight:600;color:#111827;text-decoration:none;line-height:1.4">{{$p.Title}}</a>
      <p style="font-size:13px;color:#6b7280;margin:4px 0 0">by <strong>@{{$p.AuthorUsername}}</strong> &nbsp;&bull;&nbsp; {{$p.ReactionCount}} reactions &nbsp;&bull;&nbsp; {{$p.ViewCount}} views</p>
    </td>
  </tr>
</table>
{{end}}<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">
<p style="margin:0">
  <a href="{{.SiteURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">Read more on SIN &rarr;</a>
</p>`)

// RenderDigestEmail returns the subject and full HTML body for the weekly digest email.
// It uses the existing DigestPost type defined in email.go.
func RenderDigestEmail(posts []DigestPost, recipientName, siteURL string) (subject, html string) {
	subject = "Your weekly SIN digest"

	name := recipientName
	if name == "" {
		name = "there"
	}

	// Register the inc helper on the body template at runtime via a FuncMap clone.
	tmpl := template.Must(template.New("digestBody").Funcs(template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}).Parse(`<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px">Hi {{.RecipientName}},</p>
<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 20px">
  Here are this week&rsquo;s top posts on SIN:
</p>
{{range $i, $p := .Posts}}<table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:16px">
  <tr>
    <td style="width:32px;vertical-align:top;padding-top:2px">
      <span style="display:inline-block;width:24px;height:24px;background:#6366f1;border-radius:50%;color:#ffffff;font-size:12px;font-weight:700;text-align:center;line-height:24px">{{inc $i}}</span>
    </td>
    <td style="padding-left:10px">
      <a href="{{$.SiteURL}}/posts/{{$p.Slug}}" style="font-size:15px;font-weight:600;color:#111827;text-decoration:none;line-height:1.4">{{$p.Title}}</a>
      <p style="font-size:13px;color:#6b7280;margin:4px 0 0">by <strong>@{{$p.AuthorUsername}}</strong> &nbsp;&bull;&nbsp; {{$p.ReactionCount}} reactions &nbsp;&bull;&nbsp; {{$p.ViewCount}} views</p>
    </td>
  </tr>
</table>
{{end}}<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">
<p style="margin:0">
  <a href="{{.SiteURL}}" style="display:inline-block;background:#6366f1;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">Read more on SIN &rarr;</a>
</p>`))

	data := struct {
		RecipientName string
		Posts         []DigestPost
		SiteURL       string
	}{
		RecipientName: name,
		Posts:         posts,
		SiteURL:       siteURL,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	body := template.HTML(buf.String()) //nolint:gosec // template already escapes user data

	full, err := renderBase(subject, siteURL, body)
	if err != nil {
		return subject, fallbackHTML(subject, siteURL)
	}
	return subject, full
}

// fallbackHTML returns a minimal plain HTML email when template rendering fails.
// This should never happen in production since templates are compiled at init time.
func fallbackHTML(subject, siteURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><body><p>%s</p><p><a href="%s">Visit SIN</a></p></body></html>`,
		template.HTMLEscapeString(subject),
		template.HTMLEscapeString(siteURL),
	)
}
