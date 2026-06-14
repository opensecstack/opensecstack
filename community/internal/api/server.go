package api

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
	"github.com/opensecstack/community/internal/hub"
	"github.com/opensecstack/community/internal/search"
)

func NewServer(cfg *config.Config, pool *pgxpool.Pool, version string) http.Handler {
	cit := citadel.New(cfg.CitadelURL, cfg.CitadelHMAC, cfg.CitadelKeyID, cfg.CitadelDryRun)

	sc, _ := search.New(cfg)

	mailer := email.New(email.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
		SiteURL:  cfg.SiteURL,
	})

	channelHub := hub.New()

	d := handlers.Deps{
		Pool:       pool,
		Cfg:        cfg,
		Citadel:    cit,
		Search:     sc,
		Mailer:     mailer,
		Version:    version,
		ChannelHub: channelHub,
	}

	serverStartTime := time.Now()

	mux := http.NewServeMux()

	auth    := middleware.Auth(cfg.JWTSecret, pool)
	optAuth := middleware.OptionalAuth(cfg.JWTSecret)
	authRL  := middleware.RateLimit(5, time.Minute)

	// health
	mux.HandleFunc("GET /api/v1/health", handlers.HealthCheck(d, serverStartTime))
	mux.HandleFunc("GET /api/v1/ready",  handlers.ReadinessCheck(d))

	// nativeGate disables native email/password endpoints when
	// COMMUNITY_NATIVE_AUTH=false, so sinauth SSO is the only way in.
	nativeGate := func(h http.Handler) http.Handler {
		if cfg.NativeAuthEnabled {
			return h
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"native authentication is disabled; sign in with SIN"}`))
		})
	}

	// auth methods discovery (public — drives which buttons the UI renders)
	mux.HandleFunc("GET /api/v1/auth/methods", handlers.AuthMethods(d))

	// auth (rate-limited: 5 req/min per IP)
	mux.Handle("POST /api/v1/auth/login",            nativeGate(authRL(http.HandlerFunc(handlers.Login(d)))))
	mux.Handle("POST /api/v1/auth/register",          nativeGate(authRL(http.HandlerFunc(handlers.Register(d)))))
	mux.Handle("POST /api/v1/auth/forgot-password",   nativeGate(authRL(http.HandlerFunc(handlers.ForgotPassword(d)))))
	mux.Handle("POST /api/v1/auth/reset-password",    nativeGate(authRL(http.HandlerFunc(handlers.ResetPassword(d)))))
	mux.Handle("GET /api/v1/auth/verify-email",       nativeGate(http.HandlerFunc(handlers.VerifyEmail(d))))
	mux.Handle("POST /api/v1/auth/resend-verification", nativeGate(auth(http.HandlerFunc(handlers.ResendVerification(d)))))
	mux.HandleFunc("GET /api/v1/auth/github",           handlers.GitHubOAuthStart(d))
	mux.HandleFunc("GET /api/v1/auth/github/callback",  handlers.GitHubOAuthCallback(d))
	mux.HandleFunc("GET /api/v1/auth/google",           handlers.GoogleOAuthStart(d))
	mux.HandleFunc("GET /api/v1/auth/google/callback",  handlers.GoogleOAuthCallback(d))
	mux.HandleFunc("GET /api/v1/auth/sinauth",          handlers.SinauthOAuthStart(d))
	mux.HandleFunc("GET /api/v1/auth/sinauth/callback", handlers.SinauthOAuthCallback(d))

	// invites
	mux.Handle("POST /api/v1/admin/invites", auth(http.HandlerFunc(handlers.GenerateInvite(d))))
	mux.Handle("GET /api/v1/admin/invites", auth(http.HandlerFunc(handlers.ListInvites(d))))
	mux.HandleFunc("GET /api/v1/invites/{code}/validate", handlers.ValidateInvite(d))

	// admin
	mux.Handle("GET /api/v1/admin/users", auth(http.HandlerFunc(handlers.ListAdminUsers(d))))
	mux.Handle("POST /api/v1/admin/users/bulk-role", auth(http.HandlerFunc(handlers.BulkSetRole(d))))
	mux.Handle("POST /api/v1/admin/users/bulk-ban", auth(http.HandlerFunc(handlers.BulkBanUsers(d))))
	mux.Handle("PUT /api/v1/admin/users/{username}/role", auth(http.HandlerFunc(handlers.SetUserRole(d))))
	mux.Handle("PUT /api/v1/admin/users/{username}/badge", auth(http.HandlerFunc(handlers.SetUserBadge(d))))
	mux.Handle("DELETE /api/v1/admin/users/{username}/badge", auth(http.HandlerFunc(handlers.RemoveUserBadge(d))))
	mux.Handle("POST /api/v1/admin/users/{username}/deactivate", auth(http.HandlerFunc(handlers.DeactivateUser(d))))
	mux.Handle("DELETE /api/v1/admin/users/{username}/deactivate", auth(http.HandlerFunc(handlers.ReactivateUser(d))))
	mux.Handle("GET /api/v1/admin/users/{username}/notes", auth(http.HandlerFunc(handlers.ListModNotes(d))))
	mux.Handle("POST /api/v1/admin/users/{username}/notes", auth(http.HandlerFunc(handlers.CreateModNote(d))))
	mux.Handle("DELETE /api/v1/admin/notes/{id}", auth(http.HandlerFunc(handlers.DeleteModNote(d))))
	mux.Handle("POST /api/v1/admin/tags", auth(http.HandlerFunc(handlers.AdminCreateTag(d))))
	mux.Handle("PUT /api/v1/admin/tags/{slug}", auth(http.HandlerFunc(handlers.AdminUpdateTag(d))))
	mux.Handle("DELETE /api/v1/admin/tags/{slug}", auth(http.HandlerFunc(handlers.AdminDeleteTag(d))))
	mux.Handle("GET /api/v1/admin/tags/{slug}/aliases", auth(http.HandlerFunc(handlers.AdminListTagAliases(d))))
	mux.Handle("POST /api/v1/admin/tags/{slug}/aliases", auth(http.HandlerFunc(handlers.AdminCreateTagAlias(d))))
	mux.Handle("DELETE /api/v1/admin/tags/aliases/{alias}", auth(http.HandlerFunc(handlers.AdminDeleteTagAlias(d))))
	mux.HandleFunc("GET /api/v1/broadcasts", handlers.GetBroadcast(d))
	mux.Handle("POST /api/v1/admin/broadcasts", auth(http.HandlerFunc(handlers.CreateBroadcast(d))))
	mux.Handle("DELETE /api/v1/admin/broadcasts/{id}", auth(http.HandlerFunc(handlers.DeleteBroadcast(d))))

	// feed (public with optional auth for personalisation)
	mux.Handle("GET /api/v1/feed/following", auth(http.HandlerFunc(handlers.ListFollowingFeed(d))))
	mux.Handle("GET /api/v1/feed/following-tags", auth(http.HandlerFunc(handlers.ListFollowingTagsFeed(d))))
	mux.Handle("GET /api/v1/feed/trending", optAuth(http.HandlerFunc(handlers.ListTrendingFeed(d))))
	mux.Handle("GET /api/v1/feed", optAuth(http.HandlerFunc(handlers.ListFeed(d))))

	// posts
	mux.Handle("GET /api/v1/posts", optAuth(http.HandlerFunc(handlers.ListPosts(d))))
	mux.Handle("POST /api/v1/posts", auth(http.HandlerFunc(handlers.CreatePost(d))))
	mux.Handle("GET /api/v1/posts/{slug}", optAuth(http.HandlerFunc(handlers.GetPost(d))))
	mux.Handle("PUT /api/v1/posts/{id}", auth(http.HandlerFunc(handlers.UpdatePost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}", auth(http.HandlerFunc(handlers.DeletePost(d))))
	mux.Handle("POST /api/v1/posts/{id}/publish", auth(http.HandlerFunc(handlers.PublishPost(d))))
	mux.Handle("POST /api/v1/posts/{id}/schedule", auth(http.HandlerFunc(handlers.SchedulePost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/schedule", auth(http.HandlerFunc(handlers.UnschedulePost(d))))

	// post revisions (handler created by another agent in handlers/revisions.go)
	mux.Handle("GET /api/v1/posts/{id}/revisions", auth(http.HandlerFunc(handlers.ListPostRevisions(d))))

	// post subscriptions (handlers created by another agent in handlers/subscriptions.go)
	mux.Handle("POST /api/v1/posts/{id}/subscribe", auth(http.HandlerFunc(handlers.SubscribePost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/subscribe", auth(http.HandlerFunc(handlers.UnsubscribePost(d))))
	mux.Handle("GET /api/v1/posts/{id}/subscribe", auth(http.HandlerFunc(handlers.GetPostSubscriptionStatus(d))))

	// reactions
	mux.Handle("GET /api/v1/posts/{id}/reactions", optAuth(http.HandlerFunc(handlers.GetPostReactions(d))))
	mux.Handle("POST /api/v1/posts/{id}/reactions", auth(http.HandlerFunc(handlers.AddReaction(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/reactions/{kind}", auth(http.HandlerFunc(handlers.RemoveReaction(d))))

	// comments
	mux.Handle("GET /api/v1/posts/{id}/comments", optAuth(http.HandlerFunc(handlers.ListComments(d))))
	mux.Handle("POST /api/v1/posts/{id}/comments", auth(http.HandlerFunc(handlers.CreateComment(d))))
	mux.Handle("DELETE /api/v1/comments/{id}", auth(http.HandlerFunc(handlers.DeleteComment(d))))
	mux.Handle("PUT /api/v1/comments/{id}", auth(http.HandlerFunc(handlers.UpdateComment(d))))
	mux.Handle("GET /api/v1/comments/{id}/reactions", handlers.GetCommentReactions(d))
	mux.Handle("POST /api/v1/comments/{id}/reactions", auth(http.HandlerFunc(handlers.ToggleCommentReaction(d))))

	// tags
	mux.Handle("GET /api/v1/tags", optAuth(http.HandlerFunc(handlers.ListTags(d))))
	mux.HandleFunc("GET /api/v1/tags/trending", handlers.GetTrendingTags(d))
	mux.HandleFunc("GET /api/v1/tags/popular", handlers.GetPopularTags(d))
	mux.HandleFunc("GET /api/v1/tags/{slug}", handlers.GetTag(d))
	mux.Handle("GET /api/v1/tags/{slug}/posts", optAuth(http.HandlerFunc(handlers.ListPostsByTag(d))))
	mux.Handle("POST /api/v1/tags/{slug}/follow", auth(http.HandlerFunc(handlers.FollowTag(d))))
	mux.Handle("DELETE /api/v1/tags/{slug}/follow", auth(http.HandlerFunc(handlers.UnfollowTag(d))))
	mux.Handle("GET /api/v1/tags/{slug}/follow", auth(http.HandlerFunc(handlers.GetTagFollowStatus(d))))
	mux.Handle("POST /api/v1/tags/{slug}/suppress", auth(http.HandlerFunc(handlers.SuppressTag(d))))
	mux.Handle("DELETE /api/v1/tags/{slug}/suppress", auth(http.HandlerFunc(handlers.UnsuppressTag(d))))
	mux.Handle("GET /api/v1/tags/{slug}/suppress", auth(http.HandlerFunc(handlers.GetTagSuppressionStatus(d))))

	// users
	mux.HandleFunc("GET /api/v1/users", handlers.ListUsers(d))
	mux.Handle("GET /api/v1/users/suggested", optAuth(http.HandlerFunc(handlers.GetSuggestedUsers(d))))
	mux.Handle("GET /api/v1/users/search", optAuth(http.HandlerFunc(handlers.SearchUsers(d))))
	mux.Handle("GET /api/v1/users/{username}", optAuth(http.HandlerFunc(handlers.GetUser(d))))
	mux.Handle("GET /api/v1/users/{username}/posts", optAuth(http.HandlerFunc(handlers.ListUserPosts(d))))
	mux.Handle("PUT /api/v1/users/me", auth(http.HandlerFunc(handlers.UpdateMe(d))))

	// notifications
	mux.Handle("GET /api/v1/notifications", auth(http.HandlerFunc(handlers.ListNotifications(d))))
	mux.Handle("POST /api/v1/notifications/{id}/read", auth(http.HandlerFunc(handlers.MarkNotificationRead(d))))
	mux.Handle("POST /api/v1/notifications/read-all", auth(http.HandlerFunc(handlers.MarkAllNotificationsRead(d))))
	// Stream uses optAuth: it authenticates internally via one-time ticket (EventSource cannot send headers).
	mux.Handle("POST /api/v1/me/notifications/stream-ticket", auth(http.HandlerFunc(handlers.IssueSSETicket(d))))
	mux.Handle("GET /api/v1/me/notifications/stream", optAuth(handlers.NotificationStream(d)))

	// search
	mux.Handle("GET /api/v1/search", optAuth(http.HandlerFunc(handlers.Search(d))))
	mux.HandleFunc("GET /api/v1/search/autocomplete", handlers.Autocomplete(d))

	// follows
	mux.Handle("POST /api/v1/users/{username}/follow", auth(http.HandlerFunc(handlers.FollowUser(d))))
	mux.Handle("DELETE /api/v1/users/{username}/follow", auth(http.HandlerFunc(handlers.UnfollowUser(d))))
	mux.Handle("GET /api/v1/users/{username}/followers", http.HandlerFunc(handlers.ListFollowers(d)))
	mux.Handle("GET /api/v1/users/{username}/following", http.HandlerFunc(handlers.ListFollowing(d)))
	mux.Handle("GET /api/v1/users/{username}/follow-counts", http.HandlerFunc(handlers.GetFollowCounts(d)))
	mux.Handle("GET /api/v1/users/{username}/follow-status", auth(http.HandlerFunc(handlers.GetFollowStatus(d))))

	// blocks
	mux.Handle("POST /api/v1/users/{username}/block", auth(http.HandlerFunc(handlers.BlockUser(d))))
	mux.Handle("DELETE /api/v1/users/{username}/block", auth(http.HandlerFunc(handlers.UnblockUser(d))))
	mux.Handle("GET /api/v1/users/{username}/block-status", auth(http.HandlerFunc(handlers.GetBlockStatus(d))))

	// bookmarks
	mux.Handle("POST /api/v1/posts/{id}/bookmark", auth(http.HandlerFunc(handlers.BookmarkPost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/bookmark", auth(http.HandlerFunc(handlers.UnbookmarkPost(d))))
	mux.Handle("GET /api/v1/me/bookmarks", auth(http.HandlerFunc(handlers.ListMyBookmarks(d))))
	mux.Handle("GET /api/v1/posts/{id}/bookmark-status", auth(http.HandlerFunc(handlers.GetBookmarkStatus(d))))

	// views
	mux.Handle("POST /api/v1/posts/{id}/view", http.HandlerFunc(handlers.RecordView(d)))

	// lock
	mux.Handle("POST /api/v1/posts/{id}/lock", auth(http.HandlerFunc(handlers.LockPost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/lock", auth(http.HandlerFunc(handlers.UnlockPost(d))))

	// archive
	mux.Handle("POST /api/v1/posts/{id}/archive", auth(http.HandlerFunc(handlers.ArchivePost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/archive", auth(http.HandlerFunc(handlers.UnarchivePost(d))))

	// reports
	mux.Handle("POST /api/v1/posts/{id}/report", auth(http.HandlerFunc(handlers.ReportPost(d))))
	mux.Handle("POST /api/v1/comments/{id}/report", auth(http.HandlerFunc(handlers.ReportComment(d))))
	mux.Handle("GET /api/v1/mod/reports", auth(http.HandlerFunc(handlers.ListReports(d))))
	mux.Handle("POST /api/v1/mod/reports/{id}/resolve", auth(http.HandlerFunc(handlers.ResolveReport(d))))

	// rss
	mux.HandleFunc("GET /api/v1/feed.rss", handlers.GetFeedRSS(d))
	mux.HandleFunc("GET /api/v1/users/{username}/feed.rss", handlers.GetUserFeedRSS(d))
	mux.HandleFunc("GET /api/v1/tags/{slug}/feed.rss", handlers.GetTagFeedRSS(d))

	// series
	mux.Handle("POST /api/v1/series", auth(http.HandlerFunc(handlers.CreateSeries(d))))
	mux.Handle("GET /api/v1/series/{slug}", http.HandlerFunc(handlers.GetSeries(d)))
	mux.Handle("GET /api/v1/posts/{id}/series", optAuth(http.HandlerFunc(handlers.GetPostSeries(d))))
	mux.Handle("POST /api/v1/series/{id}/posts", auth(http.HandlerFunc(handlers.AddPostToSeries(d))))
	mux.Handle("DELETE /api/v1/series/{id}/posts/{post_id}", auth(http.HandlerFunc(handlers.RemovePostFromSeries(d))))
	mux.Handle("PUT /api/v1/series/{id}/posts/{post_id}/position", auth(http.HandlerFunc(handlers.UpdateSeriesPostPosition(d))))
	mux.Handle("GET /api/v1/me/series", auth(http.HandlerFunc(handlers.ListMySeries(d))))

	// my posts (all states: draft, scheduled, published)
	mux.Handle("GET /api/v1/me/posts", auth(http.HandlerFunc(handlers.GetMyPosts(d))))
	mux.Handle("GET /api/v1/me/scheduled", auth(http.HandlerFunc(handlers.GetScheduledPosts(d))))

	// templates
	mux.Handle("GET /api/v1/me/templates", auth(http.HandlerFunc(handlers.ListTemplates(d))))
	mux.Handle("POST /api/v1/me/templates", auth(http.HandlerFunc(handlers.CreateTemplate(d))))
	mux.Handle("DELETE /api/v1/me/templates/{id}", auth(http.HandlerFunc(handlers.DeleteTemplate(d))))

	// reading history
	mux.Handle("POST /api/v1/posts/{id}/read", auth(http.HandlerFunc(handlers.RecordRead(d))))
	mux.Handle("GET /api/v1/me/history", auth(http.HandlerFunc(handlers.ListReadingHistory(d))))

	// web push subscriptions
	mux.Handle("POST /api/v1/me/push-subscription", auth(http.HandlerFunc(handlers.SubscribePush(d))))
	mux.Handle("DELETE /api/v1/me/push-subscription", auth(http.HandlerFunc(handlers.UnsubscribePush(d))))

	// sessions
	mux.Handle("GET /api/v1/me/sessions",         auth(http.HandlerFunc(handlers.ListSessions(d))))
	mux.Handle("DELETE /api/v1/me/sessions/{id}",  auth(http.HandlerFunc(handlers.RevokeSession(d))))
	mux.Handle("DELETE /api/v1/me/sessions",       auth(http.HandlerFunc(handlers.RevokeAllSessions(d))))

	// totp / 2fa
	mux.Handle("GET /api/v1/me/totp", auth(http.HandlerFunc(handlers.GetTOTPStatus(d))))
	mux.Handle("POST /api/v1/me/totp/setup", auth(http.HandlerFunc(handlers.SetupTOTP(d))))
	mux.Handle("POST /api/v1/me/totp/confirm", auth(http.HandlerFunc(handlers.ConfirmTOTP(d))))
	mux.Handle("DELETE /api/v1/me/totp", auth(http.HandlerFunc(handlers.DisableTOTP(d))))

	// api keys
	mux.Handle("GET /api/v1/me/api-keys", auth(http.HandlerFunc(handlers.ListAPIKeys(d))))
	mux.Handle("POST /api/v1/me/api-keys", auth(http.HandlerFunc(handlers.CreateAPIKey(d))))
	mux.Handle("DELETE /api/v1/me/api-keys/{id}", auth(http.HandlerFunc(handlers.DeleteAPIKey(d))))

	// mutes
	mux.Handle("POST /api/v1/users/{username}/mute", auth(http.HandlerFunc(handlers.MuteUser(d))))
	mux.Handle("DELETE /api/v1/users/{username}/mute", auth(http.HandlerFunc(handlers.UnmuteUser(d))))
	mux.Handle("GET /api/v1/users/{username}/mute-status", auth(http.HandlerFunc(handlers.GetMuteStatus(d))))
	mux.Handle("GET /api/v1/me/mutes", auth(http.HandlerFunc(handlers.ListMutedUsers(d))))

	// user stats + pinned post (public)
	mux.HandleFunc("GET /api/v1/users/{username}/stats", handlers.GetUserStats(d))
	mux.HandleFunc("GET /api/v1/users/{username}/pinned-post", handlers.GetUserPinnedPost(d))

	// related posts (public)
	mux.HandleFunc("GET /api/v1/posts/{id}/related", handlers.GetRelatedPosts(d))

	// leaderboard (public)
	mux.HandleFunc("GET /api/v1/leaderboard", handlers.GetLeaderboard(d))

	// sitemap / robots
	mux.HandleFunc("GET /sitemap.xml", handlers.GetSitemap(d))
	mux.HandleFunc("GET /robots.txt", handlers.GetRobotsTxt(d))

	// gdpr
	mux.Handle("POST /api/v1/me/deletion-request", auth(http.HandlerFunc(handlers.RequestDeletion(d))))
	mux.Handle("DELETE /api/v1/me/deletion-request", auth(http.HandlerFunc(handlers.CancelDeletion(d))))
	mux.Handle("GET /api/v1/me/deletion-request", auth(http.HandlerFunc(handlers.GetDeletionStatus(d))))
	mux.Handle("GET /api/v1/me/export", auth(http.HandlerFunc(handlers.ExportMyData(d))))
	mux.Handle("POST /api/v1/admin/digest/send", auth(http.HandlerFunc(handlers.TriggerDigest(d))))
	mux.Handle("GET /api/v1/admin/deletion-requests", auth(http.HandlerFunc(handlers.AdminListDeletionRequests(d))))
	mux.Handle("POST /api/v1/admin/deletion-requests/{id}/process", auth(http.HandlerFunc(handlers.AdminProcessDeletion(d))))

	// notification preferences
	mux.Handle("GET /api/v1/me/notification-preferences", auth(http.HandlerFunc(handlers.GetNotificationPrefs(d))))
	mux.Handle("PUT /api/v1/me/notification-preferences", auth(http.HandlerFunc(handlers.UpdateNotificationPrefs(d))))

	// password change
	mux.Handle("PUT /api/v1/me/password", auth(http.HandlerFunc(handlers.ChangePassword(d))))

	// admin stats
	mux.Handle("GET /api/v1/admin/stats", auth(http.HandlerFunc(handlers.GetAdminStats(d))))

	// uploads
	mux.Handle("POST /api/v1/upload", auth(http.HandlerFunc(handlers.UploadImage(d))))
	mux.Handle("GET /uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(cfg.UploadDir))))

	// pin
	mux.Handle("POST /api/v1/posts/{id}/pin", auth(http.HandlerFunc(handlers.PinPost(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/pin", auth(http.HandlerFunc(handlers.UnpinPost(d))))

	// analytics
	mux.Handle("GET /api/v1/posts/{id}/analytics", auth(http.HandlerFunc(handlers.GetPostAnalytics(d))))

	// audit log
	mux.Handle("GET /api/v1/admin/audit-log", auth(http.HandlerFunc(handlers.ListAuditLog(d))))

	// context notes
	mux.Handle("POST /api/v1/posts/{id}/context-note", auth(http.HandlerFunc(handlers.UpsertContextNote(d))))
	mux.Handle("DELETE /api/v1/posts/{id}/context-note", auth(http.HandlerFunc(handlers.DeleteContextNote(d))))
	mux.HandleFunc("GET /api/v1/posts/{id}/context-note", handlers.GetContextNote(d))

	// spaces + channels
	mux.Handle("GET /api/v1/spaces",                                                    optAuth(http.HandlerFunc(handlers.ListSpaces(d))))
	mux.Handle("POST /api/v1/spaces",                                                   auth(http.HandlerFunc(handlers.CreateSpace(d))))
	mux.Handle("GET /api/v1/spaces/{slug}",                                             optAuth(http.HandlerFunc(handlers.GetSpace(d))))
	mux.Handle("PUT /api/v1/spaces/{slug}",                                             auth(http.HandlerFunc(handlers.UpdateSpace(d))))
	mux.Handle("DELETE /api/v1/spaces/{slug}",                                          auth(http.HandlerFunc(handlers.DeleteSpace(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/join",                                       auth(http.HandlerFunc(handlers.JoinSpace(d))))
	mux.Handle("DELETE /api/v1/spaces/{slug}/leave",                                    auth(http.HandlerFunc(handlers.LeaveSpace(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/channels",                                          auth(http.HandlerFunc(handlers.CreateChannel(d))))
	mux.Handle("DELETE /api/v1/spaces/{slug}/channels/{channel_slug}",                        auth(http.HandlerFunc(handlers.DeleteChannel(d))))
	mux.Handle("GET /api/v1/spaces/{slug}/channels/{channel_slug}/posts",                     optAuth(http.HandlerFunc(handlers.GetChannelPosts(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/channels/{channel_slug}/posts",                    auth(http.HandlerFunc(handlers.CreateChannelPost(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/invites",                                          auth(http.HandlerFunc(handlers.CreateSpaceInvite(d))))
	mux.Handle("POST /api/v1/space-invites/{code}/join",                                      auth(http.HandlerFunc(handlers.JoinSpaceByInvite(d))))
	// channel chat messages
	mux.Handle("GET /api/v1/spaces/{slug}/channels/{channel}/messages",                       optAuth(http.HandlerFunc(handlers.ListChannelMessages(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/channels/{channel}/messages",                      auth(http.HandlerFunc(handlers.CreateChannelMessage(d))))
	mux.Handle("PUT /api/v1/spaces/{slug}/channels/{channel}/messages/{id}",                  auth(http.HandlerFunc(handlers.EditChannelMessage(d))))
	mux.Handle("DELETE /api/v1/spaces/{slug}/channels/{channel}/messages/{id}",               auth(http.HandlerFunc(handlers.DeleteChannelMessage(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions",       auth(http.HandlerFunc(handlers.ToggleMessageReaction(d))))
	mux.Handle("DELETE /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions/{emoji}", auth(http.HandlerFunc(handlers.RemoveMessageReaction(d))))
	mux.Handle("GET /api/v1/spaces/{slug}/channels/{channel}/stream",                         optAuth(http.HandlerFunc(handlers.StreamChannelMessages(d))))
	// channel unread counts
	mux.Handle("GET /api/v1/spaces/{slug}/unread",                                            auth(http.HandlerFunc(handlers.GetSpaceUnreadCounts(d))))
	mux.Handle("POST /api/v1/spaces/{slug}/channels/{channel}/read",                          auth(http.HandlerFunc(handlers.MarkChannelRead(d))))

	// SPA catch-all with per-post OpenGraph tag injection
	indexHTML, err := os.ReadFile("web/dist/index.html")
	if err != nil {
		slog.Warn("index.html not found, SPA will not be served", "err", err)
		indexHTML = []byte("<html><body>SIN Community</body></html>")
	}
	mux.Handle("/", handlers.ServeWithOG(d, indexHTML))

	allowedOrigins := cfg.AllowedOrigins
	if len(allowedOrigins) == 0 && cfg.SiteURL != "" {
		allowedOrigins = []string{cfg.SiteURL}
	}
	return middleware.CORS(allowedOrigins)(middleware.MaxBodySize(middleware.Logger(middleware.RateLimit(120, time.Minute)(mux))))
}
