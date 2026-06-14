# API Reference

## Overview

**Base URL (dev):** `http://localhost:8090`
**Base URL (prod):** value of `COMMUNITY_SITE_URL`

**Authentication:** Pass a Bearer token in the `Authorization` header:
```
Authorization: Bearer <token>
```
Obtain a token via `POST /api/v1/auth/login`.

**All responses are JSON** unless otherwise noted (RSS, sitemap, file streams).

**Auth column values:**
- `Required` — must be wrapped in `auth(...)` middleware
- `Optional` — wrapped in `optAuth(...)`, token enriches response if present
- `None` — no auth middleware

---

### Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/health | None | Health check |
| GET | /api/v1/ready | None | Readiness check |

---

### Authentication

Rate-limited to 5 requests/minute per IP on login, register, and password endpoints.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/auth/login | None | Log in, receive JWT |
| POST | /api/v1/auth/register | None | Register new account |
| POST | /api/v1/auth/forgot-password | None | Request password reset email |
| POST | /api/v1/auth/reset-password | None | Reset password via token |
| GET | /api/v1/auth/verify-email | None | Verify email address |
| POST | /api/v1/auth/resend-verification | Required | Resend verification email |
| GET | /api/v1/auth/github | None | Start GitHub OAuth flow |
| GET | /api/v1/auth/github/callback | None | GitHub OAuth callback |
| GET | /api/v1/auth/google | None | Start Google OAuth flow |
| GET | /api/v1/auth/google/callback | None | Google OAuth callback |

---

### Invites

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/admin/invites | Required | Generate invite code |
| GET | /api/v1/admin/invites | Required | List all invite codes |
| GET | /api/v1/invites/{code}/validate | None | Validate an invite code |

---

### Admin — Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/admin/users | Required | List all users |
| POST | /api/v1/admin/users/bulk-role | Required | Set role on multiple users |
| POST | /api/v1/admin/users/bulk-ban | Required | Ban multiple users |
| PUT | /api/v1/admin/users/{username}/role | Required | Set role for a user |
| PUT | /api/v1/admin/users/{username}/badge | Required | Assign badge to user |
| DELETE | /api/v1/admin/users/{username}/badge | Required | Remove badge from user |
| POST | /api/v1/admin/users/{username}/deactivate | Required | Deactivate a user account |
| DELETE | /api/v1/admin/users/{username}/deactivate | Required | Reactivate a user account |
| GET | /api/v1/admin/users/{username}/notes | Required | List mod notes for user |
| POST | /api/v1/admin/users/{username}/notes | Required | Create mod note on user |
| DELETE | /api/v1/admin/notes/{id} | Required | Delete a mod note |

---

### Admin — Tags

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/admin/tags | Required | Create a tag |
| PUT | /api/v1/admin/tags/{slug} | Required | Update a tag |
| DELETE | /api/v1/admin/tags/{slug} | Required | Delete a tag |
| GET | /api/v1/admin/tags/{slug}/aliases | Required | List tag aliases |
| POST | /api/v1/admin/tags/{slug}/aliases | Required | Create tag alias |
| DELETE | /api/v1/admin/tags/aliases/{alias} | Required | Delete tag alias |

---

### Admin — Broadcasts

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/broadcasts | None | Get active broadcast |
| POST | /api/v1/admin/broadcasts | Required | Create broadcast message |
| DELETE | /api/v1/admin/broadcasts/{id} | Required | Delete broadcast message |

---

### Admin — Moderation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/mod/reports | Required | List all reports |
| POST | /api/v1/mod/reports/{id}/resolve | Required | Resolve a report |
| POST | /api/v1/posts/{id}/context-note | Required | Upsert context note on post |
| DELETE | /api/v1/posts/{id}/context-note | Required | Delete context note on post |
| GET | /api/v1/posts/{id}/context-note | None | Get context note for post |
| GET | /api/v1/admin/audit-log | Required | List audit log entries |

---

### Admin — GDPR

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/admin/deletion-requests | Required | List deletion requests |
| POST | /api/v1/admin/deletion-requests/{id}/process | Required | Process a deletion request |
| POST | /api/v1/admin/digest/send | Required | Trigger digest email send |

---

### Admin — Misc

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/admin/stats | Required | Get platform-wide stats |

---

### Feed

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/feed | Optional | Main personalized feed |
| GET | /api/v1/feed/trending | Optional | Trending posts feed |
| GET | /api/v1/feed/following | Required | Feed from followed users |
| GET | /api/v1/feed/following-tags | Required | Feed from followed tags |

---

### Posts

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/posts | Optional | List published posts |
| POST | /api/v1/posts | Required | Create a post |
| GET | /api/v1/posts/{slug} | Optional | Get post by slug |
| PUT | /api/v1/posts/{id} | Required | Update a post |
| DELETE | /api/v1/posts/{id} | Required | Delete a post |
| POST | /api/v1/posts/{id}/publish | Required | Publish a draft post |
| GET | /api/v1/posts/{id}/revisions | Required | List post revisions |
| GET | /api/v1/posts/{id}/related | None | Get related posts |
| GET | /api/v1/posts/{id}/analytics | Required | Get post analytics |
| GET | /api/v1/me/posts | Required | List own posts (all states) |
| GET | /api/v1/me/scheduled | Required | List scheduled posts |

---

### Post Actions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/posts/{id}/reactions | Optional | Get post reactions |
| POST | /api/v1/posts/{id}/reactions | Required | Add reaction to post |
| DELETE | /api/v1/posts/{id}/reactions/{kind} | Required | Remove post reaction |
| POST | /api/v1/posts/{id}/bookmark | Required | Bookmark a post |
| DELETE | /api/v1/posts/{id}/bookmark | Required | Remove bookmark |
| GET | /api/v1/posts/{id}/bookmark-status | Required | Get bookmark status |
| GET | /api/v1/me/bookmarks | Required | List own bookmarks |
| POST | /api/v1/posts/{id}/pin | Required | Pin a post |
| DELETE | /api/v1/posts/{id}/pin | Required | Unpin a post |
| POST | /api/v1/posts/{id}/archive | Required | Archive a post |
| DELETE | /api/v1/posts/{id}/archive | Required | Unarchive a post |
| POST | /api/v1/posts/{id}/lock | Required | Lock a post |
| DELETE | /api/v1/posts/{id}/lock | Required | Unlock a post |
| POST | /api/v1/posts/{id}/view | None | Record a post view |
| POST | /api/v1/posts/{id}/schedule | Required | Schedule a post |
| DELETE | /api/v1/posts/{id}/schedule | Required | Unschedule a post |
| POST | /api/v1/posts/{id}/subscribe | Required | Subscribe to post |
| DELETE | /api/v1/posts/{id}/subscribe | Required | Unsubscribe from post |
| GET | /api/v1/posts/{id}/subscribe | Required | Get subscription status |
| POST | /api/v1/posts/{id}/read | Required | Mark post as read |
| POST | /api/v1/posts/{id}/report | Required | Report a post |

---

### Comments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/posts/{id}/comments | Optional | List post comments |
| POST | /api/v1/posts/{id}/comments | Required | Create a comment |
| PUT | /api/v1/comments/{id} | Required | Update a comment |
| DELETE | /api/v1/comments/{id} | Required | Delete a comment |
| GET | /api/v1/comments/{id}/reactions | None | Get comment reactions |
| POST | /api/v1/comments/{id}/reactions | Required | Toggle comment reaction |
| POST | /api/v1/comments/{id}/report | Required | Report a comment |

---

### Tags

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/tags | Optional | List tags |
| GET | /api/v1/tags/trending | None | Get trending tags |
| GET | /api/v1/tags/popular | None | Get popular tags |
| GET | /api/v1/tags/{slug} | None | Get tag by slug |
| GET | /api/v1/tags/{slug}/posts | Optional | List posts by tag |
| POST | /api/v1/tags/{slug}/follow | Required | Follow a tag |
| DELETE | /api/v1/tags/{slug}/follow | Required | Unfollow a tag |
| GET | /api/v1/tags/{slug}/follow | Required | Get tag follow status |
| POST | /api/v1/tags/{slug}/suppress | Required | Suppress a tag |
| DELETE | /api/v1/tags/{slug}/suppress | Required | Unsuppress a tag |
| GET | /api/v1/tags/{slug}/suppress | Required | Get tag suppression status |

---

### Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/users | None | List users |
| GET | /api/v1/users/suggested | Optional | Get suggested users |
| GET | /api/v1/users/search | Optional | Search users |
| GET | /api/v1/users/{username} | Optional | Get user profile |
| GET | /api/v1/users/{username}/posts | Optional | List user's posts |
| GET | /api/v1/users/{username}/stats | None | Get user stats |
| GET | /api/v1/users/{username}/pinned-post | None | Get user's pinned post |
| PUT | /api/v1/users/me | Required | Update own profile |
| PUT | /api/v1/me/password | Required | Change own password |
| GET | /api/v1/leaderboard | None | Get user leaderboard |

---

### Notifications

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/notifications | Required | List notifications |
| POST | /api/v1/notifications/{id}/read | Required | Mark notification as read |
| POST | /api/v1/notifications/read-all | Required | Mark all notifications read |
| GET | /api/v1/me/notifications/stream | Required | SSE notification stream |
| GET | /api/v1/me/notification-preferences | Required | Get notification preferences |
| PUT | /api/v1/me/notification-preferences | Required | Update notification preferences |

---

### Search

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/search | Optional | Full-text search |
| GET | /api/v1/search/autocomplete | None | Search autocomplete suggestions |

---

### Follows

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/users/{username}/follow | Required | Follow a user |
| DELETE | /api/v1/users/{username}/follow | Required | Unfollow a user |
| GET | /api/v1/users/{username}/followers | None | List user's followers |
| GET | /api/v1/users/{username}/following | None | List accounts user follows |
| GET | /api/v1/users/{username}/follow-counts | None | Get follow/follower counts |
| GET | /api/v1/users/{username}/follow-status | Required | Get follow status |

---

### Blocks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/users/{username}/block | Required | Block a user |
| DELETE | /api/v1/users/{username}/block | Required | Unblock a user |
| GET | /api/v1/users/{username}/block-status | Required | Get block status |

---

### Mutes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/users/{username}/mute | Required | Mute a user |
| DELETE | /api/v1/users/{username}/mute | Required | Unmute a user |
| GET | /api/v1/users/{username}/mute-status | Required | Get mute status |
| GET | /api/v1/me/mutes | Required | List muted users |

---

### Sessions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/me/sessions | Required | List active sessions |
| DELETE | /api/v1/me/sessions/{id} | Required | Revoke a session |
| DELETE | /api/v1/me/sessions | Required | Revoke all sessions |

---

### TOTP / 2FA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/me/totp | Required | Get TOTP status |
| POST | /api/v1/me/totp/setup | Required | Begin TOTP setup |
| POST | /api/v1/me/totp/confirm | Required | Confirm TOTP setup |
| DELETE | /api/v1/me/totp | Required | Disable TOTP |

---

### API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/me/api-keys | Required | List API keys |
| POST | /api/v1/me/api-keys | Required | Create API key |
| DELETE | /api/v1/me/api-keys/{id} | Required | Delete API key |

---

### Series

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/series | Required | Create a series |
| GET | /api/v1/series/{slug} | None | Get series by slug |
| GET | /api/v1/posts/{id}/series | Optional | Get series for a post |
| POST | /api/v1/series/{id}/posts | Required | Add post to series |
| DELETE | /api/v1/series/{id}/posts/{post_id} | Required | Remove post from series |
| PUT | /api/v1/series/{id}/posts/{post_id}/position | Required | Reorder post in series |
| GET | /api/v1/me/series | Required | List own series |

---

### Templates

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/me/templates | Required | List own templates |
| POST | /api/v1/me/templates | Required | Create a template |
| DELETE | /api/v1/me/templates/{id} | Required | Delete a template |

---

### Reading History

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/posts/{id}/read | Required | Record post as read |
| GET | /api/v1/me/history | Required | List reading history |

---

### Push Notifications

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/me/push-subscription | Required | Subscribe to push notifications |
| DELETE | /api/v1/me/push-subscription | Required | Unsubscribe from push notifications |

---

### Reports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/posts/{id}/report | Required | Report a post |
| POST | /api/v1/comments/{id}/report | Required | Report a comment |
| GET | /api/v1/mod/reports | Required | List all reports |
| POST | /api/v1/mod/reports/{id}/resolve | Required | Resolve a report |

---

### RSS

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/feed.rss | None | Global RSS feed |
| GET | /api/v1/users/{username}/feed.rss | None | User RSS feed |
| GET | /api/v1/tags/{slug}/feed.rss | None | Tag RSS feed |

---

### Spaces & Channels

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/spaces | Optional | List spaces |
| POST | /api/v1/spaces | Required | Create a space |
| GET | /api/v1/spaces/{slug} | Optional | Get space by slug |
| PUT | /api/v1/spaces/{slug} | Required | Update a space |
| DELETE | /api/v1/spaces/{slug} | Required | Delete a space |
| POST | /api/v1/spaces/{slug}/join | Required | Join a space |
| DELETE | /api/v1/spaces/{slug}/leave | Required | Leave a space |
| POST | /api/v1/spaces/{slug}/channels | Required | Create a channel |
| GET | /api/v1/spaces/{slug}/channels/{channel_slug}/posts | Optional | List channel posts |
| POST | /api/v1/spaces/{slug}/channels/{channel_slug}/posts | Required | Create channel post |
| POST | /api/v1/spaces/{slug}/invites | Required | Create space invite |
| POST | /api/v1/space-invites/{code}/join | Required | Join space via invite |
| GET | /api/v1/spaces/{slug}/channels/{channel}/messages | Optional | List channel messages |
| POST | /api/v1/spaces/{slug}/channels/{channel}/messages | Required | Send channel message |
| PUT | /api/v1/spaces/{slug}/channels/{channel}/messages/{id} | Required | Edit channel message |
| DELETE | /api/v1/spaces/{slug}/channels/{channel}/messages/{id} | Required | Delete channel message |
| POST | /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions | Required | Toggle message reaction |
| DELETE | /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions/{emoji} | Required | Remove message reaction |
| GET | /api/v1/spaces/{slug}/channels/{channel}/stream | Optional | SSE channel message stream |

---

### Uploads

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/upload | Required | Upload an image |
| GET | /uploads/{filename} | None | Serve uploaded file |

---

### GDPR

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/me/deletion-request | Required | Request account deletion |
| DELETE | /api/v1/me/deletion-request | Required | Cancel deletion request |
| GET | /api/v1/me/deletion-request | Required | Get deletion request status |
| GET | /api/v1/me/export | Required | Export own data |
