# Changelog

All notable changes to Community are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization code + PKCE). First login auto-provisions an account; existing accounts are linked by verified email.
- "Continue with SIN" is now the primary, default sign-in option on the Login and Register pages; native email/password is demoted to a fallback.
- `GET /api/v1/auth/methods` endpoint advertising enabled auth methods, so the frontend renders buttons from server config.
- `COMMUNITY_NATIVE_AUTH` config flag (default `true`) — set to `false` to disable native email/password endpoints and make sinauth SSO the only login.
- Initial scaffold: post feed, tags, reactions, threaded comments
- JWT auth aligned with opensecstack role model
- CITADEL evidence emission on publish
- Full-text search (PostgreSQL `tsvector`)
- Platform operator badges
- React + Vite + Tailwind frontend
