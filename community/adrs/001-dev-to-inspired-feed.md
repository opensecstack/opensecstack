# ADR-001: dev.to-inspired feed design

## Status: Accepted

## Context
The Community platform needs a publishing model familiar to security practitioners. dev.to's model (markdown posts + tags + reactions) is widely known and encourages short-form knowledge sharing alongside longer write-ups.

## Decision
Adopt the dev.to UX pattern: card-based feed, tag-based navigation, three reaction types (heart/unicorn/fire), threaded comments, and author platform badges.

## Consequences
- Simple mental model for operators already familiar with dev.to
- No markdown rendering engine server-side (body stored as plain text; client renders)
- Reactions limited to three kinds to keep the schema simple
