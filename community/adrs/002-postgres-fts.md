# ADR-002: PostgreSQL full-text search over Elasticsearch

## Status: Accepted

## Context
Full-text search is required for post discovery. Options: Elasticsearch, Meilisearch, or PostgreSQL built-in FTS.

## Decision
Use PostgreSQL `tsvector` with a `GENERATED ALWAYS AS STORED` column. No additional search service required.

## Consequences
- Zero operational overhead (no extra container)
- Suitable for the expected scale (<100k posts)
- Less sophisticated ranking than dedicated search engines — acceptable for v0.x
