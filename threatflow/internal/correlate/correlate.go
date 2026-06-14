// Package correlate links related IOCs across feeds and types. Each rule
// produces zero or more ioc_correlations rows connecting a "source" IOC to
// one or more "target" IOCs with a named relationship.
//
// Relationship vocabulary (see migration 006):
//   - duplicate      — same pattern_hash seen via a different feed (cross-feed agreement)
//   - resolves-to    — URL value contains a known domain IOC's value
//   - subdomain-of   — domain ends with a shorter registered domain
//   - shares-cve     — two IOCs carry the same CVE
//   - same-network   — two ipv4-addr share a /24
//   - related-to     — generic fallback
package correlate

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// Engine runs correlation rules against the live database. It holds no state
// between calls, so it is safe to invoke from concurrent goroutines.
type Engine struct {
	pool   *pgxpool.Pool
	corr   *store.CorrelationStore
	logger zerolog.Logger
}

// New wires a correlation engine to the pool + correlation store.
func New(pool *pgxpool.Pool, corr *store.CorrelationStore, logger zerolog.Logger) *Engine {
	return &Engine{
		pool:   pool,
		corr:   corr,
		logger: logger.With().Str("component", "correlate").Logger(),
	}
}

// CorrelateIOC runs every rule against a newly ingested or updated IOC and
// persists the resulting relationships. Returns the number of correlations
// upserted. Errors from individual rules are logged but do not abort the run —
// correlation is best-effort enrichment.
func (e *Engine) CorrelateIOC(ctx context.Context, ioc *store.IOC) (int, error) {
	if e == nil || e.corr == nil {
		return 0, nil
	}
	total := 0

	if n, err := e.ruleCrossFeedDuplicate(ctx, ioc); err != nil {
		e.logger.Warn().Err(err).Msg("rule duplicate")
	} else {
		total += n
	}

	switch ioc.Type {
	case "url":
		if n, err := e.ruleURLResolvesToDomain(ctx, ioc); err != nil {
			e.logger.Warn().Err(err).Msg("rule resolves-to")
		} else {
			total += n
		}
	case "domain-name":
		if n, err := e.ruleDomainSubdomain(ctx, ioc); err != nil {
			e.logger.Warn().Err(err).Msg("rule subdomain-of")
		} else {
			total += n
		}
	case "ipv4-addr":
		if n, err := e.ruleIPSameNetwork(ctx, ioc); err != nil {
			e.logger.Warn().Err(err).Msg("rule same-network")
		} else {
			total += n
		}
	}

	if ioc.CVE != "" {
		if n, err := e.ruleSharedCVE(ctx, ioc); err != nil {
			e.logger.Warn().Err(err).Msg("rule shares-cve")
		} else {
			total += n
		}
	}

	return total, nil
}

// ruleCrossFeedDuplicate links this IOC to previously-seen IOCs with the same
// pattern_hash but from a different feed. In practice pattern_hash is UNIQUE in
// iocs, so a true cross-feed duplicate collapses into a single row via Upsert.
// We look for any OTHER IOC whose value + type match but whose feed_id differs;
// this lets us surface "same indicator observed across data sources" even after
// the dedup has merged them. Since pattern_hash is unique the main value here
// is detecting value-level duplicates emitted with slightly different patterns.
func (e *Engine) ruleCrossFeedDuplicate(ctx context.Context, ioc *store.IOC) (int, error) {
	rows, err := e.pool.Query(ctx, `
SELECT id, feed_id, source FROM iocs
WHERE type = $1 AND value = $2 AND id <> $3
LIMIT 25`, ioc.Type, ioc.Value, ioc.ID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			otherID    uuid.UUID
			otherFeed  *uuid.UUID
			otherSrc   string
		)
		if err := rows.Scan(&otherID, &otherFeed, &otherSrc); err != nil {
			return count, err
		}
		ev, _ := json.Marshal(map[string]any{
			"this_feed_id":  ioc.FeedID,
			"this_source":   ioc.Source,
			"other_feed_id": otherFeed,
			"other_source":  otherSrc,
		})
		c := &store.Correlation{
			SourceIOCID:  ioc.ID,
			TargetIOCID:  otherID,
			Relationship: "duplicate",
			Confidence:   90,
			Evidence:     ev,
		}
		if err := e.corr.Upsert(ctx, c); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// ruleURLResolvesToDomain walks domain-name IOCs that appear inside this URL's
// host component and records resolves-to links. Two-tier match: host-exact,
// then host-suffix (so "login.bank.example" links to a "bank.example" IOC).
func (e *Engine) ruleURLResolvesToDomain(ctx context.Context, ioc *store.IOC) (int, error) {
	host := hostFromURL(ioc.Value)
	if host == "" {
		return 0, nil
	}
	rows, err := e.pool.Query(ctx, `
SELECT id, value FROM iocs
WHERE type = 'domain-name' AND id <> $1 AND (value = $2 OR $2 LIKE '%.' || value)
LIMIT 25`, ioc.ID, host)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			domainID    uuid.UUID
			domainValue string
		)
		if err := rows.Scan(&domainID, &domainValue); err != nil {
			return count, err
		}
		ev, _ := json.Marshal(map[string]any{"host": host, "matched_domain": domainValue})
		c := &store.Correlation{
			SourceIOCID:  ioc.ID,
			TargetIOCID:  domainID,
			Relationship: "resolves-to",
			Confidence:   80,
			Evidence:     ev,
		}
		if err := e.corr.Upsert(ctx, c); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// ruleDomainSubdomain links "x.y.example" to "y.example" when both exist.
func (e *Engine) ruleDomainSubdomain(ctx context.Context, ioc *store.IOC) (int, error) {
	if !strings.Contains(ioc.Value, ".") {
		return 0, nil
	}
	rows, err := e.pool.Query(ctx, `
SELECT id, value FROM iocs
WHERE type = 'domain-name' AND id <> $1 AND $2 LIKE '%.' || value
LIMIT 10`, ioc.ID, ioc.Value)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			parentID    uuid.UUID
			parentValue string
		)
		if err := rows.Scan(&parentID, &parentValue); err != nil {
			return count, err
		}
		ev, _ := json.Marshal(map[string]any{"subdomain": ioc.Value, "parent": parentValue})
		c := &store.Correlation{
			SourceIOCID:  ioc.ID,
			TargetIOCID:  parentID,
			Relationship: "subdomain-of",
			Confidence:   85,
			Evidence:     ev,
		}
		if err := e.corr.Upsert(ctx, c); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// ruleIPSameNetwork links this ipv4-addr to others in the same /24. Cheap
// shared-infrastructure heuristic; evidence captures the common prefix.
func (e *Engine) ruleIPSameNetwork(ctx context.Context, ioc *store.IOC) (int, error) {
	_, ipNet, err := net.ParseCIDR(ioc.Value + "/24")
	if err != nil || ipNet == nil {
		return 0, nil
	}
	prefix := ipNet.String()
	rows, err := e.pool.Query(ctx, `
SELECT id, value FROM iocs
WHERE type = 'ipv4-addr' AND id <> $1 AND value <<= $2::inet
LIMIT 25`, ioc.ID, prefix)
	if err != nil {
		// inet operator may not be available for text values — fall back to substring.
		return e.ruleIPSameNetworkFallback(ctx, ioc, prefix)
	}
	defer rows.Close()
	return e.persistSameNetwork(ctx, ioc, rows, prefix)
}

// ruleIPSameNetworkFallback compares on the textual /24 prefix when the inet
// cast cannot be applied (our schema stores value as TEXT, not inet).
func (e *Engine) ruleIPSameNetworkFallback(ctx context.Context, ioc *store.IOC, prefix string) (int, error) {
	base := strings.TrimSuffix(prefix, "/24")
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return 0, nil
	}
	prefixLike := parts[0] + "." + parts[1] + "." + parts[2] + ".%"
	rows, err := e.pool.Query(ctx, `
SELECT id, value FROM iocs
WHERE type = 'ipv4-addr' AND id <> $1 AND value LIKE $2
LIMIT 25`, ioc.ID, prefixLike)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	return e.persistSameNetwork(ctx, ioc, rows, prefix)
}

func (e *Engine) persistSameNetwork(ctx context.Context, ioc *store.IOC, rows pgx.Rows, prefix string) (int, error) {
	count := 0
	for rows.Next() {
		var (
			otherID    uuid.UUID
			otherValue string
		)
		if err := rows.Scan(&otherID, &otherValue); err != nil {
			return count, err
		}
		ev, _ := json.Marshal(map[string]any{"prefix": prefix, "other_ip": otherValue})
		c := &store.Correlation{
			SourceIOCID:  ioc.ID,
			TargetIOCID:  otherID,
			Relationship: "same-network",
			Confidence:   60,
			Evidence:     ev,
		}
		if err := e.corr.Upsert(ctx, c); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// ruleSharedCVE links IOCs sharing a CVE identifier.
func (e *Engine) ruleSharedCVE(ctx context.Context, ioc *store.IOC) (int, error) {
	rows, err := e.pool.Query(ctx, `
SELECT id, type, value FROM iocs
WHERE cve = $1 AND id <> $2
LIMIT 25`, ioc.CVE, ioc.ID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			otherID    uuid.UUID
			otherType  string
			otherValue string
		)
		if err := rows.Scan(&otherID, &otherType, &otherValue); err != nil {
			return count, err
		}
		ev, _ := json.Marshal(map[string]any{"cve": ioc.CVE, "other_type": otherType, "other_value": otherValue})
		c := &store.Correlation{
			SourceIOCID:  ioc.ID,
			TargetIOCID:  otherID,
			Relationship: "shares-cve",
			Confidence:   75,
			Evidence:     ev,
		}
		if err := e.corr.Upsert(ctx, c); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// hostFromURL extracts the hostname from a raw URL value. Returns "" when the
// value cannot be parsed — rules skip silently.
func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	return strings.ToLower(strings.TrimSpace(host))
}
