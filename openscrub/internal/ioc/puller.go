// Package ioc pulls IP IOCs from ThreatFlow and turns them into
// blocklist rules with `source=threatflow` and a 24-hour TTL.
//
// Loop semantics:
//   - Every cfg.Interval (default 15min) the puller GETs
//       {ThreatFlowURL}/api/v1/iocs?type=ip
//     hashing the response body to deduplicate against the
//     ioc_ingest_log audit table.
//   - For each IP not already covered by an active rule, Service.Create
//     is invoked with principal="threatflow-puller" and source="threatflow".
//   - Failures bump the openscrub_ioc_pulls_total{outcome="error"}
//     counter and are retried on the next tick.
package ioc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/metrics"
	"github.com/opensecstack/openscrub/internal/rules"
)

// Config carries puller tunables.
type Config struct {
	BaseURL    string
	Token      string
	Interval   time.Duration
	RuleTTL    time.Duration
	HTTPTimeout time.Duration
}

// IOCLoggerCompat is the type-erased adapter so the concrete
// *db.IOCIngestLogStore (which returns its own struct) can plug in
// without circular imports.
type IOCLoggerCompat func(ctx context.Context, source, sha string, count int) error

// Puller orchestrates the periodic ThreatFlow pull.
type Puller struct {
	cfg     Config
	svc     *rules.Service
	logger  zerolog.Logger
	http    *http.Client
	logFn   IOCLoggerCompat
}

// New builds a Puller. logFn may be nil — in that case ingest events
// are logged but not persisted (used in tests / when no DB).
func New(cfg Config, svc *rules.Service, logger zerolog.Logger, logFn IOCLoggerCompat) *Puller {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.RuleTTL <= 0 {
		cfg.RuleTTL = 24 * time.Hour
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	return &Puller{
		cfg:    cfg,
		svc:    svc,
		logger: logger.With().Str("component", "ioc-puller").Logger(),
		http:   &http.Client{Timeout: cfg.HTTPTimeout},
		logFn:  logFn,
	}
}

// Run blocks until ctx is cancelled, calling Tick at every interval.
// The first tick fires immediately.
func (p *Puller) Run(ctx context.Context) {
	if p.cfg.BaseURL == "" {
		p.logger.Warn().Msg("ThreatFlow URL empty — IOC puller disabled")
		return
	}
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()

	if err := p.Tick(ctx); err != nil {
		p.logger.Warn().Err(err).Msg("initial pull failed")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.Tick(ctx); err != nil {
				p.logger.Warn().Err(err).Msg("pull failed")
			}
		}
	}
}

// Bundle is the response shape the puller expects from ThreatFlow.
// Fields are conservative — extra fields are ignored.
type Bundle struct {
	Items []Item `json:"items"`
}

// Item is one IOC. The puller only consumes type="ip" entries; other
// types (domain, hash) are skipped.
type Item struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Tick performs one pull. Public so unit tests can drive it directly.
func (p *Puller) Tick(ctx context.Context) error {
	bundle, raw, err := p.fetch(ctx)
	if err != nil {
		metrics.IOCPullsTotal.WithLabelValues("error").Inc()
		return err
	}
	sha := sha256Hex(raw)

	if p.logFn != nil {
		if err := p.logFn(ctx, rules.SourceThreatFlow, sha, len(bundle.Items)); err != nil {
			if isAlreadyIngested(err) {
				metrics.IOCPullsTotal.WithLabelValues("dedup").Inc()
				p.logger.Debug().Str("sha256", sha).Msg("bundle already ingested — skipping apply")
				return nil
			}
			metrics.IOCPullsTotal.WithLabelValues("error").Inc()
			return fmt.Errorf("ioc audit log: %w", err)
		}
	}

	// Build the active-blocklist CIDR set once per tick so we don't
	// thrash repo.Insert with rules that already exist (the prior
	// behaviour produced a duplicate-key error per IOC per tick once
	// the bundle stabilised).
	active := map[string]struct{}{}
	// Request the full active set (up to the repo's hard cap) so the
	// dedup window covers every live blocklist rule, not just the
	// default page.
	if existing, err := p.svc.List(ctx, rules.TypeBlocklist, 100_000, 0); err == nil {
		for _, r := range existing {
			active[r.CIDR] = struct{}{}
		}
	} else {
		p.logger.Warn().Err(err).Msg("could not list active rules for dedup — proceeding without")
	}

	applied := 0
	for _, item := range bundle.Items {
		if !strings.EqualFold(item.Type, "ip") {
			continue
		}
		cidr, err := normaliseIP(item.Value)
		if err != nil {
			p.logger.Debug().Err(err).Str("value", item.Value).Msg("skipping malformed ioc")
			continue
		}
		if _, ok := active[cidr]; ok {
			continue
		}
		req := rules.CreateRequest{
			Type:       rules.TypeBlocklist,
			CIDR:       cidr,
			TTLSeconds: int(p.cfg.RuleTTL.Seconds()),
			Source:     rules.SourceThreatFlow,
		}
		if _, err := p.svc.Create(ctx, req, "threatflow-puller", nil); err != nil {
			p.logger.Debug().Err(err).Str("cidr", cidr).Msg("ioc rule create failed")
			continue
		}
		active[cidr] = struct{}{}
		applied++
		metrics.IOCIngestedTotal.Inc()
	}
	metrics.IOCPullsTotal.WithLabelValues("ok").Inc()
	p.logger.Info().Int("applied", applied).Int("total", len(bundle.Items)).
		Str("sha256", sha).Msg("ioc pull complete")
	return nil
}

func (p *Puller) fetch(ctx context.Context) (Bundle, []byte, error) {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/api/v1/iocs?type=ip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Bundle{}, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return Bundle{}, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Bundle{}, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Bundle{}, nil, fmt.Errorf("threatflow http %d: %s", resp.StatusCode, string(body[:min(len(body), 256)]))
	}
	// Decode with DisallowUnknownFields so a malformed feed (or a
	// hostile one substituted at the network) can't smuggle in extra
	// fields that the rule path would later deserialise. Cap the
	// number of items at maxBundleItems so a (compromised or buggy)
	// ThreatFlow can't push a 16-MiB feed of hundreds of thousands of
	// /32 rules in a single tick — combined with the 16-MiB byte cap
	// above this bounds both the wire size and the in-memory footprint.
	const maxBundleItems = 200_000
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil {
		return Bundle{}, nil, fmt.Errorf("decode threatflow body: %w", err)
	}
	if dec.More() {
		return Bundle{}, nil, fmt.Errorf("decode threatflow body: trailing data after json object")
	}
	if len(bundle.Items) > maxBundleItems {
		return Bundle{}, nil, fmt.Errorf("threatflow bundle has %d items (cap %d)",
			len(bundle.Items), maxBundleItems)
	}
	return bundle, body, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// normaliseIP accepts a bare IP ("198.51.100.7") or a prefix
// ("198.51.100.0/24") and returns the canonical CIDR.
func normaliseIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty ioc value")
	}
	if strings.Contains(s, "/") {
		p, err := rules.ParseCIDR(s)
		if err != nil {
			return "", err
		}
		return p.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("not an ip: %s", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

func isAlreadyIngested(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already ingested")
}
