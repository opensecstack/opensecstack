package ioc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Source is the contract every community-feed adapter satisfies.
// Name() must be stable — it doubles as the metric label and the
// audit-row source column.
type Source interface {
	Name() string
	Fetch(ctx context.Context) ([]IOC, error)
}

// ─── FileSource ─────────────────────────────────────────────────────

// FileSource reads a JSON array of IOCs from a local file. Used by
// tests and air-gapped deployments that pre-stage curated feeds via
// rsync / object storage.
type FileSource struct {
	NameTag string
	Path    string
}

func (f FileSource) Name() string {
	if f.NameTag != "" {
		return f.NameTag
	}
	return "file"
}

func (f FileSource) Fetch(ctx context.Context) ([]IOC, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Path, err)
	}
	var raw []struct {
		Kind       string   `json:"kind"`
		Value      string   `json:"value"`
		Confidence float64  `json:"confidence"`
		Tags       []string `json:"tags"`
		ExpiresAt  string   `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", f.Path, err)
	}
	out := make([]IOC, 0, len(raw))
	for _, r := range raw {
		ioc := IOC{
			Kind:       Kind(r.Kind),
			Value:      strings.TrimSpace(r.Value),
			Source:     f.Name(),
			Confidence: r.Confidence,
			Tags:       r.Tags,
		}
		if r.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil {
				ioc.ExpiresAt = &t
			}
		}
		if ioc.Confidence == 0 {
			ioc.Confidence = 0.5
		}
		out = append(out, ioc)
	}
	return out, nil
}

// ─── MISPSource ─────────────────────────────────────────────────────

// MISPSource pulls a MISP feed manifest of "Attribute" objects.
// Conservative subset of MISP's schema — only the fields the puller
// needs are decoded so feed-side additions don't break ingestion.
type MISPSource struct {
	NameTag    string
	URL        string
	AuthHeader string // forwarded verbatim (e.g. "Bearer xyz" or a raw API key)
	HTTPClient *http.Client
}

func (m MISPSource) Name() string {
	if m.NameTag != "" {
		return m.NameTag
	}
	return "misp"
}

func (m MISPSource) Fetch(ctx context.Context) ([]IOC, error) {
	if m.URL == "" {
		return nil, fmt.Errorf("misp: empty URL")
	}
	cli := m.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if m.AuthHeader != "" {
		req.Header.Set("Authorization", m.AuthHeader)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("misp http %d", resp.StatusCode)
	}
	var doc struct {
		Response []struct {
			Attribute []struct {
				Type    string `json:"type"`
				Value   string `json:"value"`
				Comment string `json:"comment"`
			} `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode misp: %w", err)
	}
	out := []IOC{}
	for _, ev := range doc.Response {
		for _, a := range ev.Attribute {
			k, ok := mispTypeToKind(a.Type)
			if !ok {
				continue
			}
			out = append(out, IOC{
				Kind:       k,
				Value:      strings.TrimSpace(a.Value),
				Source:     m.Name(),
				Confidence: 0.7,
				Tags:       []string{"misp"},
			})
		}
	}
	return out, nil
}

func mispTypeToKind(t string) (Kind, bool) {
	switch strings.ToLower(t) {
	case "ip-src", "ip-dst", "ip":
		return KindIP, true
	case "domain", "hostname":
		return KindDomain, true
	case "url":
		return KindURL, true
	case "sha256":
		return KindHashSHA256, true
	case "md5":
		return KindHashMD5, true
	}
	return "", false
}

// ─── AbuseChSource ──────────────────────────────────────────────────

// AbuseChSource fetches the plaintext URL list and the SHA-256 hash
// list. Both are simple line-oriented feeds — comment lines start with
// '#' and blank lines are ignored. URL is the URLhaus endpoint;
// HashURL is the MalwareBazaar SHA-256 list. Either may be empty.
type AbuseChSource struct {
	NameTag    string
	URL        string // URL list (URLhaus)
	HashURL    string // SHA-256 list (MalwareBazaar)
	HTTPClient *http.Client
}

func (a AbuseChSource) Name() string {
	if a.NameTag != "" {
		return a.NameTag
	}
	return "abuse_ch"
}

func (a AbuseChSource) Fetch(ctx context.Context) ([]IOC, error) {
	cli := a.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}
	out := []IOC{}
	if a.URL != "" {
		lines, err := fetchLines(ctx, cli, a.URL)
		if err != nil {
			return nil, fmt.Errorf("abuse_ch urls: %w", err)
		}
		for _, l := range lines {
			out = append(out, IOC{
				Kind: KindURL, Value: l, Source: a.Name(),
				Confidence: 0.8, Tags: []string{"urlhaus"},
			})
		}
	}
	if a.HashURL != "" {
		lines, err := fetchLines(ctx, cli, a.HashURL)
		if err != nil {
			return nil, fmt.Errorf("abuse_ch hashes: %w", err)
		}
		for _, l := range lines {
			out = append(out, IOC{
				Kind: KindHashSHA256, Value: l, Source: a.Name(),
				Confidence: 0.85, Tags: []string{"malwarebazaar"},
			})
		}
	}
	return out, nil
}

func fetchLines(ctx context.Context, cli *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, sc.Err()
}
