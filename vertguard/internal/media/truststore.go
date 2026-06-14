package media

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// TrustStore holds an x509.CertPool of trusted C2PA root anchors loaded
// from a directory or single bundle file. Snapshots are swapped
// atomically so Verify never observes a half-loaded pool.
type TrustStore struct {
	dir string

	mu        sync.Mutex
	lastStamp string // concatenated mtime+size fingerprint of the source files

	pool atomic.Pointer[x509.CertPool]
	// anchors holds the parsed certs alongside the pool so the verifier
	// can still pass them as Roots even if reloads happen mid-flight.
	anchors atomic.Pointer[[]*x509.Certificate]
}

// NewTrustStore loads the initial pool from dir. Empty dir is allowed
// (returns a store with an empty pool — every chain will fail to verify
// unless the operator populates the directory and reload triggers).
func NewTrustStore(dir string) (*TrustStore, error) {
	ts := &TrustStore{dir: dir}
	if err := ts.Reload(); err != nil {
		return nil, err
	}
	return ts, nil
}

// Dir returns the configured anchors directory (or empty string).
func (t *TrustStore) Dir() string { return t.dir }

// Pool returns the current snapshot. Always non-nil.
func (t *TrustStore) Pool() *x509.CertPool {
	if p := t.pool.Load(); p != nil {
		return p
	}
	return x509.NewCertPool()
}

// Anchors returns the current parsed anchor list (read-only).
func (t *TrustStore) Anchors() []*x509.Certificate {
	if a := t.anchors.Load(); a != nil {
		return *a
	}
	return nil
}

// Reload re-reads every PEM file in the configured directory (or
// loads the bundle when dir points at a regular file). Safe to call
// concurrently; the swap is atomic.
func (t *TrustStore) Reload() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	pool := x509.NewCertPool()
	var anchors []*x509.Certificate

	if t.dir != "" {
		info, err := os.Stat(t.dir)
		if err != nil {
			if os.IsNotExist(err) {
				// Treat missing dir as empty pool — operator may not
				// have provisioned anchors yet.
				t.pool.Store(pool)
				t.anchors.Store(&anchors)
				t.lastStamp = ""
				return nil
			}
			return fmt.Errorf("truststore stat %q: %w", t.dir, err)
		}

		var files []string
		if info.IsDir() {
			entries, err := os.ReadDir(t.dir)
			if err != nil {
				return fmt.Errorf("truststore read %q: %w", t.dir, err)
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				ext := filepath.Ext(name)
				if ext != ".pem" && ext != ".crt" && ext != ".cer" {
					continue
				}
				files = append(files, filepath.Join(t.dir, name))
			}
		} else {
			files = []string{t.dir}
		}
		sort.Strings(files)

		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("truststore read %q: %w", f, err)
			}
			rest := b
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("truststore parse %q: %w", f, err)
				}
				pool.AddCert(cert)
				anchors = append(anchors, cert)
			}
		}
	}

	t.pool.Store(pool)
	t.anchors.Store(&anchors)
	t.lastStamp = t.fingerprint()
	return nil
}

// fingerprint returns a string built from mtime+size of every source
// file. A change in either triggers a reload via WatchChanges.
func (t *TrustStore) fingerprint() string {
	if t.dir == "" {
		return ""
	}
	info, err := os.Stat(t.dir)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		return fmt.Sprintf("%s:%d:%d", t.dir, info.ModTime().UnixNano(), info.Size())
	}
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var s string
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(t.dir, n))
		if err != nil {
			continue
		}
		s += fmt.Sprintf("%s:%d:%d|", n, fi.ModTime().UnixNano(), fi.Size())
	}
	return s
}

// WatchChanges polls the source every interval and reloads when the
// fingerprint changes. Returns when ctx is done.
func (t *TrustStore) WatchChanges(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			t.mu.Lock()
			cur := t.fingerprint()
			changed := cur != t.lastStamp
			t.mu.Unlock()
			if changed {
				_ = t.Reload()
			}
		}
	}
}

// ErrNoTrustAnchors is returned by VerifyChain when the pool is empty.
var ErrNoTrustAnchors = errors.New("media: trust store has no anchors")

// VerifyChain validates leaf against the current pool, using
// intermediates as supplemental chain candidates. Returns nil on
// success, a structured error otherwise.
func (t *TrustStore) VerifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	pool := t.Pool()
	if len(t.Anchors()) == 0 {
		return ErrNoTrustAnchors
	}
	interPool := x509.NewCertPool()
	for _, c := range intermediates {
		interPool.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: interPool,
		// C2PA signing certs commonly carry CodeSigning or
		// EmailProtection EKUs; permit any so the trust check focuses
		// on chain validity rather than EKU policy.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	return nil
}
