package media

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// revokedCertTotal counts manifests rejected because their signing
// cert appears in the configured CRL. Registered against the default
// Prometheus registry so the package can self-instrument without
// taking a *metrics.Registry dependency.
var revokedCertTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "vertguard_media_revoked_cert_total",
	Help: "C2PA verifications rejected because the signing certificate was on the configured CRL.",
})

// RevocationList holds a serial-number set parsed from a CRL file
// (PEM or DER). Empty path → empty set (every cert is non-revoked).
type RevocationList struct {
	path string

	mu        sync.Mutex
	lastStamp string

	// serials maps decimal serial-string → struct{}. We use the
	// decimal form because *big.Int is not comparable; callers
	// translate the cert serial via serialKey.
	serials atomic.Pointer[map[string]struct{}]
}

// NewRevocationList loads the initial CRL. Empty path is allowed.
func NewRevocationList(path string) (*RevocationList, error) {
	rl := &RevocationList{path: path}
	if err := rl.Reload(); err != nil {
		return nil, err
	}
	return rl, nil
}

// Path returns the configured CRL path (may be empty).
func (r *RevocationList) Path() string { return r.path }

// Reload re-reads the CRL file. Safe for concurrent calls.
func (r *RevocationList) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	set := map[string]struct{}{}
	if r.path == "" {
		r.serials.Store(&set)
		r.lastStamp = ""
		return nil
	}

	b, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			r.serials.Store(&set)
			r.lastStamp = ""
			return nil
		}
		return fmt.Errorf("crl read %q: %w", r.path, err)
	}

	der := b
	if block, _ := pem.Decode(b); block != nil && (block.Type == "X509 CRL" || block.Type == "CRL") {
		der = block.Bytes
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("crl parse %q: %w", r.path, err)
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber != nil {
			set[serialKey(e.SerialNumber)] = struct{}{}
		}
	}

	r.serials.Store(&set)
	r.lastStamp = r.fingerprint()
	return nil
}

// IsRevoked reports whether the given cert's serial is in the CRL.
// Increments the revoked-cert metric when true.
func (r *RevocationList) IsRevoked(cert *x509.Certificate) bool {
	if cert == nil || cert.SerialNumber == nil {
		return false
	}
	set := r.serials.Load()
	if set == nil {
		return false
	}
	if _, ok := (*set)[serialKey(cert.SerialNumber)]; ok {
		revokedCertTotal.Inc()
		return true
	}
	return false
}

// serialKey converts a serial to a stable decimal-string key.
func serialKey(n *big.Int) string { return n.Text(10) }

func (r *RevocationList) fingerprint() string {
	if r.path == "" {
		return ""
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
}

// WatchChanges polls the CRL file and reloads when mtime/size change.
func (r *RevocationList) WatchChanges(stop <-chan struct{}, interval time.Duration) {
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
			r.mu.Lock()
			cur := r.fingerprint()
			changed := cur != r.lastStamp
			r.mu.Unlock()
			if changed {
				_ = r.Reload()
			}
		}
	}
}
