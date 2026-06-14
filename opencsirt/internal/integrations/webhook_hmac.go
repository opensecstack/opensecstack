// Package integrations holds inbound webhook receivers and outbound
// clients for sibling opensecstack platforms (ThreatFlow, IRFlow,
// NIS2 Compass, VertGuard).
package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// replayWindow is the maximum allowed clock drift for webhook timestamps.
const replayWindow = 5 * time.Minute

// nonceSweepInterval controls how often expired nonces are evicted.
// Half the window ensures no nonce outlives its validity period.
const nonceSweepInterval = replayWindow / 2

// nonceEntry records when a nonce was first seen so the sweeper can expire it.
type nonceEntry struct {
	seenAt time.Time
}

// nonceCache is an in-memory replay-prevention store.
// LIMITATION: nonces are lost on process restart, so a restarted pod accepts
// replays for up to the replayWindow duration. For cluster deployments with
// rolling updates, use a shared Redis/DB-backed nonce store instead.
var (
	nonceMu   sync.Mutex
	nonceSet  = map[string]nonceEntry{}
	nonceOnce sync.Once
)

// startNonceSweeper launches the background goroutine that evicts expired
// nonces. Called lazily on first VerifyHMAC use to avoid init-order issues.
func startNonceSweeper() {
	// TODO(ops): no package-level logger is available here; wire one in and
	// emit the warning below so operators see it at startup:
	// logger.Warn().Msg("webhook_hmac: nonce cache is in-memory; replays possible across pod restarts — use Redis-backed store in production clusters")
	go func() {
		t := time.NewTicker(nonceSweepInterval)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-replayWindow)
			nonceMu.Lock()
			for k, e := range nonceSet {
				if e.seenAt.Before(cutoff) {
					delete(nonceSet, k)
				}
			}
			nonceMu.Unlock()
		}
	}()
}

// deriveNonce produces a deterministic replay token from the request body
// and timestamp. Because the HMAC already binds body+ts to the secret,
// using sha256(body+ts) as the nonce key is sufficient to detect exact
// replays of a previously accepted request.
func deriveNonce(ts string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(ts))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC validates the IRFlow / VertGuard webhook signature scheme:
//
//	X-Signature: hex(HMAC-SHA256(secret, ts || "." || body))
//	X-Timestamp: RFC3339, must be within ±5 min of now.
//
// It also enforces single-use nonces for the duration of the replay window
// so that a captured valid request cannot be replayed.
func VerifyHMAC(secret []byte, ts, sig string, body []byte) error {
	nonceOnce.Do(startNonceSweeper)

	if secret == nil {
		return errors.New("integrations: hmac secret not configured")
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return errors.New("integrations: invalid timestamp")
	}
	if drift := time.Since(t); drift < 0 || drift > replayWindow {
		return errors.New("integrations: timestamp outside replay window")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	want := mac.Sum(nil)
	got, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil {
		return errors.New("integrations: invalid signature hex")
	}
	if !hmac.Equal(want, got) {
		return errors.New("integrations: signature mismatch")
	}

	// Nonce check — reject replays of already-seen (body, timestamp) pairs.
	nonce := deriveNonce(ts, body)
	nonceMu.Lock()
	defer nonceMu.Unlock()
	if _, seen := nonceSet[nonce]; seen {
		return errors.New("integrations: replayed request")
	}
	nonceSet[nonce] = nonceEntry{seenAt: time.Now()}
	return nil
}
