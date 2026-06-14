package webhook

import "testing"

// BenchmarkSignPayload measures HMAC-SHA256 signing throughput — every
// webhook delivery computes one of these, so it gates the dispatcher's
// max fan-out rate.
func BenchmarkSignPayload(b *testing.B) {
	secret := "long-enough-secret-to-match-realistic-deployments"
	ts := "1745123456"
	body := []byte(`{"type":"ioc.created","payload":{"type":"ipv4-addr","value":"10.0.0.1","confidence":85,"tags":["c2","malware"]}}`)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signPayload(secret, ts, body)
	}
}

// BenchmarkVerifySignature measures the cost a subscriber pays per event.
// Constant-time compare means verify ≈ sign; kept separate to document the
// expected 1:1 throughput ratio.
func BenchmarkVerifySignature(b *testing.B) {
	secret := "long-enough-secret-to-match-realistic-deployments"
	ts := "1745123456"
	body := []byte(`{"type":"sighting.reported","payload":{"ioc_value":"evil.example"}}`)
	sig := signPayload(secret, ts, body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifySignature(secret, ts, sig, body) {
			b.Fatal("verify failed")
		}
	}
}
