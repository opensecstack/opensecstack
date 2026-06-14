package stix

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkParseBundle_100Objects measures the throughput of parsing a 100-
// indicator STIX bundle — representative of a small TAXII poll. Target from
// the v1.0.0 roadmap is ≥10K IOCs/sec end-to-end; the parser alone is
// typically 20–30× faster than that so there is ample headroom.
func BenchmarkParseBundle_100Objects(b *testing.B) {
	payload := buildBundle(100)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bundle, err := ParseBundle(payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeObjects(bundle); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParsePattern_SimpleEquality exercises the hot path every
// feed-originated indicator takes before it becomes an `iocs` row.
func BenchmarkParsePattern_SimpleEquality(b *testing.B) {
	p := `[ipv4-addr:value = '203.0.113.42']`
	for i := 0; i < b.N; i++ {
		if _, _, err := PrimaryIOC(p); err != nil {
			b.Fatal(err)
		}
	}
}

// buildBundle constructs a bundle with n synthetic indicators — used by the
// benchmarks above and by importer benchmarks in other packages.
func buildBundle(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb,
			`{"type":"indicator","spec_version":"2.1","id":"indicator--%08x-0000-4000-8000-000000000000","created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '10.0.%d.%d']","pattern_type":"stix","valid_from":"2026-01-01T00:00:00Z","confidence":75,"labels":["c2"]}`,
			uint32(i+1), i/256, i%256,
		)
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}
