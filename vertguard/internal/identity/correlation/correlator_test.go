package correlation

import (
	"context"
	"testing"
	"time"
)

// newTestCorrelator returns a Correlator with short windows suitable for tests.
func newTestCorrelator(t *testing.T, threshold, graphThreshold int, window, graphWindow time.Duration) *Correlator {
	t.Helper()
	return New(Config{
		Window:         window,
		Threshold:      threshold,
		GraphWindow:    graphWindow,
		GraphThreshold: graphThreshold,
		JanitorPeriod:  window * 10, // disable automatic eviction during tests
	})
}

func TestRecordAndCheck_BelowThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		hits      int
	}{
		{"one_hit_threshold_3", 3, 1},
		{"two_hits_threshold_3", 3, 2},
		{"one_hit_threshold_5", 5, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCorrelator(t, tc.threshold, 10, time.Hour, time.Hour*72)
			fp := Fingerprint("passport", "abc123hash", "tenant-a")
			gk := graphKey{issuerCountry: "AL", emailDisposable: false, claimType: "passport"}

			var res Result
			for i := 0; i < tc.hits; i++ {
				res = c.RecordAndCheck(context.Background(), fp, gk)
			}
			if res.IsSuspicious {
				t.Errorf("hits=%d threshold=%d: IsSuspicious=true, want false", tc.hits, tc.threshold)
			}
			if res.Count != tc.hits {
				t.Errorf("Count=%d, want %d", res.Count, tc.hits)
			}
			if res.Fingerprint != fp {
				t.Errorf("Fingerprint=%q, want %q", res.Fingerprint, fp)
			}
		})
	}
}

func TestRecordAndCheck_AtThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		hits      int // hits >= threshold → suspicious
	}{
		{"exactly_at_threshold_3", 3, 3},
		{"above_threshold_3", 3, 5},
		{"exactly_at_threshold_5", 5, 5},
		{"above_threshold_5", 5, 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCorrelator(t, tc.threshold, 10, time.Hour, time.Hour*72)
			fp := Fingerprint("national_id", "deadbeef", "tenant-b")
			gk := graphKey{issuerCountry: "US", emailDisposable: true, claimType: "national_id"}

			var res Result
			for i := 0; i < tc.hits; i++ {
				res = c.RecordAndCheck(context.Background(), fp, gk)
			}
			if !res.IsSuspicious {
				t.Errorf("hits=%d threshold=%d: IsSuspicious=false, want true", tc.hits, tc.threshold)
			}
			if res.Count != tc.hits {
				t.Errorf("Count=%d, want %d", res.Count, tc.hits)
			}
		})
	}
}

func TestRecordAndCheck_WindowExpiry(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		// preFill is the number of hits before the window expires.
		preFill int
	}{
		{"hits_reset_after_window_threshold_3", 3, 3},
		{"hits_reset_after_window_threshold_5", 5, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use a very short window so we can manipulate time via evict().
			window := 50 * time.Millisecond
			c := newTestCorrelator(t, tc.threshold, 10, window, time.Hour*72)
			fp := Fingerprint("driver_license", "cafebabe", "tenant-c")
			gk := graphKey{issuerCountry: "DE", emailDisposable: false, claimType: "driver_license"}

			// Pre-fill to threshold → should be suspicious.
			var res Result
			for i := 0; i < tc.preFill; i++ {
				res = c.RecordAndCheck(context.Background(), fp, gk)
			}
			if !res.IsSuspicious {
				t.Fatalf("pre-window: IsSuspicious=false, want true (hits=%d threshold=%d)", tc.preFill, tc.threshold)
			}

			// Wait for the window to expire, then force a manual eviction via
			// RecordAndCheck which resets the entry when firstSeen is past window.
			time.Sleep(window + 10*time.Millisecond)

			// A single new hit after window expiry must reset the counter.
			res = c.RecordAndCheck(context.Background(), fp, gk)
			if res.IsSuspicious {
				t.Errorf("post-window: IsSuspicious=true, want false (count reset expected)")
			}
			if res.Count != 1 {
				t.Errorf("post-window: Count=%d, want 1 (counter should have reset)", res.Count)
			}
		})
	}
}

func TestRecordAndCheck_ActorGraph(t *testing.T) {
	tests := []struct {
		name           string
		graphThreshold int
		fps            []string // distinct fingerprints sharing the same graphKey
		wantLinked     bool
	}{
		{
			name:           "two_fps_threshold_2",
			graphThreshold: 2,
			fps:            []string{"fp-alpha", "fp-beta"},
			wantLinked:     true,
		},
		{
			name:           "one_fp_threshold_2_not_linked",
			graphThreshold: 2,
			fps:            []string{"fp-only"},
			wantLinked:     false,
		},
		{
			name:           "three_fps_threshold_2",
			graphThreshold: 2,
			fps:            []string{"fp-one", "fp-two", "fp-three"},
			wantLinked:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCorrelator(t, 100, tc.graphThreshold, time.Hour, time.Hour*72)
			gk := graphKey{issuerCountry: "RU", emailDisposable: true, claimType: "passport"}

			var res Result
			for _, fp := range tc.fps {
				res = c.RecordAndCheck(context.Background(), fp, gk)
			}
			if res.ActorLinked != tc.wantLinked {
				t.Errorf("fps=%v graphThreshold=%d: ActorLinked=%v, want %v (LinkedCount=%d)",
					tc.fps, tc.graphThreshold, res.ActorLinked, tc.wantLinked, res.LinkedCount)
			}
			if tc.wantLinked && res.LinkedCount < tc.graphThreshold {
				t.Errorf("LinkedCount=%d, want >= %d", res.LinkedCount, tc.graphThreshold)
			}
		})
	}
}

func TestEvict_RemovesStaleEntries(t *testing.T) {
	window := 30 * time.Millisecond
	graphWindow := 30 * time.Millisecond
	c := newTestCorrelator(t, 3, 2, window, graphWindow)

	fp := Fingerprint("passport", "staleentry", "tenant-evict")
	gk := graphKey{issuerCountry: "CN", emailDisposable: false, claimType: "passport"}

	// Record a hit so entries exist.
	c.RecordAndCheck(context.Background(), fp, gk)
	if c.Count(fp) != 1 {
		t.Fatalf("Count before evict = %d, want 1", c.Count(fp))
	}

	// Wait past 2× window and 2× graphWindow (both cutoffs use -2*<window>).
	time.Sleep(window*2 + graphWindow*2 + 20*time.Millisecond)

	// Call evict with current time to trigger cleanup past all cutoffs.
	c.evict(time.Now())

	if got := c.Count(fp); got != 0 {
		t.Errorf("Count after evict = %d, want 0 (fingerprint entry should be evicted)", got)
	}

	// Actor graph entry should also be gone.
	c.mu.Lock()
	_, graphExists := c.actorGraph[gk]
	c.mu.Unlock()
	if graphExists {
		t.Errorf("actorGraph entry still present after evict, want removed")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	tests := []struct {
		name      string
		claimType string
		idHash    string
		tenant    string
	}{
		{"passport_us", "passport", "aabbccdd", "acme"},
		{"national_id_al", "national_id", "11223344", "tenant-x"},
		{"driver_license_de", "driver_license", "deadbeef", "my-org"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fp1 := Fingerprint(tc.claimType, tc.idHash, tc.tenant)
			fp2 := Fingerprint(tc.claimType, tc.idHash, tc.tenant)
			if fp1 != fp2 {
				t.Errorf("not deterministic: %q != %q", fp1, fp2)
			}
			if len(fp1) == 0 {
				t.Error("empty fingerprint")
			}
		})
	}

	// Different inputs must produce different fingerprints.
	diffTests := []struct {
		name string
		a, b [3]string // {claimType, idHash, tenant}
	}{
		{
			name: "different_claim_type",
			a:    [3]string{"passport", "hash1", "tenant"},
			b:    [3]string{"national_id", "hash1", "tenant"},
		},
		{
			name: "different_id_hash",
			a:    [3]string{"passport", "hash1", "tenant"},
			b:    [3]string{"passport", "hash2", "tenant"},
		},
		{
			name: "different_tenant",
			a:    [3]string{"passport", "hash1", "tenant-a"},
			b:    [3]string{"passport", "hash1", "tenant-b"},
		},
	}
	for _, tc := range diffTests {
		t.Run(tc.name, func(t *testing.T) {
			fpA := Fingerprint(tc.a[0], tc.a[1], tc.a[2])
			fpB := Fingerprint(tc.b[0], tc.b[1], tc.b[2])
			if fpA == fpB {
				t.Errorf("collision on different inputs: both produced %q", fpA)
			}
		})
	}
}
