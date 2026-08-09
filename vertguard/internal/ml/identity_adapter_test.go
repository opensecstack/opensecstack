package ml

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/identity"
	pb "github.com/opensecstack/vertguard/internal/ml/pb"
)

func TestNewIdentityAdapter_NilClient(t *testing.T) {
	a := NewIdentityAdapter(nil)
	if a != nil {
		t.Fatalf("NewIdentityAdapter(nil) = %v, want nil", a)
	}
}

func TestNewIdentityAdapter_WrapsClient(t *testing.T) {
	addr, cleanup := newTestServer(t, &fakeServer{})
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	a := NewIdentityAdapter(c)
	if a == nil {
		t.Fatal("NewIdentityAdapter(non-nil) returned nil")
	}
}

func TestIdentityAdapter_AlwaysScore(t *testing.T) {
	addr, cleanup := newTestServer(t, &fakeServer{})
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	a := NewIdentityAdapter(c)
	if a.AlwaysScore() {
		t.Fatal("AlwaysScore should be false by default")
	}
	c.cfg.AlwaysScore = true
	if !a.AlwaysScore() {
		t.Fatal("AlwaysScore should reflect underlying client config")
	}
}

func TestIdentityAdapter_ScoreIdentity_Success(t *testing.T) {
	fake := &fakeServer{
		scoreResp: &pb.ScoreResponse{Confidence: 0.8, Verdict: "SUSPICIOUS", ModelVersion: "id-v1", LatencyMs: 12.5},
	}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	a := NewIdentityAdapter(c)

	claim := identity.ClaimRequest{
		ClaimType: identity.ClaimPassport,
		Context:   identity.ContextKYC,
		Fields: map[string]string{
			"name":           "Albi Hoxha",
			"issuer_country": "al",
			"dob":            "1990-01-01",
		},
	}
	res, err := a.ScoreIdentity(context.Background(), claim)
	if err != nil {
		t.Fatalf("ScoreIdentity err: %v", err)
	}
	if res.Verdict != "SUSPICIOUS" || res.ModelVersion != "id-v1" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Confidence != 0.8 {
		t.Fatalf("confidence = %v, want 0.8", res.Confidence)
	}
	if res.LatencyMs != 12.5 {
		t.Fatalf("latency = %v, want 12.5", res.LatencyMs)
	}
}

func TestIdentityAdapter_ScoreIdentity_ErrorPropagates(t *testing.T) {
	addr, cleanup := newTestServer(t, &fakeServer{scoreErr: context.DeadlineExceeded})
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	a := NewIdentityAdapter(c)

	claim := identity.ClaimRequest{ClaimType: identity.ClaimPassport, Fields: map[string]string{}}
	res, err := a.ScoreIdentity(context.Background(), claim)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if res != nil {
		t.Fatalf("expected nil result on error, got %+v", res)
	}
}

func TestCountTokens(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"Albi", 1},
		{"Albi Hoxha", 2},
		{"  Albi   Hoxha  ", 2},
		{"Jean-Paul", 2},
		{"O'Brien Smith", 3},
		{"   ", 0},
	}
	for _, c := range cases {
		if got := countTokens(c.in); got != c.want {
			t.Errorf("countTokens(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
