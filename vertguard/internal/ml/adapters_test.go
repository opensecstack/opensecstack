package ml

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/opensecstack/vertguard/internal/ml/pb"
)

func TestMediaEnricher_NilClient(t *testing.T) {
	e := MediaEnricher{}
	res, err := e.ScoreMedia(context.Background(), "h", "m", 1, false, false, "", "")
	if res != nil || err != nil {
		t.Fatalf("nil client should soft-fail: res=%v err=%v", res, err)
	}
	if e.AlwaysScore() {
		t.Fatal("nil client AlwaysScore should be false")
	}
}

func TestMediaEnricher_Delegates(t *testing.T) {
	fake := &fakeServer{scoreResp: &pb.ScoreResponse{Verdict: "BLOCKED", Confidence: 0.9}}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	e := MediaEnricher{C: c}
	res, err := e.ScoreMedia(context.Background(), "h", "m", 1, true, true, "corr", "tenant")
	if err != nil {
		t.Fatalf("ScoreMedia err: %v", err)
	}
	if res.Verdict != "BLOCKED" {
		t.Fatalf("verdict = %q, want BLOCKED", res.Verdict)
	}
	c.cfg.AlwaysScore = true
	if !e.AlwaysScore() {
		t.Fatal("AlwaysScore should delegate to client config")
	}
}

func TestPromptEnricher_NilClient(t *testing.T) {
	p := PromptEnricher{}
	res, err := p.Score(context.Background(), "hi", "user_chat_input")
	if res != nil || err != nil {
		t.Fatalf("nil client should soft-fail: res=%v err=%v", res, err)
	}
	if p.AlwaysScore() {
		t.Fatal("nil client AlwaysScore should be false")
	}
}

func TestPromptEnricher_Delegates(t *testing.T) {
	fake := &fakeServer{scoreResp: &pb.ScoreResponse{Verdict: "SUSPICIOUS", Confidence: 0.5, ModelVersion: "p1"}}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	p := PromptEnricher{C: c}
	res, err := p.Score(context.Background(), "hi", "user_chat_input")
	if err != nil {
		t.Fatalf("Score err: %v", err)
	}
	if res.Verdict != "SUSPICIOUS" || res.ModelVersion != "p1" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestPromptEnricher_ErrorPropagates(t *testing.T) {
	fake := &fakeServer{scoreErr: status.Error(codes.Internal, "boom")}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	p := PromptEnricher{C: c}
	res, err := p.Score(context.Background(), "hi", "user_chat_input")
	if err == nil {
		t.Fatal("expected error to propagate from ScorePrompt failure")
	}
	if res != nil {
		t.Fatalf("expected nil result on error, got %+v", res)
	}
}

func TestAudioEnricher_NilClient(t *testing.T) {
	e := AudioEnricher{}
	res, err := e.ScoreAudio(context.Background(), "s", nil, nil, 0, false, "", "")
	if res != nil || err != nil {
		t.Fatalf("nil client should soft-fail: res=%v err=%v", res, err)
	}
	if e.AlwaysScore() {
		t.Fatal("nil client AlwaysScore should be false")
	}
}

func TestAudioEnricher_Delegates(t *testing.T) {
	fake := &fakeServer{scoreResp: &pb.ScoreResponse{Verdict: "CLEAN"}}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	e := AudioEnricher{C: c}
	res, err := e.ScoreAudio(context.Background(), "sess", []byte("a"), []byte("b"), 100, true, "corr", "tenant")
	if err != nil {
		t.Fatalf("ScoreAudio err: %v", err)
	}
	if res.Verdict != "CLEAN" {
		t.Fatalf("verdict = %q, want CLEAN", res.Verdict)
	}
}

func TestPhishingEnricher_NilClient(t *testing.T) {
	p := PhishingEnricher{}
	res, err := p.ScorePhishing(context.Background(), "url", "url_kind")
	if res != nil || err != nil {
		t.Fatalf("nil client should soft-fail: res=%v err=%v", res, err)
	}
	if p.AlwaysScore() {
		t.Fatal("nil client AlwaysScore should be false")
	}
}

func TestPhishingEnricher_Delegates(t *testing.T) {
	fake := &fakeServer{scoreResp: &pb.ScoreResponse{Verdict: "BLOCKED", ModelVersion: "phish-v2"}}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()
	c := newClientForTest(t, addr, time.Second)
	p := PhishingEnricher{C: c}
	res, err := p.ScorePhishing(context.Background(), "http://bad.example", "url")
	if err != nil {
		t.Fatalf("ScorePhishing err: %v", err)
	}
	if res.Verdict != "BLOCKED" || res.ModelVersion != "phish-v2" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
