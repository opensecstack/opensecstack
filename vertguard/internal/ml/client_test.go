package ml

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/opensecstack/vertguard/internal/breaker"
	mlpb "github.com/opensecstack/vertguard/internal/ml/pb"
)

// fakeServer satisfies mlpb.InferenceServiceServer for unit tests.
// Each method returns a programmable response so individual tests can
// drive the success / failure / timeout paths without spinning up the
// real Python service.
type fakeServer struct {
	mlpb.UnimplementedInferenceServiceServer

	scoreResp *mlpb.ScoreResponse
	scoreErr  error
	infoResp  *mlpb.ModelInfoResponse
	infoErr   error
	delay     time.Duration
}

func (f *fakeServer) ScorePrompt(ctx context.Context, req *mlpb.PromptScoreRequest) (*mlpb.ScoreResponse, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, status.Error(codes.DeadlineExceeded, "timeout")
		}
	}
	if f.scoreErr != nil {
		return nil, f.scoreErr
	}
	return f.scoreResp, nil
}

func (f *fakeServer) ScorePhishing(ctx context.Context, req *mlpb.PhishingScoreRequest) (*mlpb.ScoreResponse, error) {
	if f.scoreErr != nil {
		return nil, f.scoreErr
	}
	return f.scoreResp, nil
}

func (f *fakeServer) ModelInfo(ctx context.Context, req *mlpb.ModelInfoRequest) (*mlpb.ModelInfoResponse, error) {
	if f.infoErr != nil {
		return nil, f.infoErr
	}
	return f.infoResp, nil
}

// newTestServer spins up an in-process gRPC server on a random
// loopback port and returns the dial address + a teardown.
func newTestServer(t *testing.T, fake *fakeServer) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// ForceServerCodec routes server de/serialisation through our
	// hand-written wire codec — same as the client side.
	srv := grpc.NewServer(grpc.ForceServerCodec(mlpb.Codec{}))
	mlpb.RegisterInferenceServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), func() {
		srv.Stop()
		_ = lis.Close()
	}
}

// newClientForTest builds a Client wired to the test server with a
// loose breaker (5 failures = trip).
func newClientForTest(t *testing.T, addr string, timeout time.Duration) *Client {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &Client{
		cfg:  Config{GRPCURL: addr, Timeout: timeout, Enabled: true},
		conn: conn,
		stub: mlpb.NewInferenceServiceClient(conn),
		breaker: breaker.New(breaker.Config{
			Name: "ml-test", FailThreshold: 5, CoolDown: 5 * time.Second,
		}),
		metrics: noopMetrics{},
		logger:  zerolog.Nop(),
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestScorePrompt_Success(t *testing.T) {
	fake := &fakeServer{
		scoreResp: &mlpb.ScoreResponse{
			Confidence:   0.92,
			Verdict:      "BLOCKED",
			ModelVersion: "v1.0.0",
			InputHash:    "sha256:deadbeef",
		},
	}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()

	c := newClientForTest(t, addr, 1*time.Second)
	res, err := c.ScorePrompt(context.Background(), "hello", "user_chat_input", "corr-1", "")
	if err != nil {
		t.Fatalf("ScorePrompt err: %v", err)
	}
	if res.Verdict != "BLOCKED" {
		t.Fatalf("verdict=%q, want BLOCKED", res.Verdict)
	}
	if res.Confidence < 0.91 || res.Confidence > 0.93 {
		t.Fatalf("confidence=%v, want ≈0.92", res.Confidence)
	}
}

func TestScorePrompt_BreakerOpensOnRepeatedFailures(t *testing.T) {
	fake := &fakeServer{scoreErr: status.Error(codes.Internal, "boom")}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()

	c := newClientForTest(t, addr, 500*time.Millisecond)
	// 5 consecutive failures trips the breaker; the 6th call short-circuits.
	for i := 0; i < 5; i++ {
		if _, err := c.ScorePrompt(context.Background(), "x", "", "", ""); err == nil {
			t.Fatalf("expected error on attempt %d, got nil", i)
		}
	}
	_, err := c.ScorePrompt(context.Background(), "x", "", "", "")
	if !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("want ErrMLUnavailable, got %v", err)
	}
}

func TestScorePrompt_Timeout(t *testing.T) {
	fake := &fakeServer{
		scoreResp: &mlpb.ScoreResponse{Verdict: "CLEAN"},
		delay:     100 * time.Millisecond,
	}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()

	c := newClientForTest(t, addr, 10*time.Millisecond)
	if _, err := c.ScorePrompt(context.Background(), "x", "", "", ""); err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestModelInfo_RoundTrip(t *testing.T) {
	fake := &fakeServer{
		infoResp: &mlpb.ModelInfoResponse{
			Name:     "distilbert-prompt-v1",
			Version:  "1.0.0",
			Backend:  "onnx-cpu",
			LoadedAt: 1700000000,
		},
	}
	addr, cleanup := newTestServer(t, fake)
	defer cleanup()

	c := newClientForTest(t, addr, 1*time.Second)
	info, err := c.ModelInfo(context.Background())
	if err != nil {
		t.Fatalf("ModelInfo err: %v", err)
	}
	if info.Name != "distilbert-prompt-v1" || info.Backend != "onnx-cpu" {
		t.Fatalf("unexpected info: %+v", info)
	}
}
