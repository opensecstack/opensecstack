package main

import (
	"context"
	"errors"
	"testing"
)

type stubPinger struct {
	err error
}

func (s *stubPinger) Ping(ctx context.Context) error {
	return s.err
}

func TestPoolPinger_Ping_ReturnsUnderlyingPoolError(t *testing.T) {
	wantErr := errors.New("connection refused")
	p := &poolPinger{pool: &stubPinger{err: wantErr}}

	if err := p.Ping(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("expected Ping to return the underlying pool error, got %v", err)
	}
}

func TestPoolPinger_Ping_Success(t *testing.T) {
	p := &poolPinger{pool: &stubPinger{err: nil}}

	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("expected nil error on successful ping, got %v", err)
	}
}
