package breaker

import (
	"errors"
	"testing"
	"time"
)

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b := New(Config{Name: "t", FailThreshold: 3, CoolDown: time.Hour})
	bad := errors.New("bad")
	for i := 0; i < 3; i++ {
		if err := b.Execute(func() error { return bad }); err != bad {
			t.Fatalf("attempt %d: err = %v, want bad", i, err)
		}
	}
	if got := b.State(); got != StateOpen {
		t.Fatalf("state = %s, want open", got)
	}
	if err := b.Execute(func() error { return nil }); err != ErrOpen {
		t.Fatalf("err = %v, want ErrOpen", err)
	}
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	now := time.Now()
	mockTime := now
	b := New(Config{
		FailThreshold: 1,
		CoolDown:      100 * time.Millisecond,
		Now:           func() time.Time { return mockTime },
	})
	bad := errors.New("bad")
	_ = b.Execute(func() error { return bad })
	if b.State() != StateOpen {
		t.Fatal("expected open")
	}
	mockTime = now.Add(150 * time.Millisecond)
	if b.State() != StateHalfOpen {
		t.Fatalf("after cooldown, state = %s, want half_open", b.State())
	}
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("trial call: %v", err)
	}
	if b.State() != StateClosed {
		t.Fatalf("after success, state = %s, want closed", b.State())
	}
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	now := time.Now()
	mockTime := now
	b := New(Config{
		FailThreshold: 1,
		CoolDown:      100 * time.Millisecond,
		Now:           func() time.Time { return mockTime },
	})
	bad := errors.New("bad")
	_ = b.Execute(func() error { return bad })
	mockTime = now.Add(150 * time.Millisecond)
	_ = b.Execute(func() error { return bad })
	if b.State() != StateOpen {
		t.Fatalf("state = %s, want open after half-open failure", b.State())
	}
}

func TestBreaker_ResetsConsecOnSuccess(t *testing.T) {
	b := New(Config{FailThreshold: 3})
	bad := errors.New("bad")
	_ = b.Execute(func() error { return bad })
	_ = b.Execute(func() error { return bad })
	_ = b.Execute(func() error { return nil })
	// 2 fails then 1 success — consec reset; next 2 fails should not trip.
	_ = b.Execute(func() error { return bad })
	_ = b.Execute(func() error { return bad })
	if b.State() == StateOpen {
		t.Fatal("breaker should not be open: success reset consec")
	}
}
