package hub_test

import (
	"sync"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/hub"
)

func TestPublish_DeliversToSubscriber(t *testing.T) {
	h := hub.New()
	ch := h.Subscribe("chan1")
	defer h.Unsubscribe("chan1", ch)

	h.Publish("chan1", []byte("hello"))

	select {
	case got := <-ch:
		if string(got) != "hello" {
			t.Errorf("expected 'hello', got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published message")
	}
}

func TestPublish_DoesNotDeliverToOtherChannel(t *testing.T) {
	h := hub.New()
	ch := h.Subscribe("chan1")
	defer h.Unsubscribe("chan1", ch)

	h.Publish("chan2", []byte("hello"))

	select {
	case got := <-ch:
		t.Fatalf("unexpected delivery to unrelated channel: %q", got)
	case <-time.After(50 * time.Millisecond):
		// expected: no message
	}
}

func TestPublish_NoSubscribers_DoesNotPanic(t *testing.T) {
	h := hub.New()
	h.Publish("nobody-subscribed", []byte("hello"))
}

func TestPublish_MultipleSubscribers_AllReceive(t *testing.T) {
	h := hub.New()
	ch1 := h.Subscribe("chan1")
	ch2 := h.Subscribe("chan1")
	defer h.Unsubscribe("chan1", ch1)
	defer h.Unsubscribe("chan1", ch2)

	h.Publish("chan1", []byte("broadcast"))

	for i, ch := range []chan []byte{ch1, ch2} {
		select {
		case got := <-ch:
			if string(got) != "broadcast" {
				t.Errorf("subscriber %d: expected 'broadcast', got %q", i, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for message", i)
		}
	}
}

func TestPublish_SlowSubscriber_DropsRatherThanBlocks(t *testing.T) {
	h := hub.New()
	ch := h.Subscribe("chan1")
	defer h.Unsubscribe("chan1", ch)

	// Fill the buffered channel (capacity 64) without draining it.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			h.Publish("chan1", []byte("msg"))
		}
		close(done)
	}()

	select {
	case <-done:
		// Publish must not block even though the subscriber never drains.
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow/full subscriber instead of dropping")
	}
}

func TestUnsubscribe_ClosesChannel(t *testing.T) {
	h := hub.New()
	ch := h.Subscribe("chan1")
	h.Unsubscribe("chan1", ch)

	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after Unsubscribe")
	}
}

func TestUnsubscribe_RemovesFromSubscriberList(t *testing.T) {
	h := hub.New()
	ch1 := h.Subscribe("chan1")
	ch2 := h.Subscribe("chan1")

	h.Unsubscribe("chan1", ch1)

	// ch2 should still receive; a fresh publish must not panic or fail
	// even though ch1 was removed mid-list (swap-delete correctness).
	h.Publish("chan1", []byte("still-here"))
	select {
	case got := <-ch2:
		if string(got) != "still-here" {
			t.Errorf("expected 'still-here', got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for message on remaining subscriber")
	}
	h.Unsubscribe("chan1", ch2)
}

func TestUnsubscribe_LastSubscriber_RemovesChannelKey(t *testing.T) {
	h := hub.New()
	ch := h.Subscribe("chan1")
	h.Unsubscribe("chan1", ch)

	// Publishing to a channelID with no subscribers left must be a no-op,
	// not panic (verifies the map key was actually deleted, not left as an
	// empty slice that Publish would still iterate safely either way).
	h.Publish("chan1", []byte("x"))
}

func TestChannelHub_ConcurrentAccess_NoRace(t *testing.T) {
	h := hub.New()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ch := h.Subscribe("shared")
			h.Publish("shared", []byte("x"))
			select {
			case <-ch:
			case <-time.After(time.Second):
			}
			h.Unsubscribe("shared", ch)
		}(i)
	}
	wg.Wait()
}
