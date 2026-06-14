// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package hub

import "sync"

// ChannelHub is an in-memory pub/sub hub for channel message events.
// It is safe for concurrent use.
type ChannelHub struct {
	mu   sync.RWMutex
	subs map[string][]chan []byte // channelID -> list of subscriber channels
}

// New returns an initialised ChannelHub.
func New() *ChannelHub {
	return &ChannelHub{
		subs: make(map[string][]chan []byte),
	}
}

// Publish sends payload to all subscribers of channelID.
// Non-blocking: slow subscribers are skipped (dropped message is acceptable).
func (h *ChannelHub) Publish(channelID string, payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, ch := range h.subs[channelID] {
		select {
		case ch <- payload:
		default:
			// subscriber is too slow; drop the message rather than block
		}
	}
}

// Subscribe returns a buffered channel that receives published payloads for
// channelID. The caller must call Unsubscribe when done to avoid a resource
// leak.
func (h *ChannelHub) Subscribe(channelID string) chan []byte {
	ch := make(chan []byte, 64)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.subs[channelID] = append(h.subs[channelID], ch)
	return ch
}

// Unsubscribe removes and closes the subscriber channel returned by a prior
// call to Subscribe.
func (h *ChannelHub) Unsubscribe(channelID string, ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	list := h.subs[channelID]
	for i, c := range list {
		if c == ch {
			// swap-delete to avoid shifting
			list[i] = list[len(list)-1]
			h.subs[channelID] = list[:len(list)-1]
			break
		}
	}
	if len(h.subs[channelID]) == 0 {
		delete(h.subs, channelID)
	}
	close(ch)
}
