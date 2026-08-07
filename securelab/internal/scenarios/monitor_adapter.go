// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/opensecstack/securelab/internal/detection"
)

// MonitorAdapter wraps a *detection.Monitor and implements DetectionMonitor.
// WaitForDetection calls WatchAlerts with no run-ID or technique filter and
// returns the first alert received, converting detection.AlertEvent to DetectionEvent.
type MonitorAdapter struct {
	inner *detection.Monitor
}

// NewMonitorAdapter constructs a MonitorAdapter backed by the given Monitor.
func NewMonitorAdapter(m *detection.Monitor) *MonitorAdapter {
	return &MonitorAdapter{inner: m}
}

// WaitForDetection blocks until the first alert arrives on any configured
// platform, the context is cancelled, or the monitor channel closes.
func (a *MonitorAdapter) WaitForDetection(ctx context.Context) (*DetectionEvent, error) {
	start := time.Now()
	ch := a.inner.WatchAlerts(ctx, "", nil)

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("detection: monitor channel closed without an alert")
			}
			ts := ev.Timestamp
			if ts.IsZero() {
				ts = time.Now()
			}
			return &DetectionEvent{
				Platform:   ev.Platform,
				AlertID:    ev.AlertID,
				ReceivedAt: ts,
				Latency:    time.Since(start).Milliseconds(),
				Payload:    nil,
			}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
