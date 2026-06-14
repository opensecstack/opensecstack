// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection

import "time"

// MeasureLatency calculates the detection latency per technique: the elapsed
// time between when an attack occurred (attackTime) and the first alert for
// that technique.
//
// Returns a map of technique → latency. Techniques for which no alert was
// received are not present in the map.
func MeasureLatency(attackTime time.Time, alerts []AlertEvent) map[string]time.Duration {
	// First, collect all alert times per technique.
	// We want the earliest alert for each technique.
	earliest := make(map[string]time.Time, len(alerts))

	for _, a := range alerts {
		key := normalise(a.Technique)
		if key == "" {
			continue
		}
		if t, exists := earliest[key]; !exists || a.Timestamp.Before(t) {
			earliest[key] = a.Timestamp
		}
	}

	latencies := make(map[string]time.Duration, len(earliest))
	for tech, alertTime := range earliest {
		lat := alertTime.Sub(attackTime)
		if lat < 0 {
			lat = 0
		}
		latencies[tech] = lat
	}
	return latencies
}
