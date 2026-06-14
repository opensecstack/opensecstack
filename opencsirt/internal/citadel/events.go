// Package citadel emits OpenCSIRT events to the CITADEL governance
// platform. The wire envelope mirrors CyberPath/IRFlow:
//
//   POST {citadel_api_url}/api/v1/events
//   Headers:
//     X-Event-Type:   opencsirt.<event_type>
//     X-Key-ID:       <rotation key id>
//     X-Timestamp:    RFC3339 UTC
//     X-Signature:    hex(HMAC-SHA256(secret, ts || "." || body))
//   Body: JSON event payload
//
// Replay window is enforced server-side by CITADEL (±5 min).
package citadel

const (
	EventIncidentOpened    = "opencsirt.incident_opened"
	EventIncidentClosed    = "opencsirt.incident_closed"
	EventAdvisoryPublished = "opencsirt.advisory_published"
	EventEscalationSent    = "opencsirt.escalation_sent"
)
