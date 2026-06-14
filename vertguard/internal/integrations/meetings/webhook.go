package meetings

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MeetingEvent is the normalised event envelope produced by ParseEvent.
// Each platform emits its own JSON schema; ParseEvent maps it into this
// common shape so the handler layer is platform-agnostic.
type MeetingEvent struct {
	// EventType is the normalised event name.
	// Known values: "participant.joined", "participant.left",
	// "recording.started", "audio.chunk".
	EventType string

	// MeetingID is the platform-native meeting or room identifier.
	MeetingID string

	// ParticipantID is the platform-native participant identifier.
	// Empty for events that are not participant-scoped (e.g. recording.started).
	ParticipantID string

	// Timestamp is the event occurrence time reported by the platform.
	Timestamp time.Time

	// Payload carries the full decoded event body for fields not mapped
	// by the common envelope. Handlers that need platform-specific data
	// should read from here.
	Payload map[string]any
}

// ValidateSignature reports whether the inbound webhook payload was signed
// with secret by the named platform. Returns false on any validation
// error (wrong signature, missing headers, unsupported platform).
//
// Zoom — HMAC-SHA256(secret, "v0:<x-zm-request-timestamp>:<body>"),
// compared against the x-zm-signature header (format "v0=<hex>").
// See https://developers.zoom.us/docs/api/rest/webhook-reference/#verify-webhook-events
//
// Teams — Activity payloads from the Azure Bot Framework carry a Bearer
// JWT in the Authorization header. Full validation requires fetching the
// OpenID Connect metadata from login.microsoftonline.com, which requires
// network access and an Azure app registration.
// Phase 4.3: implement Azure Bot Framework JWT validation once Azure app
// credentials are provisioned. For now this stub returns true so the
// webhook plumbing can be tested end-to-end.
//
// WebEx — HMAC-SHA256(secret, body), compared against the
// X-Spark-Signature header (raw hex, no prefix).
// See https://developer.webex.com/docs/webhooks#handling-requests-from-webex
func ValidateSignature(platform MeetingPlatform, secret string, body []byte, headers http.Header) bool {
	switch platform {
	case PlatformZoom:
		return validateZoomSignature(secret, body, headers)
	case PlatformTeams:
		// Phase 4.3: implement Azure Bot Framework JWT validation once
		// Azure app credentials are provisioned; validate the Bearer token
		// in the Authorization header against Microsoft's OpenID metadata.
		// TODO: replace this stub with real JWT validation.
		return true
	case PlatformWebEx:
		return validateWebExSignature(secret, body, headers)
	default:
		return false
	}
}

// validateZoomSignature validates the Zoom webhook HMAC-SHA256 signature.
// Message format: "v0:<x-zm-request-timestamp>:<body>"
// Signature header: "x-zm-signature" with value "v0=<hex>"
func validateZoomSignature(secret string, body []byte, headers http.Header) bool {
	ts := headers.Get("X-Zm-Request-Timestamp")
	sig := headers.Get("X-Zm-Signature")
	if ts == "" || sig == "" {
		return false
	}

	message := "v0:" + ts + ":"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	mac.Write(body)
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks.
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(sig)))
}

// validateWebExSignature validates the WebEx webhook HMAC-SHA256 signature.
// Message: raw body bytes.
// Signature header: "X-Spark-Signature" with value as raw hex (no prefix).
func validateWebExSignature(secret string, body []byte, headers http.Header) bool {
	sig := headers.Get("X-Spark-Signature")
	if sig == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(sig)))
}

// ParseEvent decodes a raw platform webhook body into a MeetingEvent.
// Only the fields present in the minimal common schema are mapped;
// callers may read MeetingEvent.Payload for any platform-specific fields.
func ParseEvent(platform MeetingPlatform, body []byte) (*MeetingEvent, error) {
	// Decode the raw body into a generic map first; we extract fields by
	// platform-specific key names and normalise them into MeetingEvent.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("meetings: parse event: %w", err)
	}

	switch platform {
	case PlatformZoom:
		return parseZoomEvent(raw)
	case PlatformTeams:
		return parseTeamsEvent(raw)
	case PlatformWebEx:
		return parseWebExEvent(raw)
	default:
		return nil, fmt.Errorf("meetings: unknown platform %q", platform)
	}
}

// parseZoomEvent maps a Zoom webhook payload to MeetingEvent.
// Zoom sends: {"event":"participant_joined","payload":{"object":{"id":"...","participant":{"user_id":"..."}}}}
func parseZoomEvent(raw map[string]any) (*MeetingEvent, error) {
	evt := &MeetingEvent{Payload: raw}

	if v, ok := raw["event"].(string); ok {
		evt.EventType = normaliseZoomEventType(v)
	}

	payload, _ := raw["payload"].(map[string]any)
	if payload != nil {
		obj, _ := payload["object"].(map[string]any)
		if obj != nil {
			evt.MeetingID, _ = obj["id"].(string)
			participant, _ := obj["participant"].(map[string]any)
			if participant != nil {
				evt.ParticipantID, _ = participant["user_id"].(string)
			}
		}
	}

	if tsStr, ok := raw["event_ts"].(float64); ok {
		// Zoom sends milliseconds since epoch.
		evt.Timestamp = time.UnixMilli(int64(tsStr)).UTC()
	} else {
		evt.Timestamp = time.Now().UTC()
	}

	return evt, nil
}

// normaliseZoomEventType maps Zoom's native event names to the VertGuard
// canonical event type strings used by MeetingEvent.EventType.
func normaliseZoomEventType(zoomEvent string) string {
	switch zoomEvent {
	case "meeting.participant_joined":
		return "participant.joined"
	case "meeting.participant_left":
		return "participant.left"
	case "recording.started":
		return "recording.started"
	case "meeting.audio_chunk":
		return "audio.chunk"
	default:
		return zoomEvent
	}
}

// parseTeamsEvent maps a Teams / Azure Bot Framework activity to MeetingEvent.
// Teams activities carry: {"type":"event","name":"...","conversation":{"id":"..."},"from":{"id":"..."}}
//
// Phase 4.3: extend mapping once the full Teams event schema is documented
// for the provisioned app registration — currently only basic fields are mapped.
func parseTeamsEvent(raw map[string]any) (*MeetingEvent, error) {
	evt := &MeetingEvent{Payload: raw}

	if name, ok := raw["name"].(string); ok {
		evt.EventType = name
	} else if t, ok := raw["type"].(string); ok {
		evt.EventType = t
	}

	if conv, ok := raw["conversation"].(map[string]any); ok {
		evt.MeetingID, _ = conv["id"].(string)
	}
	if from, ok := raw["from"].(map[string]any); ok {
		evt.ParticipantID, _ = from["id"].(string)
	}

	evt.Timestamp = time.Now().UTC()
	return evt, nil
}

// parseWebExEvent maps a WebEx webhook event body to MeetingEvent.
// WebEx sends: {"id":"...","name":"...","resource":"meetings","event":"started","data":{"meetingId":"...","personId":"..."}}
func parseWebExEvent(raw map[string]any) (*MeetingEvent, error) {
	evt := &MeetingEvent{Payload: raw}

	// Combine resource + event into the canonical dot-separated name.
	resource, _ := raw["resource"].(string)
	event, _ := raw["event"].(string)
	if resource != "" && event != "" {
		evt.EventType = resource + "." + event
	} else if event != "" {
		evt.EventType = event
	}

	if data, ok := raw["data"].(map[string]any); ok {
		evt.MeetingID, _ = data["meetingId"].(string)
		evt.ParticipantID, _ = data["personId"].(string)
	}

	if createdStr, ok := raw["created"].(string); ok {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			evt.Timestamp = t.UTC()
		}
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	return evt, nil
}
