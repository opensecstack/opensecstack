package meetings

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ─── Zoom signature tests ─────────────────────────────────────────────

func TestZoomSignatureValid(t *testing.T) {
	secret := "test-zoom-secret"
	body := []byte(`{"event":"meeting.participant_joined","payload":{"object":{"id":"abc123"}}}`)
	ts := "1715000000"

	// Build the correct signature the same way Zoom does.
	message := "v0:" + ts + ":"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	mac.Write(body)
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	headers := http.Header{}
	headers.Set("X-Zm-Request-Timestamp", ts)
	headers.Set("X-Zm-Signature", sig)

	if !ValidateSignature(PlatformZoom, secret, body, headers) {
		t.Fatal("expected ValidateSignature to return true for a correct Zoom HMAC")
	}
}

func TestZoomSignatureInvalid(t *testing.T) {
	secret := "test-zoom-secret"
	body := []byte(`{"event":"meeting.participant_joined"}`)
	ts := "1715000000"

	// Build signature over the original body, then tamper with the body.
	message := "v0:" + ts + ":"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	mac.Write(body)
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	tamperedBody := []byte(`{"event":"meeting.participant_left"}`) // different body

	headers := http.Header{}
	headers.Set("X-Zm-Request-Timestamp", ts)
	headers.Set("X-Zm-Signature", sig)

	if ValidateSignature(PlatformZoom, secret, tamperedBody, headers) {
		t.Fatal("expected ValidateSignature to return false for a tampered body")
	}
}

func TestZoomSignatureMissingHeaders(t *testing.T) {
	headers := http.Header{} // no timestamp or signature headers
	body := []byte(`{}`)

	if ValidateSignature(PlatformZoom, "secret", body, headers) {
		t.Fatal("expected false when Zoom signature headers are absent")
	}
}

// ─── WebEx signature tests ────────────────────────────────────────────

func TestWebExSignatureValid(t *testing.T) {
	secret := "test-webex-secret"
	body := []byte(`{"resource":"meetings","event":"started","data":{"meetingId":"m1","personId":"p1"}}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	headers := http.Header{}
	headers.Set("X-Spark-Signature", sig)

	if !ValidateSignature(PlatformWebEx, secret, body, headers) {
		t.Fatal("expected ValidateSignature to return true for a correct WebEx HMAC")
	}
}

func TestWebExSignatureInvalid(t *testing.T) {
	secret := "test-webex-secret"
	body := []byte(`{"resource":"meetings","event":"started"}`)

	headers := http.Header{}
	headers.Set("X-Spark-Signature", "deadbeefdeadbeef") // wrong value

	if ValidateSignature(PlatformWebEx, secret, body, headers) {
		t.Fatal("expected ValidateSignature to return false for a wrong WebEx signature")
	}
}

// ─── ParseEvent tests ─────────────────────────────────────────────────

func TestParseEventParticipantJoined(t *testing.T) {
	body := []byte(`{
		"event": "meeting.participant_joined",
		"event_ts": 1715000000000,
		"payload": {
			"object": {
				"id": "meeting-abc",
				"participant": {
					"user_id": "user-xyz"
				}
			}
		}
	}`)

	evt, err := ParseEvent(PlatformZoom, body)
	if err != nil {
		t.Fatalf("ParseEvent returned unexpected error: %v", err)
	}
	if evt.EventType != "participant.joined" {
		t.Errorf("EventType = %q, want %q", evt.EventType, "participant.joined")
	}
	if evt.MeetingID != "meeting-abc" {
		t.Errorf("MeetingID = %q, want %q", evt.MeetingID, "meeting-abc")
	}
	if evt.ParticipantID != "user-xyz" {
		t.Errorf("ParticipantID = %q, want %q", evt.ParticipantID, "user-xyz")
	}
	if evt.Timestamp.IsZero() {
		t.Error("Timestamp must not be zero")
	}
}

func TestParseEventInvalidJSON(t *testing.T) {
	_, err := ParseEvent(PlatformZoom, []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
}

func TestParseEventUnknownPlatform(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"event": "test"})
	_, err := ParseEvent("unknown", body)
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
}

// ─── AuthorizeURL tests ───────────────────────────────────────────────

func TestAuthorizeURL_Zoom(t *testing.T) {
	u, err := AuthorizeURL(PlatformZoom, "my-client-id", "nonce123", "https://example.com/callback")
	if err != nil {
		t.Fatalf("AuthorizeURL returned error: %v", err)
	}
	if !strings.HasPrefix(u, "https://zoom.us/oauth/authorize") {
		t.Errorf("URL does not start with Zoom authorize base: %s", u)
	}
	if !strings.Contains(u, "client_id=my-client-id") {
		t.Errorf("URL missing client_id: %s", u)
	}
	if !strings.Contains(u, "state=nonce123") {
		t.Errorf("URL missing state: %s", u)
	}
	if !strings.Contains(u, "response_type=code") {
		t.Errorf("URL missing response_type=code: %s", u)
	}
}

func TestAuthorizeURL_Teams(t *testing.T) {
	u, err := AuthorizeURL(PlatformTeams, "azure-client-id", "nonce456", "https://example.com/callback")
	if err != nil {
		t.Fatalf("AuthorizeURL returned error: %v", err)
	}
	if !strings.HasPrefix(u, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize") {
		t.Errorf("URL does not start with Teams authorize base: %s", u)
	}
	if !strings.Contains(u, "client_id=azure-client-id") {
		t.Errorf("URL missing client_id: %s", u)
	}
	// Teams must include a scope parameter.
	if !strings.Contains(u, "scope=") {
		t.Errorf("Teams URL missing scope: %s", u)
	}
}

func TestAuthorizeURL_WebEx(t *testing.T) {
	u, err := AuthorizeURL(PlatformWebEx, "webex-client-id", "nonce789", "https://example.com/callback")
	if err != nil {
		t.Fatalf("AuthorizeURL returned error: %v", err)
	}
	if !strings.HasPrefix(u, "https://webexapis.com/v1/authorize") {
		t.Errorf("URL does not start with WebEx authorize base: %s", u)
	}
	if !strings.Contains(u, "client_id=webex-client-id") {
		t.Errorf("URL missing client_id: %s", u)
	}
}

func TestAuthorizeURL_UnknownPlatform(t *testing.T) {
	_, err := AuthorizeURL("unknown", "id", "state", "https://example.com/cb")
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
}
