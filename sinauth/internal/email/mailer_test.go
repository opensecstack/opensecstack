package email

import "testing"

// TestSend_DevModeSkipsWithoutError proves that when no SMTP host is
// configured (dev mode), sending silently succeeds rather than attempting
// a network connection.
func TestSendVerification_DevModeNoHost(t *testing.T) {
	m := New(Config{SiteURL: "https://sin.to"})
	if err := m.SendVerification("user@example.com", "alice", "tok-123"); err != nil {
		t.Fatalf("SendVerification with no SMTP host configured: unexpected error %v, want nil (dev-mode no-op)", err)
	}
}

func TestSendPasswordReset_DevModeNoHost(t *testing.T) {
	m := New(Config{SiteURL: "https://sin.to"})
	if err := m.SendPasswordReset("user@example.com", "tok-456"); err != nil {
		t.Fatalf("SendPasswordReset with no SMTP host configured: unexpected error %v, want nil (dev-mode no-op)", err)
	}
}

// TestSend_WithHostAttemptsDeliveryAndErrorsOnFailure proves that once a
// host IS configured, the mailer no longer treats sending as a no-op — it
// actually attempts SMTP delivery, which must fail against an address with
// nothing listening (rather than silently succeeding, which would mask
// misconfiguration in prod).
func TestSendVerification_WithHostAttemptsDeliveryAndFails(t *testing.T) {
	m := New(Config{
		Host:    "127.0.0.1",
		Port:    1, // nothing listens on port 1
		From:    "noreply@sin.to",
		SiteURL: "https://sin.to",
	})
	err := m.SendVerification("user@example.com", "alice", "tok-123")
	if err == nil {
		t.Fatal("SendVerification: expected error when SMTP host is configured but unreachable, got nil")
	}
}
