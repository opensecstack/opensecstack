package scanner

import (
	"context"
	"testing"
)

// TestValidateTargetURL_LocalhostBlocked verifies that localhost is blocked.
func TestValidateTargetURL_LocalhostBlocked(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "http://localhost/api", false)
	if err == nil {
		t.Error("expected error for localhost target, got nil")
	}
}

// TestValidateTargetURL_AWSMetadataBlocked verifies that the AWS metadata IP is blocked.
func TestValidateTargetURL_AWSMetadataBlocked(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "http://169.254.169.254/latest", false)
	if err == nil {
		t.Error("expected error for AWS metadata address, got nil")
	}
}

// TestValidateTargetURL_PrivateIPBlocked verifies that RFC-1918 private addresses are blocked.
func TestValidateTargetURL_PrivateIPBlocked(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "http://192.168.1.1/api", false)
	if err == nil {
		t.Error("expected error for private IP 192.168.1.1, got nil")
	}
}

// TestValidateTargetURL_EmptyTarget verifies that an empty target returns an error.
func TestValidateTargetURL_EmptyTarget(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "", false)
	if err == nil {
		t.Error("expected error for empty target URL, got nil")
	}
}

// TestValidateTargetURL_InvalidURL verifies that a non-URL string returns an error.
func TestValidateTargetURL_InvalidURL(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "not a url", false)
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}

// TestValidateTargetURL_AllowInternalBypassesBlock verifies that allowInternal=true permits
// internal addresses (localhost) and returns nil IPs.
func TestValidateTargetURL_AllowInternalBypassesBlock(t *testing.T) {
	ips, err := validateTargetURL(context.Background(), "http://127.0.0.1/api", true)
	if err != nil {
		t.Errorf("expected no error with allowInternal=true, got: %v", err)
	}
	// allowInternal returns nil IPs (no DNS pinning needed for internal targets).
	if ips != nil {
		t.Errorf("expected nil IPs for allowInternal=true, got %v", ips)
	}
}

// TestValidateTargetURL_ExternalURL tests validation of an external URL.
// This test requires network access for DNS resolution; it is skipped in
// isolated environments.
func TestValidateTargetURL_ExternalURL(t *testing.T) {
	ips, err := validateTargetURL(context.Background(), "https://api.example.com/v1", false)
	if err != nil {
		// DNS may not be available in the test environment — skip rather than fail.
		t.Skipf("skipping external URL test (DNS unavailable): %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected non-empty IPs list for external URL, got empty")
	}
}

// TestValidateTargetURL_LoopbackIPBlocked verifies that 127.x.x.x is blocked.
func TestValidateTargetURL_LoopbackIPBlocked(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "http://127.0.0.1/api", false)
	if err == nil {
		t.Error("expected error for loopback IP 127.0.0.1, got nil")
	}
}

// TestValidateTargetURL_10NetBlocked verifies that 10.x.x.x is blocked.
func TestValidateTargetURL_10NetBlocked(t *testing.T) {
	_, err := validateTargetURL(context.Background(), "http://10.0.0.1/api", false)
	if err == nil {
		t.Error("expected error for private IP 10.0.0.1, got nil")
	}
}
