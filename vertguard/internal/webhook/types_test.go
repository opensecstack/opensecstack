package webhook

import "testing"

func TestSubscriber_Matches(t *testing.T) {
	tests := []struct {
		name       string
		eventTypes []string
		eventType  string
		want       bool
	}{
		{"empty EventTypes matches everything", nil, "prompt_scan", true},
		{"exact match", []string{"prompt_scan", "media_scan"}, "prompt_scan", true},
		{"no match", []string{"prompt_scan"}, "phishing_scan", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Subscriber{EventTypes: tt.eventTypes}
			if got := s.Matches(tt.eventType); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestSubscriber_PrimarySecret(t *testing.T) {
	tests := []struct {
		name       string
		secrets    []string
		keyIDs     []string
		wantSecret string
		wantKID    string
	}{
		{"full slots", []string{"p", "n", "old"}, []string{"kp", "kn", "kold"}, "p", "kp"},
		{"no secrets configured", nil, nil, "", ""},
		{"secrets present but no key ids", []string{"p", "", ""}, nil, "p", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Subscriber{HMACSecrets: tt.secrets, KeyIDs: tt.keyIDs}
			secret, kid := s.PrimarySecret()
			if secret != tt.wantSecret {
				t.Errorf("secret = %q, want %q", secret, tt.wantSecret)
			}
			if kid != tt.wantKID {
				t.Errorf("kid = %q, want %q", kid, tt.wantKID)
			}
		})
	}
}

func TestSubscriber_ToPublic(t *testing.T) {
	s := &Subscriber{
		Tenant:      "acme",
		URL:         "https://example.com/hook",
		EventTypes:  []string{"prompt_scan"},
		HMACSecrets: []string{"1234567890abcdef", "", "shortkey"},
		KeyIDs:      []string{"k1", "", "k3"},
		Enabled:     true,
	}
	pub := s.ToPublic()

	if pub.Tenant != "acme" || pub.URL != s.URL {
		t.Fatalf("ToPublic() basic fields mismatch: %+v", pub)
	}
	if len(pub.SecretHints) != NumSlots {
		t.Fatalf("len(SecretHints) = %d, want %d", len(pub.SecretHints), NumSlots)
	}
	if pub.SecretHints[0] != "cdef" {
		t.Errorf("SecretHints[0] = %q, want last 4 chars \"cdef\"", pub.SecretHints[0])
	}
	if pub.SecretHints[1] != "" {
		t.Errorf("SecretHints[1] = %q, want empty (empty slot)", pub.SecretHints[1])
	}
	if pub.SecretHints[2] != "tkey" {
		t.Errorf("SecretHints[2] = %q, want last 4 chars \"tkey\"", pub.SecretHints[2])
	}
	// Never leak the raw secret anywhere in the public view.
	for _, hint := range pub.SecretHints {
		if hint == "1234567890abcdef" {
			t.Fatal("ToPublic() leaked a full raw secret in SecretHints")
		}
	}
}

func TestLastFour(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"ab", "ab"},
		{"abcd", "abcd"},
		{"abcdefgh", "efgh"},
	}
	for _, tt := range tests {
		if got := lastFour(tt.in); got != tt.want {
			t.Errorf("lastFour(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
