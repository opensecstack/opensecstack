// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import "testing"

func TestCheckTarget_BlocksProductionPatterns(t *testing.T) {
	blocked := []string{
		"https://api.prod/v1",
		"https://api-prod.example.com",
		"https://api_prod.example.com",
		"https://production.example.com",
		"https://api.live.example.com",
		"https://api-live.example.com",
	}
	for _, url := range blocked {
		if err := checkTarget(url); err == nil {
			t.Errorf("checkTarget(%q) = nil, want error (production blocklist)", url)
		}
	}
}

func TestCheckTarget_AllowsSafeURL(t *testing.T) {
	safe := []string{
		"http://192.168.1.10:8080",
		"http://localhost:3000",
		"http://lab-env.internal",
	}
	for _, url := range safe {
		if err := checkTarget(url); err != nil {
			t.Errorf("checkTarget(%q) = %v, want nil", url, err)
		}
	}
}

func TestCheckTarget_CaseInsensitive(t *testing.T) {
	if err := checkTarget("https://API.PRODUCTION.example.com"); err == nil {
		t.Error("expected checkTarget to catch uppercase PRODUCTION")
	}
}
