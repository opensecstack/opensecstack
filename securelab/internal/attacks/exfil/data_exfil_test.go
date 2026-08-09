// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package exfil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDataExfilAttack_Run_MissingJWT(t *testing.T) {
	d := NewDataExfilAttack()
	_, err := d.Run(context.Background(), "http://127.0.0.1:1", map[string]any{})
	if err == nil {
		t.Fatal("expected error when jwt param is missing")
	}
}

func TestDataExfilAttack_Run_BlocksProductionTarget(t *testing.T) {
	d := NewDataExfilAttack()
	_, err := d.Run(context.Background(), "https://api-prod.example.com", map[string]any{"jwt": "x"})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestDataExfilAttack_Run_StopsOnRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":1},{"id":2}]`))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	d := NewDataExfilAttack()
	result, err := d.Run(context.Background(), server.URL, map[string]any{
		"jwt":       "x",
		"page_size": 2,
		"max_pages": 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StopReason != "rate_limited" {
		t.Errorf("StopReason = %q, want rate_limited", result.StopReason)
	}
	if result.RecordsExtracted != 2 {
		t.Errorf("RecordsExtracted = %d, want 2", result.RecordsExtracted)
	}
	if !result.Success {
		t.Error("expected Success=true since records were extracted before rate limiting")
	}
}

func TestDataExfilAttack_Run_StopsOnAnomalyDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	d := NewDataExfilAttack()
	result, err := d.Run(context.Background(), server.URL, map[string]any{"jwt": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StopReason != "anomaly_detected" {
		t.Errorf("StopReason = %q, want anomaly_detected", result.StopReason)
	}
	if result.Success {
		t.Error("expected Success=false since 0 records were extracted before access was revoked")
	}
}

func TestDataExfilAttack_Run_ExhaustedOnEmptyPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if page == "1" {
			w.Write([]byte(`[{"id":1}]`))
		} else {
			w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()

	d := NewDataExfilAttack()
	result, err := d.Run(context.Background(), server.URL, map[string]any{"jwt": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StopReason != "exhausted" {
		t.Errorf("StopReason = %q, want exhausted", result.StopReason)
	}
	if result.RecordsExtracted != 1 {
		t.Errorf("RecordsExtracted = %d, want 1", result.RecordsExtracted)
	}
}

func TestCountRecords_JSONArray(t *testing.T) {
	if got := countRecords([]byte(`[1,2,3]`)); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

func TestCountRecords_ObjectWithDataField(t *testing.T) {
	if got := countRecords([]byte(`{"data":[1,2]}`)); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestCountRecords_ObjectWithItemsField(t *testing.T) {
	if got := countRecords([]byte(`{"items":[1,2,3,4]}`)); got != 4 {
		t.Errorf("got %d, want 4", got)
	}
}

func TestCountRecords_NoMatchingField(t *testing.T) {
	if got := countRecords([]byte(`{"unrelated":"value"}`)); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestCountRecords_InvalidJSON(t *testing.T) {
	if got := countRecords([]byte(`not json`)); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestCheckTarget_ExfilPackage(t *testing.T) {
	if err := checkTarget("https://api-prod.example.com"); err == nil {
		t.Error("expected production target to be blocked")
	}
	if err := checkTarget("http://192.168.1.1"); err != nil {
		t.Errorf("expected safe target to pass, got: %v", err)
	}
}

func TestIntParam_ExfilPackage(t *testing.T) {
	if got := intParam(map[string]any{}, "k", 10, 100); got != 10 {
		t.Errorf("default: got %d, want 10", got)
	}
	if got := intParam(map[string]any{"k": 500}, "k", 10, 100); got != 100 {
		t.Errorf("capped: got %d, want 100", got)
	}
}
