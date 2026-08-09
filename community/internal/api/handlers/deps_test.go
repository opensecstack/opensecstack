package handlers

// White-box test for the unexported queryInt helper. Kept in package
// handlers (rather than handlers_test) specifically because queryInt has no
// exported surface of its own — every handler that uses it only reveals the
// parsed value indirectly through a live DB query, which the rest of this
// test suite avoids. Testing it directly here gives real coverage of its
// three branches (default, valid, invalid/negative) without inventing a way
// to observe it through an HTTP handler.

import (
	"net/http/httptest"
	"testing"
)

func TestQueryInt_MissingParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 when param missing, got %d", got)
	}
}

func TestQueryInt_ValidParam_ReturnsParsedValue(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=17", nil)
	if got := queryInt(r, "limit", 42); got != 17 {
		t.Errorf("expected parsed value 17, got %d", got)
	}
}

func TestQueryInt_NonNumericParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=abc", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 for non-numeric param, got %d", got)
	}
}

func TestQueryInt_NegativeParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=-5", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 for negative param, got %d", got)
	}
}

func TestQueryInt_ZeroParam_ReturnsZero(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?offset=0", nil)
	if got := queryInt(r, "offset", 10); got != 0 {
		t.Errorf("expected 0 to be accepted, got %d", got)
	}
}
