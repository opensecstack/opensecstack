// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachablePool returns a *pgxpool.Pool pointed at a loopback address that
// actively refuses connections. pgxpool.New never dials on construction
// (connections are established lazily on first use), so building the pool
// always succeeds; the first real query against it fails fast (typically
// within tens of milliseconds) with a connection error. This lets tests
// exercise a handler's "database is unreachable" 500 branch deterministically
// without requiring a live Postgres instance, matching the existing
// SECURELAB_DB_URL-gated convention used for tests that need a *working* DB
// (see internal/scenarios/executor_test.go) while covering the error path
// that convention cannot reach in CI.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/db?connect_timeout=1")
	if err != nil {
		t.Fatalf("build unreachable pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newGetRequest builds a GET request against target, optionally injecting
// chi URL parameters (e.g. {"id": "abc"}) into the request context so that
// chi.URLParam(r, "id") resolves inside the handler under test.
func newGetRequest(target string, params map[string]string) *http.Request {
	return newRequestWithParams(http.MethodGet, target, "", params)
}

// newDeleteRequest builds a DELETE request against target with optional chi
// URL parameters, mirroring newGetRequest.
func newDeleteRequest(target string, params map[string]string) *http.Request {
	return newRequestWithParams(http.MethodDelete, target, "", params)
}

// postWithParams sends a POST request with the given JSON body and chi URL
// parameters to h and returns the recorder.
func postWithParams(h http.HandlerFunc, body string, params map[string]string) *httptest.ResponseRecorder {
	req := newRequestWithParams(http.MethodPost, "/", body, params)
	req.Header.Set("Content-Type", "application/json")
	return do(h, req)
}

func newRequestWithParams(method, target, body string, params map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if len(params) > 0 {
		rctx := chi.NewRouteContext()
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}
	return req
}

// do dispatches req to h and returns the recorder.
func do(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}
