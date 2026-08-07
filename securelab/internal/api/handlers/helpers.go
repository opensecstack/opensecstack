// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"encoding/json"
	"net/http"
)

// writeJSON serialises v as JSON and writes it to w with the given HTTP status
// code. The Content-Type header is set to application/json.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
