package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openapiSpec []byte

// OpenAPI handles GET /api/v1/openapi.json.
func OpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(openapiSpec) //nolint:errcheck
}
