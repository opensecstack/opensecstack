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
	_, _ = w.Write(openapiSpec) //nolint:errcheck // #nosec G104 -- best-effort write of an embedded constant, nothing else to report on failure
}
