package testgen

// ParsedIR matches the Rust ApiGuardIR JSON output.
type ParsedIR struct {
	Endpoints   []IREndpoint   `json:"endpoints"`
	AuthSchemes []IRAuthScheme `json:"auth_schemes"`
	Metadata    IRMetadata     `json:"metadata"`
}

// IREndpoint represents a single API endpoint from the Rust IR.
type IREndpoint struct {
	Path        string                 `json:"path"`
	Method      string                 `json:"method"`
	Parameters  []IRParameter          `json:"parameters"`
	RequestBody *IRRequestBody         `json:"request_body,omitempty"`
	Responses   map[string]IRResponse  `json:"responses"`
	Security    []string               `json:"security"`
	Tags        []string               `json:"tags"`
	XApiguard   map[string]interface{} `json:"x_apiguard"`
}

// IRParameter represents a parameter from the Rust IR.
type IRParameter struct {
	Name     string  `json:"name"`
	Location string  `json:"location"`
	Required bool    `json:"required"`
	Schema   *string `json:"schema,omitempty"`
}

// IRRequestBody represents a request body from the Rust IR.
type IRRequestBody struct {
	ContentTypes []string `json:"content_types"`
	Schema       *string  `json:"schema,omitempty"`
	Required     bool     `json:"required"`
}

// IRResponse represents a response from the Rust IR.
type IRResponse struct {
	Description string  `json:"description"`
	Schema      *string `json:"schema,omitempty"`
}

// IRAuthScheme represents an authentication scheme from the Rust IR.
type IRAuthScheme struct {
	Name       string  `json:"name"`
	SchemeType string  `json:"scheme_type"`
	Location   *string `json:"location,omitempty"`
	HeaderName *string `json:"header_name,omitempty"`
}

// IRMetadata holds API metadata from the Rust IR.
type IRMetadata struct {
	BaseURL    string `json:"base_url"`
	APIVersion string `json:"api_version"`
	SchemaHash string `json:"schema_hash"`
}
