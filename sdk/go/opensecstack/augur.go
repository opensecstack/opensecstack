package opensecstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// augurDo performs an HMAC-signed HTTP request to a CITADEL AUGUR endpoint.
//
// body is JSON-marshalled and placed in the request body when non-nil.
// dst is JSON-decoded from the response body when non-nil and the response is
// not 204 No Content. Pass nil dst to discard the response body (e.g. DELETE).
func (c *CITADELClient) augurDo(ctx context.Context, method, path string, body interface{}, dst interface{}) error {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("augurDo: marshal: %w", err)
		}
	}

	var reqBody *bytes.Reader
	if len(bodyBytes) > 0 {
		reqBody = bytes.NewReader(bodyBytes)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.citadelURL(path), reqBody)
	if err != nil {
		return fmt.Errorf("augurDo: build request: %w", err)
	}
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Citadel-Signature", c.signBody(bodyBytes))
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("augurDo %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("augurDo: reading body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("augurDo: CITADEL returned HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if dst == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("augurDo: decode response: %w", err)
	}
	return nil
}

// CreateAdvisory creates a new security advisory.
//
// If BaseURL is empty (disabled mode), returns nil, nil.
func (c *CITADELClient) CreateAdvisory(ctx context.Context, req CreateAdvisoryRequest) (*Advisory, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	var adv Advisory
	if err := c.augurDo(ctx, http.MethodPost, "augur/advisories", req, &adv); err != nil {
		return nil, err
	}
	return &adv, nil
}

// ListAdvisories returns a paginated list of advisories with optional filters.
//
// If BaseURL is empty (disabled mode), returns nil, nil.
func (c *CITADELClient) ListAdvisories(ctx context.Context, opts *ListAdvisoriesOptions) ([]Advisory, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	path := "augur/advisories"
	if opts != nil {
		params := url.Values{}
		if opts.Page > 0 {
			params.Set("page", fmt.Sprintf("%d", opts.Page))
		}
		if opts.PerPage > 0 {
			params.Set("per_page", fmt.Sprintf("%d", opts.PerPage))
		}
		if opts.Status != "" {
			params.Set("status", string(opts.Status))
		}
		if opts.Severity != "" {
			params.Set("severity", string(opts.Severity))
		}
		if encoded := params.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	var advisories []Advisory
	if err := c.augurDo(ctx, http.MethodGet, path, nil, &advisories); err != nil {
		return nil, err
	}
	return advisories, nil
}

// GetAdvisory retrieves a single advisory by ID.
//
// If BaseURL is empty (disabled mode), returns nil, nil.
func (c *CITADELClient) GetAdvisory(ctx context.Context, id string) (*Advisory, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	if id == "" {
		return nil, fmt.Errorf("advisory ID must not be empty")
	}
	var adv Advisory
	if err := c.augurDo(ctx, http.MethodGet, "augur/advisories/"+id, nil, &adv); err != nil {
		return nil, err
	}
	return &adv, nil
}

// PatchAdvisory partially updates an advisory.
//
// If BaseURL is empty (disabled mode), returns nil, nil.
func (c *CITADELClient) PatchAdvisory(ctx context.Context, id string, req PatchAdvisoryRequest) (*Advisory, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	if id == "" {
		return nil, fmt.Errorf("advisory ID must not be empty")
	}
	var adv Advisory
	if err := c.augurDo(ctx, http.MethodPatch, "augur/advisories/"+id, req, &adv); err != nil {
		return nil, err
	}
	return &adv, nil
}

// DeleteAdvisory deletes an advisory by ID.
//
// If BaseURL is empty (disabled mode), returns nil.
func (c *CITADELClient) DeleteAdvisory(ctx context.Context, id string) error {
	if c.baseURL == "" {
		return nil
	}
	if id == "" {
		return fmt.Errorf("advisory ID must not be empty")
	}
	return c.augurDo(ctx, http.MethodDelete, "augur/advisories/"+id, nil, nil)
}

// GetActiveAdvisories is a convenience method that lists only published advisories.
//
// If BaseURL is empty (disabled mode), returns nil, nil.
func (c *CITADELClient) GetActiveAdvisories(ctx context.Context) ([]Advisory, error) {
	return c.ListAdvisories(ctx, &ListAdvisoriesOptions{Status: AdvisoryStatusPublished})
}
