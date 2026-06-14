package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// MaxReasonLen caps free-form Reason fields on admin endpoints. Long
// enough for a useful incident note ("ticket VG-1234: brute force from
// 1.2.3.4") but short enough to keep audit metadata bounded.
const MaxReasonLen = 256

// ErrBadReason signals that a Reason field violated length / charset
// rules. Handlers translate this to HTTP 400 {code:"bad_reason"}.
var ErrBadReason = errors.New("bad_reason")

// validateReason enforces the universal Reason policy: ≤256 chars and
// no control runes other than TAB (0x09). Empty is allowed (Reason is
// optional everywhere it appears).
func validateReason(s string) error {
	if len(s) > MaxReasonLen {
		return ErrBadReason
	}
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if r < 0x20 {
			return ErrBadReason
		}
	}
	return nil
}

// decodeJSON reads the request body with a reasonable size limit and
// decodes it into v. 1 MiB default cap; callers that need more should
// wrap the handler with their own MaxBytesReader.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if err == io.EOF {
			return err
		}
		return err
	}
	return nil
}
