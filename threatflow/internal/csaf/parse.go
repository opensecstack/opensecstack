package csaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ErrInvalidCSAF is returned when a payload is not a parseable/well-formed
// CSAF 2.0 document. Wrapped with a specific reason — callers return 400.
var ErrInvalidCSAF = errors.New("invalid CSAF document")

// trackingIDPattern mirrors opencsirt/python/advisory/csaf.py's
// TrackingId validator: `[A-Za-z0-9_.+-]{1,128}`.
var trackingIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.+\-]{1,128}$`)

// ParseDocument decodes and validates a CSAF 2.0 payload. Validation covers
// the fields this package depends on for dedup/versioning and mapping —
// it is not a full re-implementation of the upstream CSAF JSON Schema
// (opencsirt's Python generator already validates against that schema
// before the document is ever put on the wire; this is a defensive check
// at the trust boundary, not a duplicate of the authoring-side validator).
func ParseDocument(payload []byte) (*Document, error) {
	if !json.Valid(payload) {
		return nil, fmt.Errorf("%w: not valid JSON", ErrInvalidCSAF)
	}
	var doc Document
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSAF, err)
	}
	if err := validateDocument(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSAF, err)
	}
	return &doc, nil
}

func validateDocument(doc *Document) error {
	if doc.Document.Title == "" {
		return errors.New("document.title is required")
	}
	if doc.Document.Category == "" {
		return errors.New("document.category is required")
	}
	if doc.Document.Publisher.Name == "" {
		return errors.New("document.publisher.name is required")
	}
	if doc.Document.Publisher.Category == "" {
		return errors.New("document.publisher.category is required")
	}
	tlp := doc.Document.Distribution.TLP.Label
	switch tlp {
	case "CLEAR", "GREEN", "AMBER", "RED":
	default:
		return fmt.Errorf("document.distribution.tlp.label must be one of CLEAR|GREEN|AMBER|RED, got %q", tlp)
	}
	if doc.Document.Tracking.ID == "" {
		return errors.New("document.tracking.id is required")
	}
	if !trackingIDPattern.MatchString(doc.Document.Tracking.ID) {
		return fmt.Errorf("document.tracking.id %q does not match [A-Za-z0-9_.+-]{1,128}", doc.Document.Tracking.ID)
	}
	if doc.Document.Tracking.InitialReleaseDate == "" {
		return errors.New("document.tracking.initial_release_date is required")
	}
	if _, err := time.Parse(time.RFC3339, doc.Document.Tracking.InitialReleaseDate); err != nil {
		return fmt.Errorf("document.tracking.initial_release_date: %w", err)
	}
	if doc.Document.Tracking.CurrentReleaseDate == "" {
		return errors.New("document.tracking.current_release_date is required")
	}
	if _, err := time.Parse(time.RFC3339, doc.Document.Tracking.CurrentReleaseDate); err != nil {
		return fmt.Errorf("document.tracking.current_release_date: %w", err)
	}
	for i, v := range doc.Vulnerabilities {
		if v.Title == "" {
			return fmt.Errorf("vulnerabilities[%d].title is required", i)
		}
	}
	return nil
}

// Version returns the document's tracking.version, defaulting to "1" to
// match the default in opencsirt's Pydantic Tracking model when the field
// is (unexpectedly) empty on the wire.
func (d *Document) Version() string {
	if d.Document.Tracking.Version == "" {
		return "1"
	}
	return d.Document.Tracking.Version
}

// releaseTimes parses the two tracking dates already validated by
// validateDocument. Errors here would indicate a validation bug, not bad
// input, so callers may safely ignore the error after ParseDocument succeeds.
func (d *Document) releaseTimes() (initial, current time.Time, err error) {
	initial, err = time.Parse(time.RFC3339, d.Document.Tracking.InitialReleaseDate)
	if err != nil {
		return
	}
	current, err = time.Parse(time.RFC3339, d.Document.Tracking.CurrentReleaseDate)
	return
}
