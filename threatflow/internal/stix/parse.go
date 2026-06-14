package stix

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidBundle is returned when a payload is not a parseable STIX bundle.
var ErrInvalidBundle = errors.New("invalid stix bundle")

var stixIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,249}--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseBundle decodes and validates a STIX 2.1 bundle. Objects are left as raw
// JSON on the returned Bundle; use DecodeObjects to materialise them.
func ParseBundle(payload []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBundle, err)
	}
	if b.Type != "bundle" {
		return nil, fmt.Errorf("%w: type=%q, want bundle", ErrInvalidBundle, b.Type)
	}
	if !stixIDPattern.MatchString(b.ID) {
		return nil, fmt.Errorf("%w: invalid bundle id %q", ErrInvalidBundle, b.ID)
	}
	if len(b.Objects) == 0 {
		return nil, fmt.Errorf("%w: objects array missing", ErrInvalidBundle)
	}
	return &b, nil
}

// DecodeObjects parses the bundle's objects array into Object envelopes. Each
// object retains its raw JSON for downstream type-specific decoding.
func DecodeObjects(b *Bundle) ([]Object, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(b.Objects, &raws); err != nil {
		return nil, fmt.Errorf("decode objects: %w", err)
	}
	out := make([]Object, 0, len(raws))
	for i, raw := range raws {
		var obj Object
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("object[%d]: %w", i, err)
		}
		if err := validateObject(&obj); err != nil {
			return nil, fmt.Errorf("object[%d]: %w", i, err)
		}
		obj.Raw = raw
		out = append(out, obj)
	}
	return out, nil
}

// AsIndicator decodes the raw object as an Indicator. Returns false if the
// envelope type is not "indicator".
func AsIndicator(o Object) (Indicator, bool, error) {
	if o.Type != "indicator" {
		return Indicator{}, false, nil
	}
	var ind Indicator
	if err := json.Unmarshal(o.Raw, &ind); err != nil {
		return Indicator{}, false, err
	}
	ind.Raw = o.Raw
	return ind, true, nil
}

// AsMalware decodes the raw object as Malware when type == "malware".
func AsMalware(o Object) (Malware, bool, error) {
	if o.Type != "malware" {
		return Malware{}, false, nil
	}
	var m Malware
	if err := json.Unmarshal(o.Raw, &m); err != nil {
		return Malware{}, false, err
	}
	m.Raw = o.Raw
	return m, true, nil
}

// AsAttackPattern decodes the raw object as AttackPattern when type matches.
func AsAttackPattern(o Object) (AttackPattern, bool, error) {
	if o.Type != "attack-pattern" {
		return AttackPattern{}, false, nil
	}
	var a AttackPattern
	if err := json.Unmarshal(o.Raw, &a); err != nil {
		return AttackPattern{}, false, err
	}
	a.Raw = o.Raw
	return a, true, nil
}

// AsRelationship decodes the raw object as Relationship when type matches.
func AsRelationship(o Object) (Relationship, bool, error) {
	if o.Type != "relationship" {
		return Relationship{}, false, nil
	}
	var r Relationship
	if err := json.Unmarshal(o.Raw, &r); err != nil {
		return Relationship{}, false, err
	}
	r.Raw = o.Raw
	return r, true, nil
}

func validateObject(o *Object) error {
	if o.Type == "" {
		return errors.New("missing type")
	}
	if !stixIDPattern.MatchString(o.ID) {
		return fmt.Errorf("invalid id %q", o.ID)
	}
	// STIX ID prefix must match type (indicator--..., malware--..., etc.)
	prefix := o.ID[:len(o.Type)]
	if prefix != o.Type {
		return fmt.Errorf("id prefix %q does not match type %q", prefix, o.Type)
	}
	return nil
}
