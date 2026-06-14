package stix

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnsupportedPattern signals a STIX pattern that the simple parser cannot
// decompose. Callers should retain the raw pattern and skip type/value extraction.
var ErrUnsupportedPattern = errors.New("unsupported stix pattern")

// Observation is a single {type, property, operator, value} tuple extracted
// from a STIX pattern. Most real-world feeds emit a single observation per
// indicator, so List[0] is usually sufficient.
type Observation struct {
	Type     string
	Property string
	Operator string
	Value    string
}

// simplePattern matches the common case: [type:property = 'value'] — optionally
// wrapped in whitespace. The full STIX grammar supports MATCHES, LIKE, IN,
// AND/OR/FOLLOWEDBY, but 95%+ of indicator feeds emit the simple form.
// Only the equality form is considered "IOC-safe" — MATCHES/LIKE/IN are regex
// or set patterns that cannot be reduced to a single indicator value.
var simplePattern = regexp.MustCompile(
	`^\s*\[\s*([a-z0-9_-]+):([a-zA-Z0-9_.-]+)\s*=\s*('([^']*)'|"([^"]*)")\s*\]\s*$`,
)

// ParsePattern decomposes a STIX pattern string into a list of observations.
// Only the single-observation form is supported; compound patterns return
// ErrUnsupportedPattern.
func ParsePattern(pattern string) ([]Observation, error) {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return nil, errors.New("empty pattern")
	}
	m := simplePattern.FindStringSubmatch(trimmed)
	if m == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPattern, pattern)
	}
	val := m[4]
	if val == "" {
		val = m[5]
	}
	return []Observation{{
		Type:     m[1],
		Property: m[2],
		Operator: "=",
		Value:    val,
	}}, nil
}

// PrimaryIOC returns the (type, value) pair most useful for storing an IOC.
// Falls back to ("", "") with ErrUnsupportedPattern for compound patterns.
func PrimaryIOC(pattern string) (iocType, value string, err error) {
	obs, err := ParsePattern(pattern)
	if err != nil {
		return "", "", err
	}
	if len(obs) == 0 {
		return "", "", ErrUnsupportedPattern
	}
	return obs[0].Type, obs[0].Value, nil
}
