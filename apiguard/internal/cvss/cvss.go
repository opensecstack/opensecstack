// Package cvss implements the CVSS 3.1 base score calculator.
// It is a pure-Go port of the Rust apiguard-cvss crate so modules can compute
// scores at runtime from vector strings rather than hardcoding floats.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Score parses a CVSS 3.1 vector string and returns the base score rounded to
// one decimal place using the CVSS 3.1 specification rounding algorithm.
//
// Example vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
func Score(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, fmt.Errorf("cvss: vector must start with CVSS:3.1/, got %q", vector)
	}

	vals := make(map[string]string, 8)
	for _, part := range strings.Split(vector[len("CVSS:3.1/"):], "/") {
		i := strings.IndexByte(part, ':')
		if i <= 0 {
			return 0, fmt.Errorf("cvss: invalid component %q", part)
		}
		vals[part[:i]] = part[i+1:]
	}

	get := func(key string) (string, error) {
		v, ok := vals[key]
		if !ok || v == "" {
			return "", fmt.Errorf("cvss: missing metric %s", key)
		}
		return v, nil
	}

	// --- Attack Vector ---
	avS, err := get("AV")
	if err != nil {
		return 0, err
	}
	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	av, ok := avMap[avS]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid AV value %q", avS)
	}

	// --- Attack Complexity ---
	acS, err := get("AC")
	if err != nil {
		return 0, err
	}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	ac, ok := acMap[acS]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid AC value %q", acS)
	}

	// --- Scope (needed for PR calculation) ---
	sS, err := get("S")
	if err != nil {
		return 0, err
	}
	if sS != "U" && sS != "C" {
		return 0, fmt.Errorf("cvss: invalid S value %q", sS)
	}
	scopeChanged := sS == "C"

	// --- Privileges Required (scope-dependent) ---
	prS, err := get("PR")
	if err != nil {
		return 0, err
	}
	var pr float64
	switch prS {
	case "N":
		pr = 0.85
	case "L":
		if scopeChanged {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scopeChanged {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0, fmt.Errorf("cvss: invalid PR value %q", prS)
	}

	// --- User Interaction ---
	uiS, err := get("UI")
	if err != nil {
		return 0, err
	}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	ui, ok := uiMap[uiS]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid UI value %q", uiS)
	}

	// --- Impact metrics ---
	impactVal := func(key string) (float64, error) {
		s, err := get(key)
		if err != nil {
			return 0, err
		}
		switch s {
		case "N":
			return 0.0, nil
		case "L":
			return 0.22, nil
		case "H":
			return 0.56, nil
		default:
			return 0, fmt.Errorf("cvss: invalid %s value %q", key, s)
		}
	}

	cVal, err := impactVal("C")
	if err != nil {
		return 0, err
	}
	iVal, err := impactVal("I")
	if err != nil {
		return 0, err
	}
	aVal, err := impactVal("A")
	if err != nil {
		return 0, err
	}

	// --- ISC base ---
	iscBase := 1.0 - (1.0-cVal)*(1.0-iVal)*(1.0-aVal)

	// --- ISC (scope-adjusted) ---
	var isc float64
	if scopeChanged {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		isc = 6.42 * iscBase
	}

	if isc <= 0 {
		return 0.0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	var raw float64
	if scopeChanged {
		raw = math.Min(1.08*(isc+exploitability), 10.0)
	} else {
		raw = math.Min(isc+exploitability, 10.0)
	}

	return roundup(raw), nil
}

// MustScore is like Score but panics if the vector string is invalid.
// Use this for compile-time constant vectors in module findings.
func MustScore(vector string) float64 {
	s, err := Score(vector)
	if err != nil {
		panic(fmt.Sprintf("cvss.MustScore(%q): %v", vector, err))
	}
	return s
}

// Severity returns the CVSS 3.1 qualitative severity label for a base score.
func Severity(score float64) string {
	switch {
	case score == 0.0:
		return "None"
	case score < 4.0:
		return "Low"
	case score < 7.0:
		return "Medium"
	case score < 9.0:
		return "High"
	default:
		return "Critical"
	}
}

// roundup rounds x up to one decimal place using the CVSS 3.1 ceiling algorithm.
// This is NOT standard rounding — it always rounds up (ceiling at 1dp).
func roundup(x float64) float64 {
	return math.Ceil(x*10) / 10
}
