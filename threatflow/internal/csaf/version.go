package csaf

import "strconv"

// compareVersions orders two CSAF tracking.version strings. Returns -1 if a
// is older than b, 0 if they are the same revision, 1 if a is newer than b.
//
// CSAF's `version` field is a free-form string (opencsirt's generator
// defaults it to a monotonically increasing integer string "1", "2", ... via
// tracking.revision_history, but the CSAF 2.0 spec does not mandate that
// shape for every producer). Both sides are parsed as integers when
// possible, since that is what every current producer emits and it gives an
// unambiguous total order. When either side fails to parse as an integer,
// this falls back to a lexical string comparison: equal strings are still
// recognised as the same revision (the dedup case that matters most), and
// unequal-but-unparseable strings are treated as "b is newer" so an
// unrecognised version format degrades to applying the update rather than
// silently discarding it — see the ADR-004 implementation note for why this
// direction was chosen over rejecting the revision outright.
func compareVersions(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	}
	if a == b {
		return 0
	}
	return -1
}
