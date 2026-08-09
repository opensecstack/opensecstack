package marshal

import "testing"

// TestNewExecutionID_ReturnsUniqueNonZeroUUIDs confirms NewExecutionID
// actually generates fresh random UUIDs (not a fixed/zero value and not
// repeating), since ExecutionID is what ties together a Kerkese request
// with its WORM-logged decision — a collision or a constant value would
// make two distinct governed actions indistinguishable in the audit trail.
func TestNewExecutionID_ReturnsUniqueNonZeroUUIDs(t *testing.T) {
	a := NewExecutionID()
	b := NewExecutionID()

	var zero [16]byte
	if [16]byte(a) == zero {
		t.Fatal("expected non-zero UUID")
	}
	if a == b {
		t.Fatal("expected two calls to NewExecutionID to return different UUIDs")
	}
}
