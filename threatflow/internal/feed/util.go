package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// deterministicBundleID produces `bundle--<uuid-ish>` derived from the feed
// name and payload hash. Two identical polls from the same feed produce the
// same bundle ID, so the importer dedupes via stix_bundles.stix_id UNIQUE.
func deterministicBundleID(feedName string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(feedName))
	h.Write([]byte{0})
	h.Write(payload)
	sum := h.Sum(nil)
	return "bundle--" + formatUUIDv4FromHash(sum)
}

// deterministicIndicatorID produces an indicator ID stable across polls so
// the iocs.pattern_hash dedup + stix_objects.stix_id UNIQUE interact cleanly.
func deterministicIndicatorID(pattern string) string {
	sum := sha256.Sum256([]byte(pattern))
	return "indicator--" + formatUUIDv4FromHash(sum[:])
}

// formatUUIDv4FromHash takes the first 16 bytes of a hash and formats them
// as a UUID, with the v4 + variant bits patched so the output matches the
// STIX ID regex.
func formatUUIDv4FromHash(sum []byte) string {
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40 // v4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// newCommentStripper wraps raw bytes so that lines starting with '#' (and
// the surrounding whitespace) are dropped before CSV parsing. abuse.ch
// feeds prefix ~15 lines of header banners with this style.
func newCommentStripper(raw []byte) io.Reader {
	var out bytes.Buffer
	for len(raw) > 0 {
		idx := bytes.IndexByte(raw, '\n')
		var line []byte
		if idx == -1 {
			line = raw
			raw = nil
		} else {
			line = raw[:idx+1]
			raw = raw[idx+1:]
		}
		trimmed := bytes.TrimLeft(line, " \t")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		out.Write(line)
	}
	return &out
}
