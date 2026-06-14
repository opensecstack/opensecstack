package feed

import (
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestCommentStripper(t *testing.T) {
	input := []byte("# comment\n   # indented comment\nvalue,1\n#another\nvalue,2\n")
	r := newCommentStripper(input)
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf)
	if strings.Contains(got, "#") {
		t.Errorf("comment lines leaked through: %q", got)
	}
	if !strings.Contains(got, "value,1") || !strings.Contains(got, "value,2") {
		t.Errorf("data rows missing: %q", got)
	}
}

func TestDeterministicIDs_StableAndValid(t *testing.T) {
	re := regexp.MustCompile(`^(bundle|indicator)--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	b1 := deterministicBundleID("feed-1", []byte("payload"))
	b2 := deterministicBundleID("feed-1", []byte("payload"))
	if b1 != b2 {
		t.Errorf("bundle id not stable")
	}
	if !re.MatchString(b1) {
		t.Errorf("bundle id malformed: %s", b1)
	}

	i1 := deterministicIndicatorID("[ipv4-addr:value = '1.2.3.4']")
	i2 := deterministicIndicatorID("[ipv4-addr:value = '1.2.3.4']")
	if i1 != i2 {
		t.Errorf("indicator id not stable")
	}
	if !re.MatchString(i1) {
		t.Errorf("indicator id malformed: %s", i1)
	}
}
