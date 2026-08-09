package stix

import (
	"testing"

	"github.com/google/uuid"
)

// These tests target the pure conversion helpers in import.go
// (indicatorToIOC, dedupStrings, killChainToAttack, externalRefsToAttack).
// They deliberately avoid touching Importer.Import itself, which requires a
// live *store.StixStore/*store.IOCStore (concrete pgxpool-backed structs with
// no fake/interface seam) — but the conversion logic they exercise is the
// same code path Import calls, so this is real coverage of the STIX->IOC
// business logic, not a workaround.

func TestIndicatorToIOC_ParsesSimplePattern(t *testing.T) {
	ind := Indicator{
		Object:  Object{ID: "indicator--1111", Confidence: 80, Labels: []string{"malicious-activity"}},
		Pattern: `[ipv4-addr:value = '198.51.100.7']`,
	}
	feedID := uuid.New()
	ioc := indicatorToIOC(ind, "misp", &feedID)

	if ioc == nil {
		t.Fatal("expected non-nil IOC for a simple supported pattern")
	}
	if ioc.Type != "ipv4-addr" {
		t.Errorf("Type = %q, want ipv4-addr", ioc.Type)
	}
	if ioc.Value != "198.51.100.7" {
		t.Errorf("Value = %q, want 198.51.100.7", ioc.Value)
	}
	if ioc.Confidence != 80 {
		t.Errorf("Confidence = %d, want 80", ioc.Confidence)
	}
	if ioc.Source != "misp" {
		t.Errorf("Source = %q, want misp", ioc.Source)
	}
	if ioc.FeedID == nil || *ioc.FeedID != feedID {
		t.Errorf("FeedID = %v, want %v", ioc.FeedID, feedID)
	}
	if ioc.StixID != ind.ID {
		t.Errorf("StixID = %q, want %q", ioc.StixID, ind.ID)
	}
}

func TestIndicatorToIOC_UnsupportedPatternReturnsNil(t *testing.T) {
	ind := Indicator{
		Object:  Object{ID: "indicator--2222"},
		Pattern: `[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'evil.example']`,
	}
	if got := indicatorToIOC(ind, "manual", nil); got != nil {
		t.Errorf("expected nil for unsupported compound pattern, got %+v", got)
	}
}

func TestIndicatorToIOC_ZeroConfidenceDefaultsTo50(t *testing.T) {
	ind := Indicator{
		Object:  Object{ID: "indicator--3333", Confidence: 0},
		Pattern: `[domain-name:value = 'evil.example']`,
	}
	ioc := indicatorToIOC(ind, "manual", nil)
	if ioc == nil {
		t.Fatal("expected non-nil IOC")
	}
	if ioc.Confidence != 50 {
		t.Errorf("Confidence = %d, want default 50", ioc.Confidence)
	}
}

func TestIndicatorToIOC_DescriptionFallsBackToName(t *testing.T) {
	ind := Indicator{
		Object:      Object{ID: "indicator--4444"},
		Name:        "Suspicious C2 domain",
		Description: "",
		Pattern:     `[domain-name:value = 'evil.example']`,
	}
	ioc := indicatorToIOC(ind, "manual", nil)
	if ioc == nil {
		t.Fatal("expected non-nil IOC")
	}
	if ioc.Description != "Suspicious C2 domain" {
		t.Errorf("Description = %q, want fallback to Name", ioc.Description)
	}
}

func TestIndicatorToIOC_ExplicitDescriptionWins(t *testing.T) {
	ind := Indicator{
		Object:      Object{ID: "indicator--5555"},
		Name:        "fallback name",
		Description: "explicit description",
		Pattern:     `[domain-name:value = 'evil.example']`,
	}
	ioc := indicatorToIOC(ind, "manual", nil)
	if ioc.Description != "explicit description" {
		t.Errorf("Description = %q, want explicit value to win over Name", ioc.Description)
	}
}

func TestIndicatorToIOC_PropagatesRevokedFlag(t *testing.T) {
	ind := Indicator{
		Object:  Object{ID: "indicator--6666", Revoked: true},
		Pattern: `[domain-name:value = 'evil.example']`,
	}
	ioc := indicatorToIOC(ind, "manual", nil)
	if !ioc.Revoked {
		t.Error("expected Revoked=true to propagate from the STIX object")
	}
}

func TestIndicatorToIOC_MergesIndicatorTypesAndLabelsIntoTagsWithoutDupes(t *testing.T) {
	ind := Indicator{
		Object:         Object{ID: "indicator--7777", Labels: []string{"malicious-activity", "shared-tag"}},
		IndicatorTypes: []string{"malicious-activity", "shared-tag", "c2"},
		Pattern:        `[domain-name:value = 'evil.example']`,
	}
	ioc := indicatorToIOC(ind, "manual", nil)
	if ioc == nil {
		t.Fatal("expected non-nil IOC")
	}
	seen := map[string]int{}
	for _, tag := range ioc.Tags {
		seen[tag]++
	}
	for tag, count := range seen {
		if count != 1 {
			t.Errorf("tag %q appeared %d times, want exactly once (dedup)", tag, count)
		}
	}
	for _, want := range []string{"malicious-activity", "shared-tag", "c2"} {
		if seen[want] != 1 {
			t.Errorf("expected tag %q present exactly once, got %d", want, seen[want])
		}
	}
}

func TestDedupStrings_RemovesDuplicatesAcrossSets(t *testing.T) {
	got := dedupStrings([]string{"a", "b", "a"}, []string{"b", "c"})
	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(got) != 3 {
		t.Fatalf("dedupStrings() = %v, want 3 unique elements", got)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected element %q", v)
		}
	}
}

func TestDedupStrings_SkipsEmptyStrings(t *testing.T) {
	got := dedupStrings([]string{"", "a", ""}, []string{""})
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("dedupStrings() = %v, want [a]", got)
	}
}

func TestDedupStrings_AllEmptyReturnsEmptySliceNotNil(t *testing.T) {
	got := dedupStrings(nil, []string{})
	if got == nil {
		t.Fatal("dedupStrings() = nil, want non-nil empty slice (callers marshal this to JSON '[]')")
	}
	if len(got) != 0 {
		t.Errorf("dedupStrings() = %v, want empty", got)
	}
}

func TestKillChainToAttack_MapsFieldsAndPreservesOrder(t *testing.T) {
	phases := []KillChainPhase{
		{KillChainName: "mitre-attack", PhaseName: "initial-access"},
		{KillChainName: "mitre-attack", PhaseName: "execution"},
	}
	got := killChainToAttack(phases)
	if len(got) != 2 {
		t.Fatalf("got %d phases, want 2", len(got))
	}
	if got[0].PhaseName != "initial-access" || got[1].PhaseName != "execution" {
		t.Errorf("order/content not preserved: %+v", got)
	}
	if got[0].KillChainName != "mitre-attack" {
		t.Errorf("KillChainName = %q, want mitre-attack", got[0].KillChainName)
	}
}

func TestKillChainToAttack_EmptyInputReturnsEmptyNotNil(t *testing.T) {
	got := killChainToAttack(nil)
	if got == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestExternalRefsToAttack_MapsAllFields(t *testing.T) {
	refs := []ExternalRef{
		{SourceName: "mitre-attack", ExternalID: "T1059", URL: "https://attack.mitre.org/techniques/T1059"},
	}
	got := externalRefsToAttack(refs)
	if len(got) != 1 {
		t.Fatalf("got %d refs, want 1", len(got))
	}
	if got[0].SourceName != "mitre-attack" || got[0].ExternalID != "T1059" || got[0].URL != "https://attack.mitre.org/techniques/T1059" {
		t.Errorf("fields not mapped correctly: %+v", got[0])
	}
}
