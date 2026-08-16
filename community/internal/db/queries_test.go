package db

// Tests for the pure, unexported sortSuffix helper and the exported
// SortedListPosts*Query builders that all funnel through it. None of this
// touches a database — it's plain string construction, so it's tested
// directly against the internal db package (no db_test wrapper needed).

import (
	"strings"
	"testing"
)

func TestSortSuffix_AllSortsProduceExpectedOrderingAndParams(t *testing.T) {
	cases := []struct {
		sort       string
		wantOrder  string
		wantWindow string
	}{
		{"top_week", "reactions r2", "7 days"},
		{"top_month", "reactions r2", "30 days"},
		{"top_all", "reaction_count DESC", ""},
		{"rising", "reactions r2", "24 hours"},
		{"", "p.pinned DESC", ""},
		{"unrecognized-sort-value", "p.pinned DESC", ""}, // falls through to default
	}

	for _, c := range cases {
		t.Run(c.sort, func(t *testing.T) {
			got := sortSuffix(c.sort, "$1", "$2")
			if !strings.Contains(got, c.wantOrder) {
				t.Errorf("sortSuffix(%q) = %q, want it to contain %q", c.sort, got, c.wantOrder)
			}
			if c.wantWindow != "" && !strings.Contains(got, c.wantWindow) {
				t.Errorf("sortSuffix(%q) = %q, want it to contain window %q", c.sort, got, c.wantWindow)
			}
			if !strings.Contains(got, "LIMIT $1 OFFSET $2") {
				t.Errorf("sortSuffix(%q) = %q, want it to end with the given limit/offset params", c.sort, got)
			}
		})
	}
}

func TestSortSuffix_UsesGivenParamPlaceholders(t *testing.T) {
	got := sortSuffix("top_all", "$2", "$3")
	if !strings.Contains(got, "LIMIT $2 OFFSET $3") {
		t.Errorf("sortSuffix with custom placeholders = %q, want it to use $2/$3", got)
	}
}

func TestSortedListPostsQuery_IncludesBaseAndSuffix(t *testing.T) {
	for _, sort := range []string{"top_week", "top_month", "top_all", "rising", "default"} {
		q := SortedListPostsQuery(sort)
		if !strings.Contains(q, "FROM posts p") {
			t.Errorf("SortedListPostsQuery(%q) missing base FROM clause: %q", sort, q)
		}
		if !strings.Contains(q, "LIMIT $1 OFFSET $2") {
			t.Errorf("SortedListPostsQuery(%q) missing limit/offset params: %q", sort, q)
		}
		if strings.Contains(q, "blocks bl") {
			t.Errorf("SortedListPostsQuery(%q) should not join blocks: %q", sort, q)
		}
	}
}

func TestSortedListPostsQueryWithBlocks_FiltersBlockedAuthors(t *testing.T) {
	q := SortedListPostsQueryWithBlocks("top_all")
	if !strings.Contains(q, "LEFT JOIN blocks bl ON bl.blocker_id = $3::uuid") {
		t.Errorf("SortedListPostsQueryWithBlocks missing blocks join: %q", q)
	}
	if !strings.Contains(q, "AND bl.blocked_id IS NULL") {
		t.Errorf("SortedListPostsQueryWithBlocks missing block filter: %q", q)
	}
	if !strings.Contains(q, "LIMIT $1 OFFSET $2") {
		t.Errorf("SortedListPostsQueryWithBlocks missing limit/offset params: %q", q)
	}
}

func TestSortedListPostsQueryWithBlocksAndSuppressions_FiltersBlockedAndSuppressed(t *testing.T) {
	q := SortedListPostsQueryWithBlocksAndSuppressions("rising")
	if !strings.Contains(q, "LEFT JOIN blocks bl ON bl.blocker_id = $3::uuid") {
		t.Errorf("missing blocks join: %q", q)
	}
	if !strings.Contains(q, "tag_suppressions ts2") {
		t.Errorf("missing tag suppression filter: %q", q)
	}
	if !strings.Contains(q, "ts2.user_id = $4::uuid") {
		t.Errorf("missing suppressor param: %q", q)
	}
	if !strings.Contains(q, "LIMIT $1 OFFSET $2") {
		t.Errorf("missing limit/offset params: %q", q)
	}
}

func TestSortedListPostsByTagQuery_FiltersByTagSlugAndUsesShiftedParams(t *testing.T) {
	q := SortedListPostsByTagQuery("top_month")
	if !strings.Contains(q, "t_filter.slug = $1") {
		t.Errorf("missing tag slug filter: %q", q)
	}
	// This query shifts limit/offset to $2/$3 because $1 is the tag slug.
	if !strings.Contains(q, "LIMIT $2 OFFSET $3") {
		t.Errorf("SortedListPostsByTagQuery(%q) = %q, want LIMIT $2 OFFSET $3", "top_month", q)
	}
	if !strings.Contains(q, "30 days") {
		t.Errorf("SortedListPostsByTagQuery(top_month) missing 30-day window: %q", q)
	}
}
