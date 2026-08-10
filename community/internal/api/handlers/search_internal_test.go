package handlers

// White-box tests for buildSearchQuery and buildListByIDsQuery — the
// dynamic SQL builders behind the Search handler. These are
// security-relevant: every user-controlled value (q, tag, author, from,
// to) must be passed as a placeholder argument, never string-concatenated
// into the SQL text, or the search endpoint becomes SQL-injectable.

import (
	"strings"
	"testing"
)

func TestBuildSearchQuery_NoFilters_OnlyLimitOffsetArgs(t *testing.T) {
	sql, args := buildSearchQuery("", "", "", "", "", 20, 0)

	if len(args) != 2 {
		t.Fatalf("expected exactly 2 args (limit, offset) with no filters, got %d: %v", len(args), args)
	}
	if args[0] != 20 || args[1] != 0 {
		t.Errorf("expected args [20, 0], got %v", args)
	}
	if !strings.Contains(sql, "$1") || !strings.Contains(sql, "$2") {
		t.Errorf("expected placeholders $1 and $2 in SQL, got: %s", sql)
	}
	if strings.Contains(sql, "plainto_tsquery") {
		t.Error("expected no full-text search clause when q is empty")
	}
}

func TestBuildSearchQuery_QueryStringNeverInlinedIntoSQL(t *testing.T) {
	malicious := `'; DROP TABLE posts; --`
	sql, args := buildSearchQuery(malicious, "", "", "", "", 20, 0)

	if strings.Contains(sql, malicious) {
		t.Fatal("SQL injection risk: user-controlled query string was concatenated directly into the SQL text")
	}
	found := false
	for _, a := range args {
		if a == malicious {
			found = true
		}
	}
	if !found {
		t.Error("expected the query string to be passed as a bound argument")
	}
}

func TestBuildSearchQuery_TagFilterAddsSlugifiedArgAndJoin(t *testing.T) {
	sql, args := buildSearchQuery("", "My Tag!", "", "", "", 20, 0)

	if !strings.Contains(sql, "t_f.slug = $1") {
		t.Errorf("expected tag filter to bind to $1, got: %s", sql)
	}
	if args[0] != "my-tag" {
		t.Errorf("expected tag to be slugified to 'my-tag', got %v", args[0])
	}
}

func TestBuildSearchQuery_AuthorFilterTrimsAndBinds(t *testing.T) {
	sql, args := buildSearchQuery("", "", "  alice  ", "", "", 20, 0)

	if !strings.Contains(sql, "u.username = $1") {
		t.Errorf("expected author filter bound as $1, got: %s", sql)
	}
	if args[0] != "alice" {
		t.Errorf("expected trimmed author 'alice', got %q", args[0])
	}
}

func TestBuildSearchQuery_DateRangeFiltersBothPresent(t *testing.T) {
	sql, args := buildSearchQuery("", "", "", "2026-01-01", "2026-01-31", 20, 0)

	if !strings.Contains(sql, "p.published_at >= $1::date") {
		t.Errorf("expected from-date filter, got: %s", sql)
	}
	if !strings.Contains(sql, "p.published_at <= ($2::date + interval '1 day')") {
		t.Errorf("expected to-date filter, got: %s", sql)
	}
	if args[0] != "2026-01-01" || args[1] != "2026-01-31" {
		t.Errorf("expected date args in order, got %v", args)
	}
}

func TestBuildSearchQuery_AllFiltersCombined_ArgOrderMatchesPlaceholders(t *testing.T) {
	sql, args := buildSearchQuery("security", "golang", "bob", "2026-01-01", "2026-02-01", 10, 5)

	// Expected arg order: tag, q (FTS), author, from, to, q (ORDER BY rank), limit, offset
	wantArgs := []any{"golang", "security", "bob", "2026-01-01", "2026-02-01", "security", 10, 5}
	if len(args) != len(wantArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(wantArgs), len(args), args)
	}
	for i, want := range wantArgs {
		if args[i] != want {
			t.Errorf("arg[%d]: expected %v, got %v", i, want, args[i])
		}
	}
	// LIMIT/OFFSET placeholders must reference the final two positional args.
	if !strings.Contains(sql, "LIMIT $7 OFFSET $8") {
		t.Errorf("expected 'LIMIT $7 OFFSET $8' at the end, got: %s", sql)
	}
}

func TestBuildSearchQuery_EmptyQuery_OrdersByPinnedAndDate(t *testing.T) {
	sql, _ := buildSearchQuery("", "", "", "", "", 20, 0)
	if !strings.Contains(sql, "ORDER BY p.pinned DESC, p.published_at DESC") {
		t.Errorf("expected default ordering by pinned/date when q is empty, got: %s", sql)
	}
}

func TestBuildSearchQuery_WithQuery_OrdersByRank(t *testing.T) {
	sql, _ := buildSearchQuery("security", "", "", "", "", 20, 0)
	if !strings.Contains(sql, "ORDER BY ts_rank") {
		t.Errorf("expected rank ordering when q is present, got: %s", sql)
	}
}

func TestBuildListByIDsQuery_IDsPassedAsFirstArg(t *testing.T) {
	ids := []string{"id-1", "id-2", "id-3"}
	sql, args := buildListByIDsQuery(ids, "", "", "", "")

	if len(args) != 1 {
		t.Fatalf("expected exactly 1 arg (ids) with no other filters, got %d: %v", len(args), args)
	}
	got, ok := args[0].([]string)
	if !ok {
		t.Fatalf("expected args[0] to be []string, got %T", args[0])
	}
	if len(got) != 3 || got[0] != "id-1" {
		t.Errorf("expected ids slice preserved, got %v", got)
	}
	if !strings.Contains(sql, "p.id = ANY($1)") {
		t.Errorf("expected 'p.id = ANY($1)' clause, got: %s", sql)
	}
}

func TestBuildListByIDsQuery_TagAuthorDateFilters_BoundNotInlined(t *testing.T) {
	malicious := `'; DROP TABLE posts; --`
	sql, args := buildListByIDsQuery([]string{"id-1"}, "tag", malicious, "2026-01-01", "2026-02-01")

	if strings.Contains(sql, malicious) {
		t.Fatal("SQL injection risk: author value was concatenated directly into SQL text")
	}
	// args: [ids, tag-slug, author, from, to]
	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d: %v", len(args), args)
	}
	if args[1] != "tag" {
		t.Errorf("expected slugified tag 'tag' at args[1], got %v", args[1])
	}
	if args[2] != malicious {
		t.Errorf("expected author bound as arg, got %v", args[2])
	}
	if args[3] != "2026-01-01" || args[4] != "2026-02-01" {
		t.Errorf("expected date args, got %v / %v", args[3], args[4])
	}
}

func TestBuildListByIDsQuery_NoFilters_OnlyIDsArg(t *testing.T) {
	sql, args := buildListByIDsQuery([]string{"a"}, "", "", "", "")
	if len(args) != 1 {
		t.Errorf("expected only the ids arg, got %d args: %v", len(args), args)
	}
	if strings.Contains(sql, "JOIN post_tags pt_f") {
		t.Error("expected no tag join when tag filter is empty")
	}
}
