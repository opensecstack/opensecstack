package search_test

import (
	"testing"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/search"
)

// TestNew_UnreachableMeilisearch_ReturnsError verifies that New surfaces a
// wrapped error when it cannot reach Meilisearch to configure the index
// (rather than silently returning a half-configured Client), since
// IndexPost/Search would otherwise fail confusingly deep inside handler
// code with no indication that setup never succeeded.
func TestNew_UnreachableMeilisearch_ReturnsError(t *testing.T) {
	cfg := &config.Config{
		MeilisearchURL: "http://127.0.0.1:1", // nothing listens here
		MeilisearchKey: "test-key",
	}

	_, err := search.New(cfg)
	if err == nil {
		t.Fatal("expected an error when Meilisearch is unreachable")
	}
}
