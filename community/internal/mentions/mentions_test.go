package mentions_test

import (
	"reflect"
	"testing"

	"github.com/opensecstack/community/internal/mentions"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single mention at start",
			input: "@alice",
			want:  []string{"alice"},
		},
		{
			name:  "two distinct mentions",
			input: "@alice @bob",
			want:  []string{"alice", "bob"},
		},
		{
			name:  "double at-sign is not valid",
			input: "@@invalid",
			want:  nil,
		},
		{
			name:  "duplicate mentions are deduplicated",
			input: "@alice @alice",
			want:  []string{"alice"},
		},
		{
			name:  "mentions are lowercased",
			input: "@Alice",
			want:  []string{"alice"},
		},
		{
			name:  "mixed case deduplication",
			input: "@Alice @alice",
			want:  []string{"alice"},
		},
		{
			name:  "no mentions in plain text",
			input: "hello world",
			want:  nil,
		},
		{
			name:  "mention in the middle of a sentence",
			input: "hello @carol how are you",
			want:  []string{"carol"},
		},
		{
			name:  "mention in HTML-like context",
			input: ">@dave said something",
			want:  []string{"dave"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mentions.Extract(tc.input)
			// Treat nil and empty slice as equivalent for "no results".
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Extract(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}
