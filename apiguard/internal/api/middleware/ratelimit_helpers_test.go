package middleware

import "testing"

func TestIndexByte(t *testing.T) {
	tests := []struct {
		name string
		s    string
		b    byte
		want int
	}{
		{name: "found in middle", s: "a,b,c", b: ',', want: 1},
		{name: "found at start", s: ",abc", b: ',', want: 0},
		{name: "not found", s: "abc", b: ',', want: -1},
		{name: "empty string", s: "", b: ',', want: -1},
		{name: "found at end", s: "abc,", b: ',', want: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := indexByte(tc.s, tc.b); got != tc.want {
				t.Errorf("indexByte(%q, %q) = %d, want %d", tc.s, tc.b, got, tc.want)
			}
		})
	}
}

func TestContainsSlash(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{name: "CIDR with slash", s: "10.0.0.0/8", want: true},
		{name: "plain IP no slash", s: "10.0.0.1", want: false},
		{name: "empty string", s: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsSlash(tc.s); got != tc.want {
				t.Errorf("containsSlash(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "leading and trailing spaces", s: "  hello  ", want: "hello"},
		{name: "no spaces", s: "hello", want: "hello"},
		{name: "only spaces", s: "   ", want: ""},
		{name: "empty string", s: "", want: ""},
		{name: "internal spaces preserved", s: " a b c ", want: "a b c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimSpace(tc.s); got != tc.want {
				t.Errorf("trimSpace(%q) = %q, want %q", tc.s, got, tc.want)
			}
		})
	}
}
